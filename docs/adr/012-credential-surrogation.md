# ADR-0012: Credential surrogation (Muse-model) — SPEC ONLY

- **Status:** proposed (spec-only; implementation queued — see Scope)
- **Date:** 2026-09-19
- **Deciders:** platform team

## Context

Meta's Muse architecture (Sentinel) performs just-in-time credential
insertion at the network boundary: the agent only ever holds **surrogate
tokens** with zero standalone value, and the egress proxy swaps in the real
credential after authorizing the request — so a prompt-injected or coerced
agent cannot exfiltrate real secrets, because it never possesses them.

Our current posture (FR-SEC-003, `credential-broker/`): the broker mints
scoped, expiring, revocable HMAC tokens, and they are delivered to the agent
as **real tokens** via per-execution env (`Operation.Env`, e.g.
`AGENT_TOKEN`). Scoping/TTL/revocation bound the blast radius, but a leaked
token is fully usable by anyone anywhere until expiry or reactive revocation.
Prompt injection is precisely the threat that turns "the agent legitimately
holds a credential" into "the attacker holds a credential".

Relevant invariants: INV-018 (network and credentials are capabilities, not
ambient privileges), INV-025 (control events vs bulk data; secrets never in
logs/events), FR-SEC-003 (secret injection without secret values in
control-plane transcripts), INV-026 (no vendor concepts in the API).

## Threat model

Attacker: content the agent processes (web pages, repo files, tool output,
issue text) carrying prompt-injection payloads that coerce the agent into
exfiltrating whatever credentials it can reach (posting them to an
attacker-controlled endpoint, embedding them in a commit/issue, DNS
exfil). The agent is assumed fully coercible; the host, control plane, and
egress data plane are not. A coerced agent today can:

- read its own env (real broker tokens, real third-party API keys injected
  the same way) and send them anywhere the egress policy allows — and
  exfiltration endpoints are attacker-registered domains that no static
  allowlist anticipates;
- use the token from the guest, which revocation only stops *reactively*.

Target posture: everything the agent can read is a surrogate — useless off
the platform, useless against the real destination directly, useless to a
different sandbox, and single-pathed through an authorizing boundary.

## Decision

### 1. Surrogate token format and binding

`Broker.IssueSurrogate` mints tokens in the existing `payload.signature`
HMAC format (offline-verifiable, no new crypto), with extended claims:

- `TokenID` (random, audited — value never logged, per existing rule);
- `TenantID`, `TaskRef` — as today;
- `SandboxID` + `ExecutionEpoch` — the surrogate is bound to one sandbox
  incarnation epoch; a workspace-only resume (epoch bump) invalidates it,
  and another sandbox's traffic can never use it;
- `Audience` — the destination host pattern (e.g. `api.github.com`) this
  surrogate authorizes; the proxy swaps only for that destination;
- `Capabilities` — opaque scopes passed to policy (phase 2: method/path);
- short TTL (minutes), renewable by the control plane at exec time.

The surrogate↔real-secret mapping lives ONLY in the broker (control plane).
The real secret is delivered to the egress proxy over the host-local
control channel at swap time, held in memory, never written to audit, the
event bus, or the guest.

### 2. Insertion point: a per-host egress L7 proxy is the surrogation boundary

Our egress enforcement today is host-side L3/L4: per-incarnation iptables
chains + a DNS-learning proxy (ADR-001). Header rewriting requires L7, so
we introduce a **per-host forward proxy** as the only path to
*credentialed destinations*:

- Credentialed destinations are declared in the egress policy with a
  `Credentialed: true` marker. For these hosts, DNS learning returns the
  real answers but the learned /32 allow entries are NOT installed into the
  guest-facing chain; instead, credentialed destinations resolve to / are
  reached only via the proxy listener on the TAP host address. Direct
  guest→destination packets hit the default DROP. Proxy→destination traffic
  originates on the host and is allowed by chain construction.
- The guest learns the proxy via environment (`HTTPS_PROXY`-style, injected
  like `AGENT_SANDBOX_EGRESS` today) — a coerced agent bypassing the proxy
  simply has no route (fail-closed by omission, same trick as the DNS
  learner's treatment of hardcoded resolvers).
- HTTPS requires TLS interception for header rewriting: a per-host CA is
  generated at proxy start and its root is baked into prepared environments
  by the environment builder (an image-level trust root, not a guest-agent
  component). Plain HTTP forward-proxying needs no CA. CONNECT without
  interception is supported for credentialed destinations ONLY when no
  header swap is configured (pure egress gating).

Per-host (not per-incarnation) is deliberate: one policy point per host,
connection pooling, and it matches the existing per-incarnation-DNS /
per-host-iptables split. The proxy is a host credential boundary — it must
run with the same no-host-credentials-in-guest discipline (INV-018) in
reverse: no guest credentials on the host path beyond broker-held mappings.

### 3. What stays L3/L4

Everything non-credentialed. The DNS-learning allowlist flow for ordinary
destinations is untouched; the iptables chains remain the enforcement of
record. The L7 hop exists only where a credential swap (or later, L7
policy) is configured — the data plane stays simple for the common case,
which was the reason it was L3/L4 to begin with.

### 4. Failure modes

- **Proxy down/unreachable:** credentialed requests fail closed (no route,
  no swap). Non-credentialed traffic is unaffected.
- **Broker unreachable at swap time:** swap denied, request fails; audited.
- **Surrogate stolen and replayed from elsewhere:** worthless — the swap
  happens only inside our proxy for traffic from the bound sandbox's
  incarnation (source-IP/anti-spoof checks already exist per-incarnation),
  for the bound audience, pre-expiry, un-revoked.
- **TLS-interception CA compromise:** host-level incident; CA is per-host
  and rotatable, environments rebuilt pick up the new root.

### 5. Revocation and audit

Surrogate revocation is the existing broker `Revoke` (durable, reloaded on
restart) — revoking kills the swap, not just guest-side use. Every swap
decision is audited by token ID + destination + verdict into the same JSONL
audit trail (`network.AuditLog`), giving exactly the surrogate↔real usage
ledger Muse gets from Sentinel: who used which credential, where, when,
allowed or denied — without ever recording a secret value (INV-025).

### 6. Phasing

- **Phase 1 (the spec's implementation target):** surrogate mint/verify in
  the broker; per-host forward proxy with CONNECT + TLS-interception for
  allowlisted credentialed HTTPS hosts; policy marker `Credentialed`;
  enforcement wiring (no learned /32 for credentialed hosts; proxy-only
  route); swap audit. Conformance: injected agent cannot exfiltrate — a
  coerced exec posting `AGENT_TOKEN` to an attacker host sends a surrogate,
  and replaying it against the real destination or from another sandbox
  fails.
- **Phase 2:** L7 policy at the proxy (method/path per capability claim;
  e.g. `read:repo` allows GETs only).
- **Phase 3:** lease-bound auto-renewal of surrogates on epoch boundaries;
  human-in-the-loop swap approval (capability-bound approvals) — a larger
  product decision, tracked in the backlog.

### 7. Explicitly rejected for now

**eBPF/LSM taint tracking (Muse-style flow tainting).** Sentinel tracks
tainted flows kernel-side. We reject this for now because: our threat
boundary is fully observable at the L7 proxy (we terminate TLS, so no
kernel visibility gap exists for credentialed flows); the fleet runs mixed
kernels (6.8/7.0) and an eBPF/LSM surface would multiply the compatibility
matrix we just simplified (ADR-011); and verifier/CO-RE complexity is a
research project, not a two-session feature. Revisit if the threat model
extends to host-level insiders or side-channel exfiltration outside the
proxied path.

## Consequences

- Positive: prompt injection can no longer yield real credentials — the
  strongest statement available without forbidding credential use outright;
  the surrogate↔real audit ledger improves on today's issuance-only audit;
  INV-018 moves from "scoped and revocable" to "not independently usable".
- Negative / costs: an L7 hop adds latency and a new always-up host
  component on the credentialed path; TLS interception inserts a platform
  CA into prepared environments (trust-root management, cert rotation,
  environment rebuilds); credentialed-destination failover inherits proxy
  availability. Direct-egress tooling that ignores proxy env vars breaks
  for credentialed hosts by design (fail-closed).
- Follow-ups: implementation sessions below; backlog items (SSRF final-IP
  re-verification at connect time, L7 policy phase, HITL approvals) tracked
  in docs/BACKLOG.md.

## Scope

**This ADR is a specification only; no code changes are part of it.**
Estimated implementation: ~2–3 sessions — (1) broker surrogate mint/verify
+ claims extension with conformance tests; (2) per-host L7 proxy hop with
TLS interception + CA plumbing into the environment builder; (3)
enforcement wiring in the firecracker egress chains + swap audit +
fail-closed conformance scenarios.

## Alternatives considered

- **Keep brokered real tokens, tighten TTLs.** Rejected: any TTL leaves a
  usable window, and the exfiltration channel (attacker domain) is exactly
  what static allowlists cannot enumerate. Surrogation removes the window
  entirely.
- **Per-incarnation L7 proxies.** Rejected: one proxy per sandbox
  multiplies CA/process management and blast-radius surface for no
  policy-granularity gain; per-host matches the existing enforcement split.
- **eBPF/LSM taint tracking (Muse Sentinel parity).** Rejected for now —
  see §7.
- **Service-mesh sidecar (envoy per pod).** Rejected: pulls a vendor
  control plane onto the hot path (violates INV-020's spirit) and solves a
  fleet-routing problem we do not have.

## Compliance

- [x] Does not weaken INV-005..INV-016 or make state loss silent: no state
  machinery touched; spec-only.
- [x] INV-018 strengthened, not weakened: credentials become
  non-independently-usable capabilities; the always-deny metadata/cluster
  rules are untouched.
- [x] INV-025 preserved: audit records token IDs and destinations, never
  secret values; the swap path is host-local bulk path, not the event bus.
- [x] INV-026 preserved: the surrogation boundary is a host component; no
  backend-interface or public-API concept changes.
- [x] Conformance plan precedes semantic change: phase 1 ships with the
  exfiltration-denial scenarios listed in §6.
