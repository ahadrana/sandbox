# ADR-0007: Traffic-triggered resume (ingress resume-proxy) — ACCEPTED

- **Status:** accepted
- **Date:** 2026-09-15
- **Deciders:** platform team

## Context

INV-002 says agent activation must not imply sandbox materialization: a
suspended sandbox holds no compute, and *something* must materialize it
when real work arrives. For exec-driven work the agent driver already
calls `Manager.Resume`. But endpoint traffic (PLAN §12 endpoint bindings,
the `network.Gateway` routing tier) had no counterpart: a request to a
suspended sandbox's binding was denied fail-closed ("sandbox not live" /
"binding SUSPENDED") and the client had to know to resume out-of-band.
CubeSandbox's nginx-router pattern closes exactly this gap: the proxy
detects request-to-suspended-sandbox, single-flights a resume, then
forwards — the cold-start counterpart of INV-002 (borrow-list P1.9).

Two platform facts shape the design:

- `network.Gateway.Route` is deliberately fail-closed and dumb; it is the
  right place to *verdict*, not to *act*. Acting (resume) belongs in
  front of it.
- `Manager.Resume` is the single, transactional resume path (checkpoint
  continuity or workspace-only); it is idempotent-ish per sandbox but not
  cheap (snapshot restore), so concurrent triggers must share one call.
- A latent gap: suspend marks the sandbox's bindings `EndpointSuspended`,
  but no path ever reactivated them, so a resumed sandbox's bindings
  would still be denied. This ADR fixes that in the manager (below).

## Decision

1. **A small ingress resume-proxy (`control-plane/resumeproxy`) sits in
   front of the gateway/host-agent data path.** It is an HTTP reverse
   proxy, stdlib-only (`net/http/httputil`), Go 1.18-compatible. Requests
   carry their endpoint binding ID (header `X-Endpoint-Binding`; hostname
   mapping is a deployment concern). The proxy resolves the binding via
   `network.Gateway.Route` and:
   - **Allowed (running):** forward to the sandbox's upstream address
     (resolved by a caller-supplied `Upstream` func — in the fleet this is
     the host-agent's address for the incarnation; in tests an httptest
     server).
   - **Denied as not-live** ("sandbox not live" or binding SUSPENDED):
     trigger a resume, then re-route and forward on success.
   - **Any other deny** (unknown binding, expired, stale epoch fence):
     pass the deny through as 403 — the proxy never weakens the
     gateway's fail-closed posture.
2. **Single-flight semantics.** Resumes are keyed by sandbox ID; the
   first request to trigger starts the flight, concurrent requests for
   the same suspended sandbox attach to it and share its outcome. The
   flight performs at most `MaxResumeAttempts` (default 2) sequential
   `Resume` calls. Waiters bound their patience with `ResumeTimeout`
   (default 60s): a timeout returns 504 to that waiter while the flight
   continues — a slow restore is paid once, never per request.
3. **Hot path stays cheap.** A binding verified live is cached for
   `CacheTTL` (default 2s); cached-live requests forward with **zero**
   control-plane calls (no `BindingView`, no `Route`). After the TTL the
   next request re-routes (one read-model call) and re-arms the cache.
   Resume failures set a per-binding negative entry (`NegativeTTL`,
   default 5s) that fails fast with 503 without touching the control
   plane — no stampede against a sandbox that cannot resume right now.
4. **Failure/backoff policy.** Resume errors are bounded by the attempt
   budget inside the flight; after the final failure every waiter gets
   503 and the negative entry suppresses immediate retries. There is no
   retry loop in the proxy beyond the flight budget; recovery is driven
   by later client traffic after the negative TTL expires. Timeouts are
   per-waiter, never retried automatically.
5. **Audit and metrics.** Every resume trigger, shared-flight attach,
   failure, and timeout is counted (in-memory metrics snapshot) and
   resume triggers/failures are recorded to the existing
   `network.AuditLog` (kind `resume_trigger` / `resume_failed`), so
   cold-start frequency is observable per sandbox.
6. **Manager fix: bindings reactivate on resume.** `Manager.Resume` now
   returns the sandbox's `EndpointSuspended` bindings to `EndpointActive`
   when their recorded execution epoch still matches the sandbox epoch
   (i.e., continuity resumes; a workspace-only resume bumps the epoch and
   the fence correctly keeps old bindings unroutable). Without this, the
   resumed sandbox would remain unreachable and the proxy would loop
   resume attempts against a healthy sandbox.
7. **INV-002 interaction.** The proxy *strengthens* INV-002: suspension
   becomes transparent to endpoint clients, so the control plane can
   reclaim compute more aggressively without changing client contracts.
   The proxy never materializes on its own schedule (no warming, no
   polling) — only executable work (a real request) justifies a resume,
   which is exactly INV-002's criterion.

### Rejected alternatives

- **Client-driven resume** (status quo): pushes cold-start knowledge into
  every SDK and caller; a generic HTTP client (browser, webhook,
  cron) cannot do it; it also races N clients into N resume calls.
- **Always-on polling / keep-alive resumer** (control plane periodically
  resumes "important" sandboxes): violates INV-002 directly, burns
  compute on sandboxes nobody is calling, and needs a second policy
  surface for importance.
- **Resume inside `network.Gateway`:** the gateway is a pure read-model
  verdict function used by multiple callers; giving it side effects
  (mutating control-plane state per route call) would break its
  fail-closed auditability and make every routing decision a potential
  write.
- **Queueing requests during resume** instead of holding connections:
  adds a durable queue and replay semantics for zero gain over a bounded
  in-flight wait at HTTP timescales.

## Consequences

- Positive: suspended sandboxes are first-class addressable; endpoint
  bindings survive suspend/resume transparently (continuity resumes);
  resume storms are structurally impossible (single-flight + negative
  cache).
- Positive: the hot path adds one map lookup per request; the control
  plane sees at most one route read per binding per 2s and at most one
  resume per sandbox per cold start.
- Negative: the proxy is a new data-plane hop and a new availability
  dependency for endpoint traffic; its live-cache can route to a sandbox
  that died within the TTL window (upstream dial fails → 502, correct
  fail-fast, next request re-routes).
- Follow-ups: hostname-based binding resolution and traffic tokens
  (P2.12) at the proxy edge; wiring the proxy in front of the k3s
  host-agents (ADR-005 topology); resume-trigger metrics export to the
  event service.

## Compliance

- [x] Does not weaken INV-005..INV-016: resume stays the manager's single
  transactional path; the gateway stays fail-closed; epoch fences are
  honored (workspace-only resumes keep old bindings denied).
- [x] INV-002 strengthened: materialization only on real traffic.
- [x] Conformance-style tests added before reliance: single-flight under
  concurrency, hot-path purity, bounded failure, timeout, cache expiry,
  and an end-to-end manager+fake-backend test.
- [x] No vendor concepts leak: the proxy speaks HTTP + the existing
  `network` read model only.
