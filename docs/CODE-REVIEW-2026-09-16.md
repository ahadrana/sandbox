# Code Review — 2026-09-16 (endpoint data plane + routed restore commits)

Scope: commits `0bd18e6`, `f20e4da`, `8e71fce`, `24cc4ed` — the follow-up queue
(tools GC, CheckpointGuard plumbing, k8s net tooling), hostname bindings +
endpoint-proxyd, host→guest port publishing, and routed restore (ADR-008).
Four parallel reviewers, one per commit. Findings consolidated and ranked below.

**Overall verdict:** the architecture and lifecycle design of all four commits
are sound, honestly documented, and well tested on their happy paths — but the
review found two classes of problems that must be fixed before this path
carries real traffic: (a) the port-publishing data plane matches **dport only**,
so any matching host/forwarded traffic is redirected into untrusted guests, and
(b) routed restore's placement re-registration is not atomic with the
host-side restore, re-opening exactly the false-continuity window ADR-008
claims to close. Plus one remote-DoS path in the resume proxy.

## Critical

- **C1. DNAT rules match dport only — hijacks unrelated host + routed traffic.**
  `runtime/firecracker-backend/publish.go:69-91`: `-p tcp --dport <port> -j DNAT`
  hooked from PREROUTING (no qualifier) and OUTPUT (only `! -d 127.0.0.0/8`).
  With `hostNetwork: true`, any outbound host connection to the published port
  (e.g. tenant publishes 443 → all host HTTPS: image pulls, API calls) lands in
  the untrusted guest; PREROUTING also hijacks *forwarded* pod-to-pod traffic.
  Confidentiality break, not just availability. Likely the real mechanism of the
  "8080 smoke incident". Fix: `-m addrtype --dst-type LOCAL` on both hooks
  (optionally restrict to host addresses).
  **FIXED** — addrtype LOCAL on PREROUTING, addrtype LOCAL + `! -d 127.0.0.0/8`
  on OUTPUT; `TestPublishMatchesLocalAddrOnly` (FC) proves host-uplink reach
  and no hijack of a non-LOCAL dst on the same dport.

## High

- **H1. Tenant can hijack platform/system ports.** `publish.go` +
  `hostagent.go:206-224`: `ProtectPorts` covers only the agent RPC port. A
  binding with TargetPort 22/10250/control-plane ports DNATs inbound service
  traffic into tenant code. No well-known-port floor, no listen check, no
  per-tenant range policy. INV-018/INV-027 fail-open. Fix: refuse <1024 +
  configurable deny-list.
  **FIXED** — floor 1024 + deny-list (default 6443/8080/10250,
  `Config.PublishDenyPorts`, `FC_PUBLISH_DENY_PORTS`) in the backend publish
  path with typed ErrPortConflict; port range validated in backend, manager,
  and control-planed; `TestPublishPortPolicyFloorAndDenyList`.
- **H2. Publish/unpublish RPCs bypass HostAgent fencing.** `hostagent.go:455-481`
  skips `h.route(handle)` and carries no fence (`rpc.go:175-183`) — stale
  control-plane views can install/remove DNAT the ownership model would reject.
  **FIXED** — publish/unpublish RPCs now route via `h.route` and carry a fence;
  stale fence → typed ErrStaleFence (same sentinel pattern as routed restore);
  `TestPublishProtectsRPCPort` covers stale/unknown/protected paths.
- **H3. Unknown-hostname spray = unauthenticated control-plane DoS.**
  `resumeproxy/proxy.go:245`: no negative name caching; every unknown Host →
  `BindingByName` → O(n) scan under the manager's global `m.mu`
  (`manager.go:1722`), which serializes the whole control plane. Client-reachable
  proxy → remote DoS. Fix: short-TTL negative cache + name index in manager.
  **FIXED** — proxy negative-caches unknown names (`NameNegativeTTL`, new
  `NegativeNameHits` metric); manager indexes bindings by logical name
  (`bindingsByName`, maintained on create/store-load); 404 stays fail-closed;
  `TestUnknownNameSprayNegativeCached`, `TestBindingByNameIndexAcrossLifecycle`.
- **H4. Restored incarnation can be orphan-scrubbed → false continuity
  (INV-008/009).** `fleet.go:388-397` registers placement only *after*
  `host.Restore` returns; `RegisterHost` (`fleet.go:134-147`) kills unregistered
  incarnations. Agent restart in that window → VM killed while the manager
  already took the continuity path (epoch preserved, bindings republished to a
  dead VM). Fix: pending-placement registration under `f.mu` before the RPC.
  **FIXED** — `Fleet.Restore` registers a pending placement before the RPC;
  `RegisterHost` treats pending incarnations as owned; failure rolls back
  with a best-effort host Terminate; ADR-008 amendment;
  `TestFleetRestorePendingSurvivesReregister`,
  `TestFleetRestoreRollbackTerminatesOnFailure`.
- **H5. Lost restore ACK strands a fleet-invisible live incarnation; Restore not
  idempotent.** Lost response → manager falls back to workspace-only, restored
  VM keeps running unknown to the fleet; retried Restore with same fence
  re-boots the incarnation (`hostagent.go:500-503`). Fix: idempotent restore
  replay + reconcile.
  **FIXED** — (a) `HostAgent.Restore` of an already-live incarnation under
  the same fence returns the handle without re-booting;
  (b) fleet rollback Terminate on restore-RPC error + manager Resume
  terminates the checkpoint incarnation unconditionally before
  workspace-only fallback; `TestHostAgentRestoreIdempotentReplay`,
  `TestResumeAmbiguousRestoreReconciles`.

## Medium

- **M1. 15s HTTP client timeout vs 60s resume design.** `rpc.go:475` per-call
  client with 15s timeout; a real restore exceeds it → attempt budget (2)
  burned against a healthy-but-slow resume → 503 + negative cache. Contradicts
  ADR-007 §4. Fix: transport timeout ≥ ResumeTimeout.
  **FIXED** — `rpc.PostJSONWithTimeout` added; endpoint-proxyd's resume call
  uses 75s (≥ the proxy's 60s ResumeTimeout); lookups keep the sharp 15s
  client; `TestPostJSONTimeoutPlumbing`.
- **M2. Transient control-plane errors surface as 403.** `endpoint-proxyd
  main.go:70` maps transport/5xx to deny → client sees 403 (indistinguishable
  from real deny); resume trigger is reason-string matching — fragile for a
  security-relevant branch. Should be 502/503 + typed verdicts.
  **FIXED** — `RouteDecision` gains typed additive fields: `Resumable` (set
  server-side by the gateway for binding-SUSPENDED / sandbox-not-live denies;
  replaces reason-string matching) and `LookupError` (set client-side on
  transport/5xx → proxy answers 502, never resumes, `RouteErrors` metric);
  `TestRouteLookupErrorIsBadGatewayNotDeny`.
- **M3. `createBinding` accepts never-routable bindings.** control-planed: TTL 0
  or huge (Duration overflow → negative), target_port unvalidated — creation
  succeeds, gateway denies forever. Silent trap.
- **M4. Blocking host RPC under manager lock.** `CreateEndpointBinding` and
  `publishActiveBindingsLocked` hold `m.mu` across Fleet RPCs; a hung host
  stalls all manager operations; N bindings = N serialized RPCs under lock.
  **FIXED** — publish targets are resolved under `m.mu`
  (`publishTargetLocked`), the RPCs run with `m.mu` dropped, and outcomes
  are recorded after re-acquiring with revalidation (epoch/state for
  create, still-ACTIVE for republish/Tick-retry); publish-before-persist +
  M6 compensation preserved.
- **M5. Host-side restore validation fail-open for metadata-poor checkpoints.**
  `hostagent.go:481-499`: missing `sandbox_id` → fence check skipped + outside
  bySandbox (no orphan protection); unparseable `memory_bytes` → capacity
  charge 0. Reject unparseable accounting facts instead of defaulting.
  **FIXED** — re-registration restore requires parseable `sandbox_id` and
  `memory_bytes`, else typed `ErrInvalidCheckpoint`;
  `TestHostAgentRestoreRejectsMissingFacts`.
- **M6. Publish-before-persist has no compensating action.** `manager.go:1733-42`:
  DNAT installed before `m.tx` commit; later failure leaks rule + port with no
  owning binding.
  **FIXED** — `CreateEndpointBinding` now unpublishes and drops the binding if
  the commit after publish fails; `TestEndpointPublishCompensatedOnCommitFailure`.
- **M7. PublishPort vs teardown race recreates torn-down chain.** `publish.go`
  holds `installMu`; `cleanupNetDevices` never takes it → `-N FC-PUB-*` can
  re-run after `-X`, leaking a publish on a dead incarnation until FM11 sweep.
  **FIXED** — `cleanupNetDevices`/`cleanupPubRules` now take `ns.installMu`.
- **M8. gcToolsImages races.** Deletes in-progress `.tmp` builds without
  `toolsMu` (Create then fails ENOENT); scan-under-`b.mu` then delete-unlocked
  races Create's stat→register (live incarnation with deleted tools drive).
  Fix: hold toolsMu/b.mu across scan+delete.
  **FIXED** — `gcToolsImages` holds `b.mu` (then `toolsMu`, Create's lock
  order) across the whole reference scan + delete pass;
  `TestToolsImageGCSkipsInFlightTmp`.
- **M9. `capacityFailures` asymmetry.** `Fleet.Restore` increments on failed
  Place, never resets on success (Create does); restore is pinned to one host
  so a full origin ratchets the fleet-wide scale-out signal permanently.
  **FIXED** — pinned-origin restore placement failures no longer increment
  the fleet-wide counter at all (a full origin says nothing about fleet
  capacity; justified in code comment), and a successful restore resets the
  streak like Create; `TestFleetCapacityFailuresResetOnRestore`.

## Low

- L1. Idempotent re-publish skips `ns.published` bookkeeping → later unpublish
  misses the `-D` (teardown is backstop). `publish.go:147-150`.
  **FIXED** — the `-C` hit path now records `ns.published[hostPort]`.
- L2. Re-publish same slot with changed guestPort appends a shadowed second
  rule; unpublish removes only newest. `publish.go:132-138`.
  **FIXED** — same-slot changed-guestPort re-publish is rejected with typed
  ErrPortConflict (unpublish to remap); documented in publish.go package
  comment; `TestPublishPortRemapRejected`.
- L3. `ErrPortConflict` typing does not survive RPC serialization.
  **FIXED** — `"port conflict"` wire sentinel + mapError reverse, same pattern
  as stale-fence; `TestPublishFenceAndConflictRoundTrip`.
- L4. `EndpointPublishFailed` is emit-and-forget — no retry/reconcile on Tick;
  binding stays ACTIVE-but-unreachable.
  **FIXED** — bounded reconcile-on-Tick retry (maxPublishRetries=5) for
  ACTIVE-but-unpublished bindings; `TestEndpointPublishRetriedOnTick`.
- L5. Live in-place restore can regress `rec.fence` below advanced
  `h.fences[sandboxID]`. `hostagent.go:506-508`.
  **FIXED** — fence adoption is a max, never an assignment;
  `TestRestoreFenceNoRegression`.
- L6. RPC `restore` nil-derefs `req.Checkpoint` (recovered as error; same
  pre-existing pattern as `exec`).
  **FIXED** — nil checkpoint rejected with a typed bad-request error before
  deref; `TestRestoreNilCheckpointRejected`.
- L7. `scheduler.Guard` drops the `arch` fact (P0.4 restore validation still
  fails closed — placement-quality only).
  **FIXED** — `Guard`/`HostView` gain `Arch` (exact match when set, empty =
  legacy unguarded), populated from `CheckpointFacts["arch"]` and
  `HostAgent.View`; `TestCheckpointGuardArch`.
- L8. Empty/partial CheckpointFacts map → `Guard{"",""}` → unconditional
  locality bonus (legacy behavior the guard exists to gate); safe only because
  the sole producer filters empties.
  **FIXED** — fleet guard construction treats an all-empty Guard as "no
  guard" (defense in depth).
- L9. netinit sysctl is node-wide and persists after the pod
  (`ip_unprivileged_port_start=0` on hostNetwork) — documented but unenforced
  host-hardening regression; dedicated nodes assumed, not enforced.
- L10. Hostname/case: `BindingByName` is case-sensitive, creation does no
  name validation/normalization → bindings creatable that the resolver can
  never produce (`Ep1`, `ep.1`).
  **FIXED** — `CreateEndpointBinding` validates the logical name (single
  lowercase DNS label, 1-63 chars, `[a-z0-9-]`, no leading/trailing
  hyphen) at the manager, so every edge rejects unresolvable names;
  `TestEndpointLogicalNameValidation`.
- L11. SSRF-flavored trust: `/v1/sandboxes/{id}/address` returns
  heartbeat-self-reported URL; proxy dials it. Consistent with dev shared-token
  posture; note INV-018 surface expansion (one token → data path + actuation
  + topology).
- L12. Stale name→binding cache after unbind/recreate (≤CacheTTL of 403s);
  caches never size-bounded. Dev-scale acceptable.
- L13. xtables plugins were copied to `/lib/...` instead of compiled-in
  `/usr/lib/...` in `0bd18e6` — already fixed at HEAD; noted for the record.
- L14. jail.go pre-spawn bind mount is rw without nodev/nosuid (largely
  inherent) and now exists for every jail even when never snapshotting.

## Confirmed sound (checked explicitly)

- Tools-GC reference set vs ADR-006 chains (restored incarnations covered;
  gcSnapshots-before-gcToolsImages ordering; every chain link carries its sha).
- CheckpointFacts: fresh-map copy, conservative degradation of stale facts,
  trusted producer path only.
- Publish verify-after-install/undo discipline; FM11 nat-table sweep actually
  reclaims crash residue; no shell-string iptables (argv only).
- Host-header parsing (ports, case, trailing dots, suffix-anchored
  anti-`evil.com` match); header-beats-host precedence; fail-closed unknown
  names; server-side route evaluation as single source of verdict.
- Restore: fence refreshed in a *copy* of metadata (no aliasing); origin_host
  captured before reclaim erases placement; capacity exactly-once on happy
  path; republish ordering (handles set before reactivate); `restore_error` +
  `loggingRestore` observability; honest `SupportsRestore` intersection;
  jail bind-mount cleanup on all failure paths.

## Follow-up queue (priority order)

1. ~~C1 addrtype/dst-type LOCAL match on publish hooks.~~ FIXED (Batch A).
2. ~~H1 protected port floor + deny-list.~~ FIXED (Batch A).
3. ~~H4+H5 atomic pending-placement registration + idempotent restore.~~
   FIXED (Batch C).
4. ~~H3 negative name cache + manager name index.~~ FIXED (Batch B).
5. ~~H2 fence/route enforcement on publish RPCs.~~ FIXED (Batch A).
6. ~~M1 transport timeout alignment; M2 typed route verdicts~~ (M1/M2 FIXED,
   Batch B); ~~M3 binding validation (TTL, port)~~ (M3 FIXED, Batch A);
   ~~M4 drop m.mu across fleet RPCs~~ FIXED (Batch B).
7. ~~M5 reject unparseable restore metadata~~ FIXED (Batch C); ~~M6
   compensating unpublish; M7 installMu in cleanup~~ (M6/M7 FIXED, Batch A);
   ~~M8 GC locking~~ FIXED (Batch B); ~~M9 capacity-failure reset~~ FIXED
   (Batch C).
8. L-items as a batch (L1–L4 FIXED, Batch A; L10 FIXED, Batch B; L5–L8
   FIXED, Batch C; L9, L11–L14 open).
