# ADR-0011: Sandbox snapshot primacy — durable disk state first, continuity checkpoints as accelerator — ACCEPTED

- **Status:** accepted
- **Date:** 2026-09-18
- **Deciders:** platform team

## Context

The platform's checkpoint abstraction grew bottom-up from the Firecracker
backend: the snapshot package (`vm.state` + `mem.file` + rootfs/workspace
extents, ADR-006) is treated as the primary artifact, and the committed
workspace generation rides along inside it. Resume has two paths, but they
are framed asymmetrically: continuity restore (VM resumed from checkpoint,
epoch preserved) is "success", and workspace-only recovery (epoch bump,
`ExecutionStateReset`) is framed and logged as a fallback after a failure.

An analysis of Cursor's public sandbox model — an industry-scale, widely
used agent-sandbox product — validates the opposite framing. In Cursor's
model the durable unit is disk-only: a build snapshot plus `start` and
`terminal` hooks that reconstruct runtime state on boot; RAM hibernation
exists at most as an optimization; and the lifecycle distinguishes ACTIVE
(keep the VM alive) from IDLE (reclaimable). Correctness there never
depends on a memory image. We take this as industry validation of the
disk-primary model and invert our primacy to match.

Forces that make the inversion cheap for us:

- The durable half already exists and is already correct: workspace
  generations (INV-005/006), the workspace-only resume path (INV-009), and
  honest loss reporting (ADR-002) all shipped before this ADR. Nothing about
  the inversion requires new correctness machinery — it re-ranks what
  already exists.
- Cross-machine continuity restore is gated by an exact compatibility guard
  (arch + CPU part + host kernel release + Firecracker version, P1.7/P0.4).
  The two-machine fleet validation (2026-09-18) showed both layers of that
  guard firing correctly across a host kernel difference (6.8 vs 7.0) — and
  showed that host kernel upgrades, which are routine fleet events, destroy
  continuity for every suspended sandbox on the host unless the checkpoint
  layer is demoted from the correctness path.
- INV-009 already states the principle ("snapshots preserve continuity but
  are never the sole source of truth"); this ADR makes the packaging and
  lifecycle reflect it.

## Decision

### Three first-class terms

1. **Workspace Generation** — the immutable committed filesystem state of a
   sandbox (exists today; INV-005/006). Never mutated after commit.
2. **Sandbox Snapshot** — THE portable durable unit of a sandbox: a
   workspace generation + environment/build identity + task/runtime
   metadata + a restart recipe (startup commands; hooks in step 2). A
   Sandbox Snapshot is correctness-critical: every suspended or reclaimed
   sandbox must have one durable, and any fleet host can materialize it.
3. **Continuity Checkpoint** — `vm.state` + `mem.file` (+ chain links,
   ADR-006) plus a compatibility class: arch + CPU part + host kernel class
   + Firecracker version (the existing CheckpointGuard facts). A Continuity
   Checkpoint is an optional accelerator attached to a Sandbox Snapshot.
   It is never correctness-critical.

### Primacy inversion and resume semantics

The Sandbox Snapshot is the durable sandbox format; the Continuity
Checkpoint rides on it, not vice versa. Resume has two co-equal supported
paths:

- **Continuity resume** — a compatible Continuity Checkpoint exists for an
  available host: exact continuation, epoch preserved, startup hooks NOT
  run (the workload never stopped from its own perspective).
- **Snapshot resume** — no compatible checkpoint (host lost, kernel
  upgraded, guard mismatch, checkpoint GC'd): materialize the Sandbox
  Snapshot, run the startup hooks (step 2), epoch increments,
  `ExecutionStateReset` emitted with the lost classes. This is a NORMAL
  resume mechanism — not a failure mode, not a "fallback". It must be as
  exercised, tested, and fast as the continuity path.

### Lifecycle policy (implementation is step 3)

- **ACTIVE** — foreground or background work exists under a lease: keep the
  VM alive. Checkpoint-reclaim does not apply.
- **IDLE** — no live work: optionally take a Continuity Checkpoint, ALWAYS
  ensure the Sandbox Snapshot is durable, then reclaim the VM. The order is
  mandated: snapshot durable first, checkpoint second, reclaim last.

## Amendment 2026-09-18: step 3 implemented (ACTIVE/IDLE reclaim policy)

The lifecycle policy above is now executable, as an automatic idle-reclaim
driver in the manager's `Tick`:

- **Predicates.** A sandbox is a reclaim candidate iff it has a live
  incarnation AND observed state RUNNING or QUIESCENT (BACKGROUND_ACTIVE is
  explicitly excluded) AND it is quiescent under THE quiescence policy
  (`quiescentLocked`, INV-012: no active API executions, no live
  non-baseline processes) AND has been continuously so for at least
  `PolicyConfig.IdleReclaimAfter` (default 30m; zero disables the driver).
  Baseline services never block quiescence, as before — and any live
  non-baseline work, including terminal-hook services, keeps the sandbox
  ACTIVE and unreclaimable. Reclaim-after-deadline-quiesce is legal by
  construction: INV-015 background deadlines (MaxBackgroundWall) kill
  runaway work first, the sandbox quiesces, and only then does the idle
  clock start.
- **Reclaim action.** The driver routes through the shared suspend path
  (`suspendWithReasonLocked(sb, "idle_reclaim", allowCheckpoint=true)`), so
  the mandated order holds: workspace committed (Sandbox Snapshot durable)
  before the checkpoint attempt, checkpoint before RAM release. On
  snapshot-class backends RAM is really reclaimed with continuity restore
  available; on STOP/CONT-class backends the suspend honestly reports no
  reclamation; with checkpoint unavailable/failed it degrades to the
  workspace-only path, making the subsequent resume epoch-creating (hooks
  re-run per step 2).
- **Capacity pressure.** Unchanged and verified: placement pressure never
  reclaims ACTIVE work. Preemption remains priority/class-based,
  workspace-only, BACKGROUND-class victims of strictly lower priority for
  INTERACTIVE requesters; with no legal victim the create fails honestly
  (quota/placement error + event). The idle driver is the only
  checkpoint-reclaim trigger, and it selects idle sandboxes only.
- **Observability.** The suspend event carries `reason: idle_reclaim` (plus
  the usual mode/ram_reclaimed detail). Skipped active sandboxes emit no
  events; they increment the `IdleReclaimSkipsActive` metrics counter, and
  reclaims increment `IdleReclaims` (Manager.Metrics snapshot).
- **Evidence.** Local: active sandboxes never reclaimed 10x past threshold;
  quiescent reclaimed exactly at threshold with checkpoint taken; reclaim
  legal only after background-deadline quiesce; all-active capacity
  pressure fails the new create honestly without disturbing work;
  idle-reclaimed sandbox on the workspace-only path resumes via step-2
  hooks (HTTP service reconstructed). Remote (firecracker, node1):
  `TestFirecrackerIdleReclaimReclaimsRAM` — automatic driver suspends a
  quiescent VM with `ram_reclaimed_bytes > 0`, VMM gone, continuity resume
  restores it with the epoch retained.
- **Deferred.** No IDLE→ACTIVE traffic-driven wake policy changes (resume
  proxy already wakes on demand); no idle reaper for the lease-expired
  case beyond the existing wall-deadline enforcement.

### Startup hooks rule (spec here; implementation is step 2)

Startup hooks run on every epoch-creating resume (snapshot resume), and
never on a continuity restore. Hooks are part of the Sandbox Snapshot's
restart recipe, so a sandbox that must rebuild terminals, agents, or
servers does so identically after host loss, kernel upgrade, or cold
materialization.

## Amendment 2026-09-18: step 2 implemented (startup hooks)

Step 2 landed as specified:

- **Schema (additive).** `EnvironmentSpec` gained `Start` / `Terminals`
  ([]string). They participate in `SpecDigest` only when non-empty, so
  hook-less environment digests (and dedup/reuse) are unchanged. The
  resolved recipe is copied onto the `Sandbox` record
  (`StartHooks`/`TerminalHooks`) at create time, so hook execution does not
  depend on the environment still existing at resume.
- **Persistence.** The recipe is persisted twice: `recipe.json` beside
  `manifest.json` in the environment artifact (served by
  `Builder.HookRecipe`, surviving builder restarts and environment
  retirement), and `Spec.HookStart`/`Spec.HookTerminals` inside the
  firecracker snapshot package's `meta.json` (additive; legacy packages
  lack the fields and validation tolerates their absence). The manager's
  sandbox record remains the source of truth on restore; meta.json carries
  the recipe for package portability and inspection.
- **Execution semantics.** On every epoch-creating materialization (fresh
  create, snapshot/workspace-only resume — never a continuity restore), the
  manager runs, in order: start hooks (sequential, must exit 0), then the
  sandbox's per-session StartupCommands/BaselineCommands (unchanged), then
  terminal hooks (long-running; launched backgrounded in the guest, not
  waited on). A failing start hook is an honest boot failure: the sandbox
  transitions FAILED with `EnvironmentHooksFailed` + `SandboxFailed`, never
  RUNNING-without-services. Hooks complete before `ExecutionStateReset` and
  the RUNNING transition are published, so observers never see a sandbox
  advertised as ready before its services were reconstructed.
- **Recording.** Each hook runs as a real hook-labeled `Execution`
  (`Operation.Hook` = "start"/"terminal", principal `environment-hook`,
  idempotency key `hook:<label>:<idx>:epoch-<n>`) with
  `ExecutionStarted/Completed/Failed` events (INV-010/INV-013). Lifecycle
  events `EnvironmentHooksStarted/Completed/Failed` bracket the block; an
  environment with no recorded recipe emits `HooksCompleted` with
  `recipe_empty: true` so absence is distinguishable from silence.
- **Idempotency contract.** Hooks must be idempotent: any sandbox may
  re-run them on a later epoch (host loss, reclaiming suspend, kernel
  upgrade). Terminal hooks are wrapped `( cmd ) < /dev/null >>
  /tmp/hook-terminal-N.log 2>&1 & echo launched` so the hook execution
  completes at launch.
- **Evidence.** Local (local-backend): hook ordering and lifecycle-event
  order on fresh materialize; failing start hook → FAILED; marquee
  reconstruct-services — a terminal-hook `python3 -m http.server` serving
  the workspace is killed by a reclaiming (workspace-only) suspend and
  serves again after resume with no agent-driven execution; continuity
  (STOP/CONT checkpoint) resume runs no hooks and retains the epoch; recipe
  persistence across builder reopen. Remote (firecracker, node1):
  `TestFirecrackerStartupHooksReconstructServices` re-runs the marquee
  against real VMs (workspace-only suspend → new VM → `sleep` service
  reconstructed, epoch 1→2, hooks completed before reset). Full FC
  conformance + firecracker-backend suites green.
- **Deferred.** Step 3 landed in the amendment above; the meta.json
  primary-section reshaping beyond the additive Spec fields stays as it was
  (the package remains chain-shaped, primacy contractual).

### What does not change

- INV-009 is unchanged and reinforced: continuity checkpoints were never
  the sole source of truth; now the packaging says so.
- ADR-006 (incremental chains), ADR-008 (origin-host routed restore), and
  ADR-009 (cross-host pull) remain valid — as the accelerator tier.
- Compatibility cohorts are exactly the existing CheckpointGuard facts; no
  new fact plumbing.

## Consequences

- Positive: host kernel security upgrades become non-events for idle
  sandboxes (they snapshot-resume on next traffic with an epoch bump and
  hooks, instead of being stranded behind a guard mismatch). Fleet draining
  and rebalancing stop being continuity-destroying events. The resume
  fast/slow paths share one durability contract, which simplifies
  reasoning, docs, and eventually the code.
- Positive: cross-kernel continuity restore is demoted from a correctness
  gap to a cohort-expansion optimization; the experiment (bypassing the
  kernel guard across 6.8/7.0) is deprioritized accordingly.
- Negative / costs: snapshot resume re-runs hooks and loses guest RAM —
  workloads that need RAM continuity across host maintenance still need
  matching cohorts. Two resume paths must both stay fast and well-tested.
  The current snapshot package format (meta.json) still physically carries
  workspace bits inside the checkpoint chain; the conceptual remapping is
  documented in code; step 2 (amendment above) physically added the
  restart-recipe fields to meta.json via `Spec.HookStart`/`HookTerminals`.
- Follow-ups: soak-coverage of the
  snapshot-resume path at the same depth as continuity resume, now including
  idle-reclaim-driven churn.

## Alternatives considered

- **Keep checkpoint-primary packaging, document harder.** Rejected: the
  framing mismatch is not cosmetic — it decides what breaks on a kernel
  upgrade, what the lifecycle reclaims first, and which resume path gets
  engineering effort. Documentation cannot fix a ranking baked into the
  artifact layout.
- **Full hibernation portability (cross-kernel/cross-FC checkpoint
  restore).** Rejected as a correctness dependency: guest RAM images are
  VMM- and host-kernel-specific in practice; making them portable is
  unbounded work for an optimization. Cohort expansion within the existing
  guard remains welcome — as an optimization.
- **Adopt Cursor's exact model (no RAM preservation at all).** Rejected:
  continuity resume is already built, tested, and demonstrably valuable
  (epoch-preserved restores proven on the two-machine fleet); the inversion
  keeps it as an accelerator rather than deleting it.

## Compliance

- [x] Does not weaken INV-005..INV-016 or make state loss silent: the ADR
  re-ranks existing, already-honest mechanisms. Snapshot resume keeps the
  epoch bump + `ExecutionStateReset` + lost-classes reporting (INV-002/008);
  INV-009 is quoted and reinforced, not edited.
- [x] Conformance tests updated/added before semantic change: step 2
  (hooks) landed with its conformance coverage — hook ordering/failure/
  reconstruct-services/continuity-skip tests locally and the firecracker
  marquee on node1 (see amendment); durability/isolation/fleet suites and
  SandboxLab scenario gates (host-loss-mid-restore, guard-mismatch) stay
  green.
- [x] No invariant text required editing: INVARIANTS.md already encodes the
  disk-primary contract (INV-005/006/008/009); this ADR aligns packaging
  and lifecycle language with it.
