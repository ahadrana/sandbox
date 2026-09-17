# ADR-0010: SandboxLab — deterministic discrete-event simulation of the control plane — ACCEPTED

- **Status:** accepted
- **Date:** 2026-09-17
- **Deciders:** platform team

## Context

Every correctness claim so far rests on two harnesses with opposite blind
spots:

- The **conformance suite** (`conformance/`) runs the real control-plane code
  in-process against fake backends and proves per-invariant behavior — but
  each test is a hand-written sequence on a 1–3 host fleet. Multi-host
  placement under load, storm timing, and fleet-wide capacity interactions
  are argued, not measured.
- The **live simulator** (`cmd/sandbox-sim`) drives the deployed control
  plane over real HTTP against real hosts — it proves the wiring end to end,
  but it is wall-clock, single-node, and bounded by the one bare-metal k3s
  node we have. It can never answer "what happens when 200 sandboxes storm 5
  hosts" or "what is the p99 wake latency of a 100-sandbox resume burst".

The gaps that need a third harness are all *scale-and-timing* questions on
the real control-plane logic: does placement respect capacity under a cold
storm, does resume stay single-flight under a burst, does a host loss
mid-restore fall back honestly (ADR-008/009), does the checkpoint-locality
guard (P1.7) behave when no matching host exists, does checkpoint GC behave
under capacity pressure, and does any of this survive 10k sandboxes.

The platform facts that shape the design:

- The control plane is already clock-injected. `sandboxmanager.New` takes a
  `*domain.ManualClock`; `hostagent.NewFleet` takes a `domain.Clock`; the
  scheduler is entirely time-free. The only unseamed time source in the
  sim-relevant call graph is `HostAgent.View()`, which reads
  `hostfacts.Current()` (real `uname`) directly — a facts problem, not a
  clock problem.
- Heartbeat loss and fleet ticks are already externally driven
  (`Fleet.SimulateHostLoss`, `Fleet.HostSeen`, `Fleet.Tick`,
  `Manager.Tick(d)`) — the conformance suite drives them by hand; a
  simulation drives them as scheduled events instead.
- The fake backend is time-free and honest about capabilities; the
  conformance suite already wraps it to flip `CheckpointReclaimsMemory`
  (`reclaimCapsRuntime`), so per-host capability shaping is an established
  pattern.
- The chaos harness (`chaos/chaos.go`) proves seeded `rand.Rand` suffices
  for reproducible workload generation.
- The one genuinely concurrent control-plane component is `resumeproxy`
  (goroutine-per-arrival single-flight). Its `cfg.Now` is injectable and its
  `Metrics()` counters (`ResumeTriggered`, `ResumeShared`) expose join
  state, so a burst test can be made deterministic by gating the resumer on
  a channel and polling metrics until every goroutine has joined the flight.

## Decision

SandboxLab is a new Go package `sandboxlab/` at the repo root: a
**deterministic discrete-event simulation kernel running the real
control-plane code in-process** — the same `sandboxmanager.Manager`,
`hostagent.Fleet`, `scheduler.Scheduler`, and `eventservice.Outbox` the
conformance suite instantiates — driven by a virtual clock and a seeded
event queue instead of wall-clock goroutines.

1. **The virtual clock is `domain.ManualClock`, unmodified.** It is already
   the injected seam every control-plane component accepts. The kernel owns
   the only reference that advances it.
2. **The kernel is a priority event queue ordered by (virtual time, sequence
   number).** Scheduled events — request arrivals, host failures, heartbeat
   stalls, fleet/manager ticks — are `func()` closures the kernel pops and
   runs strictly in order; equal timestamps fire in FIFO sequence order, so
   a given seed and scenario script produce exactly one interleaving. The
   kernel records every fired event (seq, sim time, label) to an in-memory
   **trace**; the trace is the determinism artifact.
3. **RNG is one `rand.New(rand.NewSource(seed))` per scenario.** All
   workload jitter (arrival spacing, op mix, victim selection) draws from
   it; no map iteration order ever leaks into a scheduled decision
   (workload lists are built index-ordered, not map-ranged).
4. **Per-operation latency is virtual and synchronous.** `SimHost` wraps a
   real `*hostagent.HostAgent` (over the fake backend, with the conformance
   capability wrapper applied) and, for each op with a configured latency,
   advances the virtual clock *before* returning. No goroutines, no real
   sleeps: the simulation is single-threaded, which is what makes the trace
   a total order. Latency models work (boot, snapshot, restore), not
   concurrency — concurrency semantics stay with the conformance suite and
   the live harness.
5. **Per-host facts are seamed.** `HostAgent` gains a `SetFacts` override
   used by `View()` in place of `hostfacts.Current()` when set (default
   behavior unchanged). This is the one production-code seam the sim
   requires; it exists because "checkpoint captured on kernel-A, fleet has
   only kernel-B hosts" is a scenario, not a property of the machine running
   the test.
6. **SimFleet composes, not wraps, the real fleet.** It owns the fleet, the
   SimHosts, and the scenario primitives: `AddHost`, scheduled `KillHost`
   (fleet `SimulateHostLoss` + cease `HostSeen`), `StallHeartbeats`,
   `ReviveHost` (`HostSeen`), and a periodic tick event that drives
   `Fleet.Tick`/`Manager.Tick` at a fixed virtual cadence. A "partition" in
   an in-process sim *is* a heartbeat stall — the control plane cannot
   distinguish them, which is precisely the point.
7. **Determinism is a gate, not a hope.** `TestDeterministicTrace` runs the
   same scenario twice with the same seed and requires byte-identical
   traces, and once with a different seed requiring a different trace. CI
   runs it like any other test.
8. **Relationship to `cmd/sandbox-sim`: complementary, not a replacement.**
   sandbox-sim exercises the deployed system over real HTTP and real time
   (transport, auth, daemons, the k3s topology); SandboxLab exercises the
   control-plane logic at scales and timings no single node can reach.
   sandbox-sim is not modified.

## Alternatives considered

- **Extend sandbox-sim with a "virtual time" mode.** Rejected: it would put
  virtual-clock seams into the daemons, the HTTP transports, and the host
  agents' real supervision loops — exactly the surfaces where an unseamed
  `time.Now` is a production behavior we must not simulate away. The sim
  boundary is the in-process component boundary, same as conformance.
- **Model checking / TLA+-style specification.** Rejected for now: the value
  we lack is *evidence about the code we ship*, and a parallel model would
  verify its own assumptions, not the Go control plane. The scenario tests
  here assert platform invariants against the real manager/fleet/scheduler.
- **Goroutine-based sim with a synchronized barrier clock** (every component
  keeps its concurrency, clock advances when all quiesce). Rejected:
  quiescence detection across the proxy/manager goroutines is fragile, and a
  missed wakeup is a silent nondeterminism bug in the harness itself. The
  single-threaded event loop with synchronous latency accounting trades
  realism of scheduling for a guarantee of reproducibility — the right trade
  for a correctness gate.

## Consequences

- Positive: same seed ⇒ byte-identical event trace, so regressions in
  control-plane behavior are diffable artifacts, not flaky red tests.
- Positive: storm, scale, and failure-timing scenarios (cold-start storm,
  resume storm, host loss mid-restore, guard mismatch, checkpoint-GC
  pressure) run in milliseconds of wall time against the real code.
- Positive: exactly one production seam added (`HostAgent.SetFacts`); the
  clock seam already existed everywhere it is needed.
- Negative: the sim cannot see concurrency bugs — the resume-storm
  single-flight test is the one deliberate exception, using the real
  `resumeproxy` with a gated resumer and metrics-join polling. Everything
  else asserts logical outcomes (capacity never oversubscribed, exactly-one
  resume RPC, honest fallback), not scheduling interleavings.
- Negative: virtual latency is per-op and constant-per-host; it models work,
  not contention. Contention claims still belong to the live harness.
- Follow-ups: shared-store origin-destroyed restore scenarios once ADR-009's
  follow-up lands; fault-injection op failures (backend errors by schedule)
  layered on the same event queue.

## Compliance

- [x] Does not weaken INV-005..INV-016: the sim asserts those invariants at
  scale (capacity accounting, fencing, honest restore fallback) rather than
  relaxing them; the only production change is an opt-in facts override that
  defaults to current behavior.
- [x] Conformance tests added before reliance: the determinism gate plus
  scenario tests for cold-start storm, resume storm, host loss mid-restore,
  guard mismatch, checkpoint GC under pressure, and a 10k-sandbox scale
  smoke.
- [x] No vendor-specific concepts leak into the API: `sandboxlab/` is a Go
  test-side package; nothing it touches appears in the external API.

## Amendment (2026-09-17): phase 3 — the executable invariant engine

`sandboxlab/invariants.go` turns docs/INVARIANTS.md into code. An `Engine`
is wired into every `SimFleet` via the kernel's `AfterEach` hook: after each
fired event the engine drains the manager's outbox through event-stream
checkers and samples read-only state snapshots (manager getters, fleet
placement, host accounting, workspace generation digests) — snapshots every
32 events plus a mandatory final one at `Report()` time, which keeps the
10k-sandbox scale smoke fast while remaining exact on a total-order trace.
Violations are recorded twice: as `INVARIANT_VIOLATION` entries in the
kernel trace (the phase-5 UI rendering seam) carrying invariant ID, detail,
kernel seq, and virtual time — and in a `Report` whose verdict line
("invariants checked: N, violations: V") scenario tests assert on. Three
minimal read-only accessors were added to production code:
`Manager.SnapshotSandboxes`, `Manager.LeaseOf`, `Memory.GenerationDigests`.

Coverage of the 30 invariants — every one has a named checker or an
explicit documented reason:

- **Continuous (20)** — evaluated on every run: INV-001 (identity fields
  never mutate; rematerialize-under-same-ID), INV-002 (dormant/suspended
  sandboxes hold no fleet placement), INV-005 (committed generation digests
  immutable), INV-006 (workspace generation never regresses; commits
  ordered), INV-007 (epoch monotonic; reset is +1), INV-008
  (reset-before-continuation ordering), INV-010 (execution identity
  unique/addressable), INV-011 (one execution per idempotency key), INV-012
  (QUIESCENT ⇒ no live descendants, no non-terminal executions), INV-013+016
  (host accounting non-negative, never oversubscribed, backend incarnations
  == accounted slots, no fleet-invisible or double-registered incarnations,
  every live incarnation traces to a lease-holding sandbox), INV-015 (live ⇒
  lease with wall deadline), INV-017 (binding lifecycle states valid, no
  double-bind, no unbound-before-bind), INV-019 (no k8s concepts in event
  payloads), INV-022 (one workspace per sandbox, never shared), INV-024
  (states contract-valid; failures carry reasons), INV-025 (event payloads ≤
  4 KiB), INV-028 (every event tenant-tagged), INV-029 (live never exceeds
  logical; exercised when dormant ≥ 10× live), INV-030 (no model concepts in
  event payloads).
- **Scenario-asserted (2)** — INV-009 (workspace-only resume must carry a
  `restore_error` — fallback never silent), INV-023 (resume paths observed;
  cold-locality recovery exercised by the host-loss and guard-mismatch
  scenarios).
- **Not sim-checkable (8)** — registered with reasons: INV-003/004 (no LLM
  in sim by construction), INV-014 (metering equivalence needs real
  processes), INV-018 (dataplane denial), INV-020 (no k8s exists here),
  INV-021 (no environment builder in sim), INV-026 (sim fixes the fake
  backend), INV-027 (breakout resistance is a real-isolation property).

The engine proves it has teeth with planted-violation meta-tests
(`sandboxlab/invariants_test.go`): a double-registered incarnation (direct
host create behind the fleet's back), a doctored event stream with
`ExecutionStateReset` events filtered out, and a crash-recovered host that
adopted 3 incarnations into 1 slot are each caught by the correct checker
(INV-013/016, INV-008, INV-013/016 respectively).
