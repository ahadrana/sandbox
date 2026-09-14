# Code Review — 2026-09-14

**Scope:** full repository (all M0–M13 packages)
**Method:** five parallel deep reviewers by area; verified against `docs/INVARIANTS.md` / `docs/DESIGN.md`; `go vet` clean, `go test -race ./conformance` clean (~26s)
**Status legend:** [ ] open, [x] fixed (reference the fixing commit)

## High severity

- [x] **H1 — `workspace/durable.go:342` — cross-workspace blob deletion in GC.** `GC(workspaceID)` computes the referenced set from only that workspace's generations, but `blobs/` is a shared content-addressed pool across all workspaces. GC'ing one workspace deletes blobs other workspaces/tenants still reference. Silent durable-state loss (INV-005/022). `Memory.GC` is per-workspace and correct — the implementations diverge.
- [x] **H2 — `environment-builder/builder.go:245` — concurrent `CompleteBuild` races.** `StartBuild` is idempotent but completion is not serialized: two callers `RemoveAll` the same build/artifact dirs concurrently → torn artifacts marked ACTIVE; install counter double-counted.
- [x] **H3 — `control-plane/sandbox-manager/manager.go:1017` — `GenerationAfter` aliases the live sandbox field.** Pointer into mutable `Sandbox.WorkspaceGeneration`; later commits retroactively corrupt historical execution audit records (INV-010).
- [x] **H4 — `manager.go:738` — failed `Materialize` wedges the sandbox in STARTING.** Quota denial / workspace error / `rt.Create` failure returns without transitioning back; retry gets `ErrIllegalState`; only control-plane restart recovers. The quota-deny path durably persists STARTING.
- [x] **H5 — `manager.go:782` — runtime loss never finalizes in-flight executions.** Kill/host-loss marks the sandbox FAILED but RUNNING executions stay RUNNING indefinitely — a reconnecting client never gets a terminal result until a restart reconciles (INV-010).
- [x] **H6 — `control-plane/sandbox-manager/filestore.go:131` — `Snapshot()` not crash-atomic.** No fsync before rename; journal truncated before the snapshot is durable → crash during compaction can destroy all control-plane state. Correct order: fsync tmp → rename → fsync dir → truncate journal → fsync journal+dir.
- [x] **H7 — `runtime/local-backend/local.go:385` + `runtime/local-backend/supervisor.go:61` — path traversal.** `BackgroundSpec.Name` flows unsanitized into output-file path joins; `../` escapes the output dir and creates/truncates arbitrary host files. Also `ReadOutput` (supervisor.go:182).
- [x] **H8 — `runtime/host-agent/hostagent.go:199` — check-and-create not atomic.** Lock dropped between fence/capacity check and `backend.Create`: racing duplicate creates produce two incarnations, double-charge capacity, leak a workspace dir.
- [x] **H9 — `environment-builder/builder.go:357` — RETIRED status never persisted.** Old env's `environment.json` still says ACTIVE; after `Open()` both are ACTIVE and the family default is nondeterministic (map order). Untested.

## Medium severity

- [x] **M1 — `domain/statemachine.go:55` — self-transitions legal from terminal states.** `CancelExecution` on a cancelled execution re-completes it and emits a duplicate event; `Manager.transition` with `to == current` bumps `Sandbox.Version` silently.
- [x] **M2 — `manager.go:849` — epoch fence inert unless `DependsOnVolatileState` is set.** A client supplying only `ExpectedEpoch` gets no fencing and no error (INV-008 exposure). Fence whenever `ExpectedEpoch != 0`.
- [x] **M3 — no tenant authorization anywhere.** `PrincipalID` is self-asserted; any caller knowing a `sandbox_id` can exec/read/terminate cross-tenant. Chaos "isolation" assertions only check attribution. Document as a declared simulation gap or enforce (INV-028, DESIGN §6.1).
- [x] **M4 — `network/network.go:39` — metadata deny-list bypassable.** Case variants, trailing-dot FQDN, `kubernetes.default.svc.cluster.local`, and alternate IP encodings (decimal/hex/IPv6-mapped) bypass `AlwaysDenied`. Test only probes two exact strings.
- [x] **M5 — `credential-broker/broker.go:41,67` — revocation memory-only; sequential token IDs.** Broker restart silently un-revokes live tokens; `tok-%d` IDs collide across broker instances sharing an HMAC key.
- [x] **M6 — `filestore.go:62,46` — corrupt journal/snapshot handling.** A corrupt line mid-journal silently drops it and everything after (only the final line may be torn); corrupt `snapshot.json` bricks the store with no fallback/quarantine.
- [x] **M7 — `manager.go:1659` — wall-deadline suspend leaks incarnation record.** Never sets `IncarnationTerminated`, never clears `RuntimeIncarnationID` (miscounts quota after restart), skips endpoint-binding suspension (INV-017).
- [x] **M8 — `manager.go:1064` — idempotent commit replay doesn't persist corrected generation.** Durable sandbox generation regresses vs workspace head after another restart.
- [x] **M9 — `manager.go:334` — restart reconciler fails genuinely-running executions.** Executions without stored outcome marked FAILED even when the backend incarnation verifies alive; their later workspace writes get misattributed.
- [x] **M10 — `runtime/host-agent/fleet.go:367` — `Fleet.Capabilities()` over-declares** (VM class, restore=true) while `Fleet.Restore` returns `ErrUnsupported`; zero hosts → full VM-class reported.
- [x] **M11 — `runtime/local-backend/local.go:406` — `WaitExecution` fabricates `ExitCode: 0` for unknown IDs** instead of `ErrNotFound` (fake backend does this correctly).
- [x] **M12 — `runtime/local-backend/supervisor.go:91` — exec entry leaked on `cmd.Start` failure** → `Wait` hangs forever; execution ID permanently consumed.
- [x] **M13 — `runtime/local-backend/local.go:376` — data race on `inc.dirty`** (write outside lock); also a commit-ordering gap: `MarkCommitted` can run between workspace write and `dirty=true`, claiming durability for an uncommitted write (INV-006).
- [x] **M14 — `runtime/host-agent/hostagent.go:481` — `View()` reads artifact cache without its lock** → race with concurrent creates ("concurrent map iteration and map write").
- [x] **M15 — `runtime/host-agent/fleet.go:227` — terminate on lost host orphans incarnation.** Re-registered host runs unroutable, unaccounted compute (INV-016); fleet believes it gone.
- [x] **M16 — backend drift (INV-026).** Local accepts `Exec` while paused, fake rejects; `fake.Snapshot` doesn't require paused, local does.
- [x] **M17 — `chaos/chaos.go:306` — kill path can't catch false continuity.** No assertion that runtime kill ⇒ epoch increment + reset event (the INV-008 failure mode the harness exists to catch). Suspend path has it; kill path doesn't.
- [x] **M18 — `environment-builder/builder.go:43,88,484` — builder identity/traversal/retired-read issues.** `SpecDigest` newline-concatenation collisions; `filepath.Clean` doesn't stop `../` in repo refs; `ArtifactManifest` rejects RETIRED envs though they must be bootable (INV-021).
- [x] **M19 — egress "enforcement" is declaration-only.** `Operation.EgressDestination` is caller-volunteered; real commands' network access is unchecked on the local backend. Needs an explicit named gap test (isolation tests set the precedent).

## Low severity

- [ ] **L1 — PID-reuse window** in `TerminateBackground`/`killProcesses`/`Restore` kill paths (no marker re-check immediately before SIGKILL).
- [ ] **L2 — `supervisor.go:190` — negative `maxBytes` panics** `ReadOutput`; `f.Stat()` error ignored.
- [ ] **L3 — `supervisor.go:74` — per-exec env can't override ambient env** (append order; shadows broker-injected credentials).
- [ ] **L4 — `control-plane/scheduler/scheduler.go:58,66` — NaN score with zero-capacity hosts; placement fences memory-only** (rejected as stale after control-plane rebuild against warm hosts); fences map grows unbounded.
- [ ] **L5 — `network/network.go:184,112` — gateway fail-open when clock unset; audit writes drop errors** (audit-durability gap for an audit component); audit memory grows unbounded.
- [ ] **L6 — `chaos/chaos.go:250,507` — error classification by substring; `opCacheLoss` returns inside first loop iteration** (dead loop / single coverage).
- [ ] **L7 — `hostagent.go:180` — adopted-incarnation fence gap**: replayed pre-restart Create can create a second incarnation for one sandbox.
- [ ] **L8 — `domain/domain.go:39` — `itoa(math.MinInt64)` returns `"-0"`**; `IDGen`/`ManualClock` not goroutine-safe (currently serialized — undocumented assumption).
- [ ] **L9 — `api/api.go:19` — `Priority`/`Class` never validated** (`"Interactive"` typo silently becomes preemptible background).
- [ ] **L10 — `manager.go:516,631,824,1130` — preemption event emitted before victim suspend succeeds; `deny` ignores flushTx error; idempotency-hit nil-deref risk; `CancelExecution` assumes sandbox exists.**
- [ ] **L11 — `integration/llm.go:113` — stale `agent-last-output.txt` misattributed to non-shell observations**; `integration/adapters.go:48` silent empty read for missing files; `Coordinator.SandboxFor` shared flag describes cache-hit, not policy.
- [ ] **L12 — `workspace/durable.go:78,111,206,294` — no dir fsync on rename-publish; all read errors collapsed to `ErrNotFound`; non-NotExist `os.Stat` error silently skipped; `Unpin` never validates generation.**
- [ ] **L13 — `environment-builder/builder.go:189,265` — `Open` loses `installRuns` and FAILED records; reuse path activates artifact without digest verification.**

## Overall assessment

Architecture and contract discipline are strong: outbox atomicity, epoch fencing, idempotency, and chaos property assertions are genuinely sound. The pattern in the findings: happy-path semantics are well tested, but failure-adjacent paths (restart persistence, concurrent entry, GC across shared pools, mid-file corruption) have real defects, plus one agent-reachable path traversal (H7) and the missing authZ layer (M3).

## Fix order (proposed)

1. H7, H8 — security / incarnation uniqueness
2. H1, H9, H4, H6 — durability / data corruption
3. H3, H5 — audit correctness
4. Medium batch M1–M19
5. Low batch as touched
