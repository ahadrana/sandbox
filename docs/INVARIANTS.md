# Agent Sandbox Platform — Architectural Invariants

**Version:** 0.1  
**Date:** 2026-09-13

These are hard system properties. Every design and implementation decision must be checked against them.

## Terminology

- **Agent task:** durable logical work owned by an external agent/orchestrator.
- **Logical sandbox:** durable sandbox identity/state associated with an execution-capable task.
- **Runtime incarnation:** a physical container/microVM materializing a logical sandbox.
- **Workspace generation:** a committed durable filesystem state.
- **Execution epoch:** monotonically increasing identity for the validity of volatile runtime state.
- **Execution:** an addressable bounded operation inside a sandbox.
- **Work lease:** the resource/budget authority under which sandbox computation runs.

---

## INV-001 — Logical sandbox state follows the task; physical compute does not

A task that needs execution capability owns or references a logical sandbox for the relevant lifetime. The microVM/container that materializes it may be created, suspended, destroyed, or replaced.

**Therefore:** `sandbox_id` is not a pod name, VM process ID, or node identity.

**Test:** kill the runtime, rematerialize on another host, and continue using the same `sandbox_id`.

---

## INV-002 — Agent activation does not imply sandbox materialization

An event, user message, timer, subagent completion, or LLM turn may wake an agent without allocating execution compute.

A physical sandbox is materialized only when executable work or execution locality justifies it.

**Test:** drive 100k sleeping/logically-active tasks while maintaining zero live runtime incarnations.

---

## INV-003 — Agent runtime and sandbox runtime are separate systems

Prompts, LLM dispatch, model-provider policy, context management, prompt caching, reasoning, and product-specific orchestration do not belong in the sandbox control plane.

The sandbox consumes model-independent execution requests and emits model-independent events.

**Test:** run the same conformance workload through a deterministic driver without any LLM.

---

## INV-004 — A sandbox may span many LLM turns

A logical or physical sandbox is not scoped to one inference call. Background builds, local services, or useful warmed state may remain available while multiple LLM turns and user messages occur.

**Test:** run foreground command → simulate LLM turn → background process continues → new command uses same runtime.

---

## INV-005 — Committed workspace state is durable and independent of compute

Committed workspace generations survive runtime destruction, pod loss, node loss, eviction, and rematerialization.

Node-local disks may cache workspace content but are not authoritative.

**Test:** commit generation G17, destroy the entire execution node, restore elsewhere, verify byte-equivalent G17.

---

## INV-006 — Workspace durability has explicit commit boundaries

The system must distinguish **committed** workspace generations from **in-flight** filesystem mutations.

At minimum, successful execution completion and explicit checkpoint/commit operations must be able to establish a durable generation. Stronger continuously durable workspace modes may be added.

If catastrophic failure loses uncommitted writes, that loss must be explicit in recovery metadata; the system must never silently claim those writes survived.

**Test:** kill a host during an in-flight write and verify recovery reports the last committed generation and any rollback/reset condition.

---

## INV-007 — Volatile execution state has an epoch

Processes, RAM, local listeners, shell sessions, and similar live state are valid only within an execution epoch.

Any event that destroys or invalidates that state increments the epoch.

**Test:** restart from workspace-only state and verify epoch N becomes N+1.

---

## INV-008 — Loss of volatile state is never invisible to the agent runtime

If execution state referenced by the agent may have been lost, the sandbox control plane emits `ExecutionStateReset` (or equivalent) before accepting/observing state-dependent continuation as though nothing happened.

**Rationale:** the LLM must not believe a server/test process still exists when it does not.

**Test:** start server, destroy runtime, restore workspace-only, verify a reset event reports lost process/listener state.

---

## INV-009 — Execution snapshots preserve continuity but are never the sole source of truth

A Firecracker-style VM checkpoint may preserve processes/RAM/listeners and avoid an epoch change when validly restored.

However, correctness must remain recoverable from committed durable workspace + agent state even when execution checkpoint restoration is impossible.

**Test:** delete the optional VM snapshot and verify recovery still proceeds with an explicit epoch reset.

---

## INV-010 — Every execution is independently addressable

An execution has a stable ID, lifecycle state, owner, timestamps, output references, and resource accounting.

Execution identity survives client disconnects and control-plane retries.

**Test:** disconnect after launch, reconnect, query the same execution and retrieve its terminal result.

---

## INV-011 — Execution creation is retry-safe

A lost ACK or client retry may not accidentally launch duplicate work when the caller supplies the same idempotency/execution key.

**Test:** send the same launch request repeatedly during injected transport failures and observe exactly one logical execution.

---

## INV-012 — Command completion is not sandbox quiescence

A shell command may return after spawning background descendants. The sandbox is not idle merely because the initiating `exec` has completed.

**Test:** `sleep 30 &` returns, but sandbox remains background-active and resource-owned until the child exits or is killed.

---

## INV-013 — All computation is transitively owned by a work lease

Processes created through `&`, `fork`, `setsid`, daemonization, process supervisors, or arbitrary child processes remain attributable to the sandbox/task lease.

The accounting/enforcement boundary is the sandbox/cgroup/VM, not cooperative use of an async API.

**Test:** double-fork a CPU burner and verify CPU, memory, and termination policy still apply.

---

## INV-014 — Explicit async APIs are coordination mechanisms, not accounting mechanisms

`watch`, `stream`, `cancel`, and execution handles make asynchronous work observable. Correct resource ownership does not depend on the agent using them.

**Test:** compare API-launched async process and Bash-backgrounded process; both are metered and bounded.

---

## INV-015 — Background compute is allowed but bounded

Builds, tests, databases, watchers, and dev servers may continue while the LLM/user is idle, but only under finite CPU, memory, wall-time, storage, and process budgets.

The platform does not promise arbitrary service uptime.

**Test:** abandoned background service crosses policy deadline and is throttled/terminated with an event.

---

## INV-016 — CPU consumption must be attributable

There is no unowned compute. Every CPU cycle executed by a sandbox belongs to a tenant/task/lease for accounting and quota purposes.

**Test:** sum host-level sandbox cgroup CPU and tenant metering within defined measurement tolerance.

---

## INV-017 — Temporary service exposure is a control-plane binding

A sandbox may listen locally, but external/preview access is provided only through a temporary, policy-controlled logical-name → sandbox/port binding.

The binding is not a durable hosting SLA.

**Test:** suspend or terminate runtime and verify the route becomes unavailable or explicitly transitions to a suspended state.

---

## INV-018 — Network and credentials are capabilities, not ambient privileges

Network reachability and credentials are explicit, scoped, auditable, and revocable. Agent code cannot obtain Kubernetes/control-plane credentials simply because it runs in the execution fleet.

**Test:** attempt metadata/Kubernetes API/other-tenant access from arbitrary code and verify denial.

---

## INV-019 — Kubernetes is fleet infrastructure, not the agent API

External callers deal with logical objects such as Sandbox, Workspace, Environment, Execution, Lease, and EndpointBinding.

Kubernetes Pod/Job/Node/PVC identities never become part of the correctness contract.

**Test:** replace/remap all Kubernetes objects underneath an existing logical sandbox without changing its external identity.

---

## INV-020 — Kubernetes is not on the hot path of each tool call

Once a runtime exists, `exec`, file access, status, stdin/stdout, and process operations use a resident supervisor/data channel.

**Test:** execute thousands of small shell operations without creating thousands of Kubernetes objects or invoking scheduling each time.

---

## INV-021 — Prepared environments are immutable, versioned inputs

A prepared environment records enough identity to reproduce what an agent booted from: runtime image/base, environment version, repository SHAs, and preparation result.

A failed new build must not silently replace the last known-good environment.

**Test:** failed environment build leaves prior active environment selectable and bootable.

---

## INV-022 — Shared immutable state is deduplicated; mutable task state is isolated

Base images, prepared environments, repository objects, and caches should be shared where safe. Task-specific writable state must not leak between tenants or logical sandboxes.

**Test:** two sandboxes reuse the same prepared base while writes remain mutually invisible.

---

## INV-023 — Node locality is an optimization, never a correctness dependency

Scheduling may prefer cached environments/workspaces/checkpoints. Recovery must work when all local cache state disappears.

**Test:** force rematerialization on a cold node with no relevant cache.

---

## INV-024 — Failure and preemption are normal paths

Process, supervisor, runtime, pod, node, and network failures are expected operational events. Reconciliation/recovery is not an exceptional manual repair path.

**Test:** continuous chaos injection while conformance workflows complete or fail with explicit, contract-valid terminal states.

---

## INV-025 — Control events and bulk data use different paths

Execution state transitions are small durable control events. Large stdout/stderr/artifacts/files must not be placed directly on the orchestration event bus.

**Test:** generate multi-GB output without destabilizing the control-plane event stream.

---

## INV-026 — Runtime implementation is substitutable

The public API cannot depend on Firecracker-specific concepts. A local/container backend must be able to satisfy the same functional contract for development/testing, while a stronger production backend can implement the same interface.

**Test:** run the conformance suite against at least two runtime adapters.

---

## INV-027 — Security isolation is stronger than Kubernetes namespace isolation

Arbitrary repository code is untrusted. Production multi-tenant execution requires a VM/strong-sandbox-class boundary and host hardening appropriate for hostile code.

**Test:** dedicated breakout/security suite is part of release qualification.

---

## INV-028 — Multiple clients may attach to one logical sandbox without changing ownership semantics

Parent agents, subagents, user steering, or product control planes may issue operations against the same logical sandbox. Every request is authenticated/tagged to a principal and task.

Concurrent execution is allowed only under explicit runtime policy; the system must not invent filesystem transaction isolation that does not exist.

**Test:** two clients issue concurrent commands; ownership, output routing, cancellation, and metering remain unambiguous.

---

## INV-029 — A large logical-agent population must not require a matching live-sandbox population

The architecture must support many more durable logical tasks/sandboxes than concurrently materialized runtimes.

**Test:** control plane stores/reconciles a large dormant population while execution fleet scales only with runnable work.

---

## INV-030 — Events are model-independent

Sandbox events describe execution reality, not prompt instructions. The agent runtime decides whether/how an event becomes context or triggers inference.

**Test:** deterministic driver and LLM-backed driver consume the same event schema.

---

# Review rule

Any proposed optimization that weakens INV-005 through INV-016 or makes state loss silent requires an explicit architecture review. These invariants define the correctness boundary between the model's logical world and execution reality.
