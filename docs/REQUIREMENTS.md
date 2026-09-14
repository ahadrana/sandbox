# Agent Sandbox Platform — Requirements

**Version:** 0.1  
**Date:** 2026-09-13  
**Normative terms:** MUST, SHOULD, MAY follow RFC-style meaning.

## 1. Objective

Build a scalable, multi-tenant execution fabric on Kubernetes for AI agent runtimes. It must support coding-agent-class workloads and general agent tool execution while keeping logical agent lifetime independent from continuous CPU/RAM allocation.

The system must be compatible with usage patterns demonstrated by modern agent platforms:

- event-driven wakeup and long-lived goals;
- prepared development environments;
- foreground/background execution;
- multiple LLM turns against one execution environment;
- subagents on separate runtimes;
- optional shared sandbox access;
- temporary local services;
- hibernation/suspend/resume;
- execution on hosted or customer/self-hosted capacity.

## 2. External system boundary

### 2.1 Agent Runtime responsibilities

The Sandbox Platform MUST NOT require ownership of:

- LLM invocation;
- system prompts;
- context windows/history;
- prompt caching;
- LLM-specific async/preemption semantics;
- product task UI;
- Jira/A2A semantics;
- parent/subagent reasoning;
- human conversation.

### 2.2 Sandbox Platform responsibilities

The platform MUST provide:

- sandbox lifecycle;
- prepared environments;
- durable workspace generations;
- isolated compute materialization;
- sync/async process execution;
- process/resource ownership;
- output streaming/storage;
- sandbox events;
- suspend/resume and optional VM checkpointing;
- temporary port/service access;
- network/security policy;
- credentials/identity integration;
- scheduling, quotas, metering, and reclamation.

---

# 3. Functional Requirements

## 3.1 Identity and lifecycle

**FR-LC-001** The system MUST assign a stable `sandbox_id` to each logical sandbox.

**FR-LC-002** A logical sandbox MUST survive replacement of its physical runtime incarnation.

**FR-LC-003** A sandbox MUST expose an explicit lifecycle state at least equivalent to:

```text
UNMATERIALIZED
STARTING
RUNNING
BACKGROUND_ACTIVE
QUIESCENT
SUSPENDING
SUSPENDED
RESUMING
FAILED
TERMINATED
```

**FR-LC-004** Lifecycle transitions MUST be idempotent/retry-safe.

**FR-LC-005** The system MUST reconcile desired versus actual runtime state after control-plane/runtime failures.

**FR-LC-006** The physical runtime MUST be placeable on any compatible execution host; original-node affinity MAY be used only as an optimization.

## 3.2 Execution epochs and state validity

**FR-EP-001** Every logical sandbox MUST have a monotonically increasing `execution_epoch`.

**FR-EP-002** Destructive loss/recreation of volatile process/RAM/listener state MUST increment the epoch unless an execution checkpoint is restored with continuity guarantees.

**FR-EP-003** Epoch changes MUST emit a durable reset event describing what state class was preserved/lost.

**FR-EP-004** Execution requests SHOULD carry the caller's last-seen epoch; stale callers MUST receive a clear conflict/reset response for operations that depend on volatile state.

## 3.3 Workspaces

**FR-WS-001** Each sandbox MUST reference a durable workspace.

**FR-WS-002** The workspace MUST support immutable committed generations.

**FR-WS-003** Committed workspace generations MUST survive node/runtime loss.

**FR-WS-004** Successful execution completion MUST be able to commit a new workspace generation. The API MUST also support explicit workspace commit/checkpoint.

**FR-WS-005** The platform MUST report the restored generation after recovery and MUST surface rollback to an earlier committed generation if uncommitted writes were lost.

**FR-WS-006** Multiple sandboxes SHOULD be able to share immutable base/environment/repository content without sharing writable overlays.

**FR-WS-007** Workspace materialization MUST not require a full copy of all immutable base data for every sandbox.

**FR-WS-008** The workspace abstraction MUST support multi-repository environments.

## 3.4 Prepared environments

**FR-ENV-001** The platform MUST support a versioned Environment artifact containing or referencing:

- base OS/runtime identity;
- installed tools/dependencies;
- repository identities/SHAs when included;
- preparation configuration;
- build logs/status;
- integrity identity/hash/version.

**FR-ENV-002** Environment creation MUST be asynchronous and addressable.

**FR-ENV-003** A failed environment build MUST NOT replace the active last-known-good environment automatically.

**FR-ENV-004** New sandboxes SHOULD boot from prepared environment state rather than re-running expensive setup.

**FR-ENV-005** Environment preparation and per-run startup MUST be distinct phases. Long-lived processes/services belong in startup/session execution, not in immutable environment preparation.

## 3.5 Execution API

**FR-EX-001** The platform MUST create an addressable Execution object for each launched command/operation.

**FR-EX-002** Launch MUST support an idempotency key supplied by the caller.

**FR-EX-003** Executions MUST expose at least:

- ID;
- sandbox/task/tenant ownership;
- requested operation;
- lifecycle state;
- start/end timestamps;
- exit status/reason;
- stdout/stderr references;
- resource usage;
- execution epoch;
- workspace generation before/after when applicable.

**FR-EX-004** The platform MUST support foreground waiting and asynchronous return of an execution handle.

**FR-EX-005** The platform MUST support execution status, cancellation, and output streaming/tailing.

**FR-EX-006** Client disconnect MUST NOT implicitly terminate an execution unless requested by policy.

**FR-EX-007** An execution MUST be cancellable independently of terminating the entire sandbox when isolation semantics permit.

**FR-EX-008** Small exec operations against an existing runtime MUST not require Kubernetes object creation/scheduling.

## 3.6 Arbitrary subprocess/background behavior

**FR-BG-001** Processes created inside the sandbox by fork/background shell/daemonization MUST remain within sandbox resource ownership and isolation.

**FR-BG-002** The platform MUST distinguish command completion from sandbox quiescence.

**FR-BG-003** The platform MUST be able to detect that non-baseline processes remain after the initiating command exits.

**FR-BG-004** Background compute MUST remain subject to task/tenant lease quotas and deadlines.

**FR-BG-005** The platform MUST provide a mechanism for the control plane to terminate all sandbox computation reliably.

**FR-BG-006** The platform SHOULD expose managed process/execution metadata where practical, but correctness MUST NOT depend on cooperative job registration by sandbox code.

## 3.7 Events

**FR-EV-001** The platform MUST publish durable lifecycle/control events.

Minimum event classes:

```text
SandboxMaterialized
SandboxSuspended
SandboxResumed
SandboxFailed
ExecutionStarted
ExecutionCompleted
ExecutionFailed
ExecutionCancelled
ExecutionTimedOut
ExecutionStateReset
WorkspaceCommitted
ResourceLimitApproaching
ResourceLimitExceeded
EndpointBound
EndpointUnbound
```

**FR-EV-002** Events MUST include stable IDs and ordering metadata sufficient for deduplication/reconciliation.

**FR-EV-003** Bulk stdout/stderr/artifacts MUST NOT be embedded directly in normal control events; events MAY reference stream/blob locations.

**FR-EV-004** Consumers MUST be able to resume after disconnect without losing terminal state changes.

**FR-EV-005** The event schema MUST be independent of LLM/model/provider semantics.

## 3.8 Suspend/resume and checkpointing

**FR-SR-001** The platform MUST support reclaiming CPU/RAM from inactive sandboxes.

**FR-SR-002** At minimum, workspace-only suspend/resume MUST be supported.

**FR-SR-003** The runtime interface MUST permit a stronger execution-checkpoint mode that preserves RAM/process state when supported by the backend.

**FR-SR-004** Restore from workspace-only state MUST increment execution epoch and emit reset semantics.

**FR-SR-005** Restore of a valid full execution checkpoint SHOULD retain the same execution epoch when continuity is guaranteed.

**FR-SR-006** Checkpoint policy SHOULD consider memory size, dirty state, active processes, expected idle time, storage bandwidth/cost, and reconstruction cost.

## 3.9 Temporary networking/services

**FR-NET-001** Sandbox processes MAY bind local ports.

**FR-NET-002** External/preview access MUST be created through a control-plane-managed EndpointBinding.

**FR-NET-003** EndpointBinding MUST specify tenant/task/sandbox, target port, authorization policy, and TTL/lifecycle.

**FR-NET-004** The platform MUST make no durable-service SLA for sandbox listeners.

**FR-NET-005** Egress MUST be policy controllable and auditable.

**FR-NET-006** Runtime code MUST NOT be able to bypass host-level/outer network restrictions merely by spawning a different process.

## 3.10 Credentials

**FR-SEC-001** Sandboxes MUST NOT receive Kubernetes/control-plane credentials.

**FR-SEC-002** Application credentials SHOULD be short-lived and scoped to tenant/task/capability.

**FR-SEC-003** The platform MUST support secret injection without requiring secret values to appear in control-plane logs/events.

**FR-SEC-004** Credential issuance/use/revocation MUST be auditable.

## 3.11 Isolation

**FR-ISO-001** Production multi-tenant execution MUST assume sandbox code is hostile.

**FR-ISO-002** Isolation MUST protect other sandboxes, host filesystem, host processes, infrastructure metadata, and the Kubernetes API.

**FR-ISO-003** Production isolation MUST be stronger than ordinary Kubernetes namespaces alone.

**FR-ISO-004** The runtime implementation MUST be replaceable behind a stable interface.

## 3.12 Scheduling and resource leases

**FR-SCH-001** Every materialized sandbox MUST execute under a resource lease.

**FR-SCH-002** Lease policy MUST include hard memory bounds and SHOULD support burstable CPU allocation.

**FR-SCH-003** Scheduling MUST support tenant quota/fairness and priority classes.

**FR-SCH-004** Scheduling SHOULD exploit environment/workspace/cache/checkpoint locality while retaining cold-node correctness.

**FR-SCH-005** Background-only workloads MAY be given different CPU/wall-time policy from interactive foreground work.

**FR-SCH-006** The scheduler MUST not require one Kubernetes pod/job per individual tool call.

## 3.13 Multiple callers/subagents

**FR-MC-001** Multiple authenticated clients MAY attach to one logical sandbox.

**FR-MC-002** Each request/execution/event MUST be attributable to a principal/task/agent identity.

**FR-MC-003** Runtime concurrency policy MUST be explicit: serialize, bounded-concurrent, or reject.

**FR-MC-004** The platform MUST NOT claim transactional filesystem isolation between concurrent callers unless explicitly implemented.

**FR-MC-005** The architecture MUST also support subagents using independent logical sandboxes/runtimes.

## 3.14 Metering and accounting

**FR-MET-001** The platform MUST meter at least CPU time, memory usage over time, runtime wall time, storage usage, network usage, execution duration, and workspace/checkpoint size.

**FR-MET-002** All measured compute MUST be attributable to tenant/task/sandbox/lease.

**FR-MET-003** Metering MUST include background descendants even when they were not explicitly registered as async jobs.

**FR-MET-004** Meter data SHOULD be suitable for capacity planning and eventual billing.

## 3.15 Garbage collection

**FR-GC-001** Terminated/expired sandboxes MUST eventually release physical runtime resources.

**FR-GC-002** Unreferenced checkpoints, workspace generations, environment builds, streams, and artifacts MUST be garbage collectible under retention policy.

**FR-GC-003** GC MUST respect durable references/pins from active tasks, audit policy, and debugging retention.

---

# 4. Non-Functional Requirements

## 4.1 Performance

**NFR-PERF-001** Small command execution on an already-running sandbox SHOULD have control-plane overhead in the millisecond-class rather than provisioning-class latency.

**NFR-PERF-002** Runtime startup and resume latency MUST be continuously measured with p50/p95/p99 metrics.

**NFR-PERF-003** Prepared environments and warm caches SHOULD materially reduce cold-start work compared with clone/install on every task.

**NFR-PERF-004** High-volume stdout/stderr MUST not cause control-plane head-of-line blocking.

## 4.2 Scale

**NFR-SCALE-001** The control plane MUST support a logical sandbox/task population substantially larger than the live runtime population.

**NFR-SCALE-002** Control-plane architecture MUST avoid per-sandbox permanently resident processes for suspended/unmaterialized sandboxes.

**NFR-SCALE-003** The design MUST support horizontal sharding/scaling of stateless API and reconciliation components.

## 4.3 Availability and recovery

**NFR-AV-001** Control-plane process restart MUST not orphan ownership or make running work unobservable.

**NFR-AV-002** Host/node failure MUST converge logical sandbox state to a valid recovered/failed state without manual database editing.

**NFR-AV-003** Event delivery MAY be at-least-once; consumers and state transitions MUST therefore be deduplication-safe.

## 4.4 Security

**NFR-SEC-001** Threat model includes malicious repository code and prompt-injected agent commands.

**NFR-SEC-002** Privileged host runtime components MUST be minimized and isolated to dedicated execution nodes.

**NFR-SEC-003** Security policy violations MUST be observable/auditable.

## 4.5 Operability

**NFR-OPS-001** Every sandbox, runtime incarnation, execution, workspace generation, environment build, checkpoint, and endpoint binding MUST be traceable by stable IDs.

**NFR-OPS-002** Operators MUST be able to inspect desired state, actual state, placement, lease, epoch, last committed workspace generation, and recent failures.

**NFR-OPS-003** Reconciliation loops MUST expose lag/error metrics.

---

# 5. Required Conformance Scenarios

The deterministic reference driver MUST automate these before production runtime optimization:

1. **Basic coding loop:** materialize → edit → test → commit workspace → rematerialize elsewhere → verify.
2. **Multi-turn session:** simulate several LLM turns against one warm runtime.
3. **Bash backgrounding:** `cmd &`; initiating exec exits while descendant continues and is metered.
4. **Daemon escape attempt:** double-fork/setsid remains sandbox-owned.
5. **Async event wake:** background execution completes while agent is dormant; durable event wakes driver.
6. **User steering:** steering event arrives while tool execution is active; harness applies at configured safe boundary.
7. **Subagent separate runtime:** parent delegates independent work to N isolated sandboxes.
8. **Shared sandbox:** two principals attach, execute, and receive correctly attributed results/events.
9. **Temporary service:** listener + EndpointBinding; route disappears or transitions correctly at suspend/termination.
10. **Workspace-only recovery:** kill runtime; restore committed generation; epoch reset emitted.
11. **Full checkpoint recovery:** when backend supports it, restore process/RAM state without semantic reset.
12. **Lost ACK/idempotency:** execution launch response lost; retry does not duplicate.
13. **Host/node loss:** destroy runtime host and recover on a cold node.
14. **Quota enforcement:** CPU/memory/process/fork bomb cannot escape lease.
15. **Large output:** huge stdout/stderr does not overwhelm control eventing.
16. **Dormant scale:** large logical population with small live runtime count.
17. **Prepared environment rollback:** new broken build does not replace last known-good build.
18. **Cold cache correctness:** restore with no node-local environment/workspace/checkpoint cache.

---

# 6. Explicit Non-Goals for Initial Delivery

The initial platform does not need to implement:

- an LLM agent reasoning framework;
- Jira/A2A itself;
- MCP routing itself;
- durable public web hosting;
- transparent survival of arbitrary external TCP connections;
- general-purpose VM hosting;
- live VM migration;
- process-level deterministic replay;
- globally transactional filesystem semantics across concurrent sandboxes;
- multi-region active-active execution.

---

# 7. Reference Compatibility Targets

The API does not need to copy any vendor, but the following workloads must be representable without vendor-specific hacks:

### Cursor-like

- boot from prepared environment/build;
- per-agent isolated runtime;
- long-running/background work;
- subagent on own runtime;
- event/subscription wakeup handled above sandbox;
- idle capacity hibernation/resume;
- local services started for each run;
- restrictive egress/secret policy.

### Atlassian-like

- durable agent/task outlives immediate response turn;
- background subagent completion produces notification/wakeup;
- sandbox allocation only for executable work;
- optional shared sandbox access;
- remote-agent/A2A remains above sandbox boundary;
- durable handle/status semantics.
