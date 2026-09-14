# Agent Sandbox Platform — High-Level Design

**Version:** 0.1  
**Date:** 2026-09-13  
**Status:** Proposed implementation architecture

## 1. Design thesis

Build a **durable logical sandbox service over disposable isolated compute**.

The system preserves the model-visible execution world through two mechanisms:

1. **durable committed workspace generations**, and
2. an **execution epoch** that explicitly invalidates lost volatile state.

Full VM checkpointing is an optional stronger continuity path; it is not required for correctness.

The platform sits below agent runtimes:

```text
Agent runtime / task orchestrator
  - prompts / context / LLM
  - event-driven wakeups
  - parent/subagent reasoning
  - product/A2A semantics
             |
             | model-independent execution RPC + events
             v
Sandbox control plane
             |
             v
Kubernetes-hosted execution fleet
```

## 2. Design goals

1. Make execution state cheap enough to allocate on demand.
2. Preserve logical sandbox continuity across physical runtime loss.
3. Correctly support arbitrary background processes, not only cooperative async jobs.
4. Keep Kubernetes out of the per-tool-call hot path.
5. Provide a strong hostile-code isolation path.
6. Exploit prepared environments and cache locality aggressively.
7. Make state loss explicit to the agent runtime.
8. Keep the API useful to Cursor-like, Atlassian-like, and custom agent runtimes.
9. Build deterministic conformance/chaos testing before production optimization.

## 3. Logical data model

### 3.1 Tenant

```text
Tenant {
  tenant_id
  policy_id
  quota_id
}
```

### 3.2 Environment

Immutable/versioned prepared execution base.

```text
Environment {
  environment_id
  version
  status: BUILDING | ACTIVE | FAILED | RETIRED
  base_runtime_ref
  repo_inputs[]        // optional repo + SHA
  config_digest
  image/disk_artifact_refs[]
  created_at
  integrity_digest
}
```

A successful Environment may become the active default; failure never implicitly replaces the prior active environment.

### 3.3 Workspace

Durable mutable task state represented as committed generations.

```text
Workspace {
  workspace_id
  tenant_id
  base_environment_id
  head_generation
}

WorkspaceGeneration {
  workspace_id
  generation
  parent_generation?
  manifest_ref
  integrity_digest
  committed_at
  cause_execution_id?
}
```

The exact physical representation (block snapshot, CAS/tree manifest, overlay delta, etc.) is an implementation detail behind `WorkspaceStore`.

### 3.4 Logical Sandbox

```text
Sandbox {
  sandbox_id
  tenant_id
  task_ref
  environment_id
  workspace_id
  desired_state
  observed_state
  execution_epoch
  workspace_generation
  policy_ref
  lease_ref?
  runtime_incarnation_id?
  checkpoint_ref?
  version             // optimistic concurrency/fencing
}
```

### 3.5 Runtime Incarnation

```text
RuntimeIncarnation {
  incarnation_id
  sandbox_id
  execution_epoch
  runtime_backend
  host_id
  state
  started_at
  last_heartbeat
  supervisor_endpoint
  runtime_metadata
}
```

Never exposed as the durable identity to agent clients.

### 3.6 Execution

```text
Execution {
  execution_id
  idempotency_key
  tenant_id
  sandbox_id
  principal_id
  execution_epoch
  requested_workspace_generation
  operation
  state
  created_at
  started_at?
  completed_at?
  exit_code?
  terminal_reason?
  stdout_ref?
  stderr_ref?
  generation_before
  generation_after?
  resource_usage
}
```

### 3.7 Lease

```text
Lease {
  lease_id
  tenant_id
  task_ref
  sandbox_id
  cpu_policy
  memory_limit
  wall_deadline
  storage_limit
  process_limit
  network_policy_ref
  priority
  background_policy
}
```

### 3.8 Checkpoint

```text
Checkpoint {
  checkpoint_id
  sandbox_id
  execution_epoch
  workspace_generation
  type: WORKSPACE_ONLY | EXECUTION_STATE
  runtime_backend
  compatibility_metadata
  artifacts[]
  created_at
}
```

### 3.9 EndpointBinding

```text
EndpointBinding {
  binding_id
  tenant_id
  sandbox_id
  execution_epoch
  target_port
  logical_name
  auth_policy
  expires_at
  state
}
```

## 4. State machines

### 4.1 Sandbox lifecycle

```text
UNMATERIALIZED
     |
     v
  STARTING --------------------+
     |                          |
     v                          |
  RUNNING <---- RESUMING       |
   |   \                        |
   |    \ descendants alive    |
   |     v                      |
   | BACKGROUND_ACTIVE          |
   |      |                     |
   +----> QUIESCENT             |
             |                  |
             v                  |
         SUSPENDING             |
             |                  |
             v                  |
         SUSPENDED -------------+

Any state -> FAILED -> reconcile to SUSPENDED/UNMATERIALIZED/TERMINATED
```

`QUIESCENT` is a policy judgment, not merely “last exec returned.”

### 4.2 Execution lifecycle

```text
PENDING -> DISPATCHED -> RUNNING -> COMPLETED
                          |  |  \
                          |  |   -> FAILED
                          |  -> TIMED_OUT
                          -> CANCELLED
```

An execution can finish while the sandbox remains `BACKGROUND_ACTIVE` because descendant processes continue.

## 5. Execution epoch protocol

The execution epoch is the fencing token for volatile runtime assumptions.

### Normal continuation

```text
Sandbox epoch 41
  - postgres running
  - server :3000 running
  - test process running

subsequent execution expected_epoch=41 -> accepted
```

### Workspace-only reconstruction

```text
runtime dies
restore workspace generation G72
new runtime
execution_epoch: 41 -> 42
emit ExecutionStateReset {
  prior_epoch: 41,
  new_epoch: 42,
  workspace_generation: G72,
  lost_classes: [PROCESS, MEMORY, LISTENER, SHELL_SESSION]
}
```

A caller using `expected_epoch=41` receives an epoch conflict/reset descriptor rather than silently executing as if the old process world existed.

### Full execution-checkpoint restoration

If runtime backend proves compatible restore and the control plane declares continuity:

```text
checkpoint(epoch=41) -> restore -> epoch remains 41
```

If restore is uncertain, increment the epoch. Prefer false reset over false continuity.

## 6. Functional components

### 6.1 API Gateway / AuthN/AuthZ

Responsibilities:

- authenticate callers;
- map caller to tenant/principal;
- authorize sandbox/environment/workspace/endpoint operations;
- idempotency header/key handling;
- request admission and coarse rate limiting.

Must remain stateless/horizontally scalable.

### 6.2 Sandbox Manager / Reconciler

Authoritative logical lifecycle controller.

Responsibilities:

- create/update Sandbox desired state;
- maintain state version/fencing;
- request placement/materialization;
- reconcile lost incarnations;
- coordinate suspend/resume;
- increment execution epochs when required;
- emit durable lifecycle events through transactional outbox;
- ensure one authoritative active incarnation unless policy explicitly permits otherwise.

Persistence baseline: relational DB (e.g., PostgreSQL) for metadata/transactions is a reasonable initial implementation.

### 6.3 Scheduler

Schedules **runtime incarnations**, not individual shell commands.

Inputs:

- compatible runtime backend/CPU model;
- memory hard requirement;
- CPU policy/burst need;
- priority/tenant fairness;
- environment cache locality;
- workspace cache locality;
- checkpoint locality/compatibility;
- host health/pressure;
- background vs interactive class.

Output:

```text
Placement {
  sandbox_id
  host_id
  placement_generation/fence
}
```

Kubernetes can provision/manage execution-host capacity, but the sandbox scheduler owns sandbox-level placement policy.

### 6.4 Workspace Service

Interface:

```text
Materialize(workspace_id, generation, host)
Commit(workspace_id, base_generation, source_overlay) -> new_generation
GetHead(workspace_id)
ReadManifest(generation)
Pin/Unpin(generation)
GC()
```

Required semantics:

- immutable committed generations;
- integrity verification;
- optimistic parent-generation checks;
- recovery on cold node;
- shared immutable base, private writable overlay;
- explicit reporting of uncommitted-write loss on catastrophic failure.

Do not lock the design to a particular CAS/block implementation in v0.1.

### 6.5 Environment Build Service

Modeled after the useful semantics of Cursor Builds:

1. start from base runtime/image;
2. clone/checkout configured repositories;
3. run bounded idempotent install/preparation command;
4. produce bootable immutable artifact;
5. record exact repo SHAs/config digest/logs;
6. mark successful artifact active;
7. leave old active artifact intact when new build fails.

Separate **install/build** from **per-session startup**. Databases, tunnels, dev servers, and tmux/session terminals start after sandbox materialization, not inside the immutable environment artifact.

### 6.6 Runtime Host Agent

Runs on dedicated Kubernetes execution nodes. Production candidate: a privileged, tightly hardened per-node service with `/dev/kvm` access that manages many isolated microVMs.

Responsibilities:

- receive fenced materialization requests;
- prepare local cached environment/workspace artifacts;
- create/destroy/pause runtime backend;
- establish host networking;
- enforce host cgroup/lease limits around the runtime;
- proxy/control the guest supervisor channel;
- heartbeat incarnation state;
- create/load backend checkpoints;
- scrub local state after termination.

**Important:** do not require one Kubernetes Job per shell operation. It is acceptable for Kubernetes to represent execution-host agents rather than every individual microVM if that provides better density/control-plane scale.

### 6.7 Runtime Backend Interface

```text
trait RuntimeBackend {
  create(spec) -> RuntimeHandle
  start(handle)
  pause(handle)
  resume(handle)
  snapshot(handle) -> BackendCheckpoint
  restore(checkpoint) -> RuntimeHandle
  terminate(handle)
  stats(handle) -> RuntimeStats
}
```

Required implementations:

1. **Local/dev backend** — process/container based, fast for tests.
2. **Production strong-isolation backend** — Firecracker is the primary candidate, but the interface must not expose Firecracker concepts.

Firecracker facts relevant to implementation:

- one Firecracker process represents one microVM;
- host networking is typically TAP-backed;
- API supports snapshot create/load;
- snapshot restore can lazily page guest memory;
- production deployment requires host/jailer hardening and compatible restore constraints.

### 6.8 Guest Supervisor

Small service inside the sandbox runtime. This is the hot-path data-plane endpoint.

Responsibilities:

- launch foreground/async processes;
- allocate process groups/session metadata;
- stream stdin/stdout/stderr;
- status/cancel execution;
- file operations where needed;
- report process inventory/quiescence hints;
- local-port/listener discovery where supported;
- health/heartbeat;
- enforce guest-local policy in addition to outer enforcement.

The supervisor MUST NOT be trusted as the only resource/security enforcement layer; arbitrary sandbox code is hostile.

Suggested transport: multiplexed gRPC/HTTP2 or similarly low-latency bidirectional protocol over vsock or an authenticated private channel.

### 6.9 Execution Service

Control-plane façade for execution objects.

Launch path:

```text
client -> CreateExecution(idempotency_key, sandbox, expected_epoch)
       -> ensure sandbox materialized
       -> persist execution PENDING
       -> dispatch to supervisor
       -> persist RUNNING
       -> return handle (or wait in foreground mode)
```

Completion path:

```text
supervisor exit/status
  -> execution terminal state
  -> capture output refs/resource data
  -> optionally commit workspace generation
  -> emit durable terminal event
  -> recompute sandbox quiescence/background-active state
```

### 6.10 Event Service / Transactional Outbox

All durable control-plane state changes that require an external event must be written transactionally with an outbox record.

At-least-once delivery is acceptable. Events therefore carry:

- event_id;
- aggregate ID;
- aggregate version;
- event type;
- timestamp;
- tenant/task identity;
- payload schema version.

Agent runtimes subscribe/consume through queue/webhook/stream adapters above this service.

Do not place bulk stdout/stderr on this bus.

### 6.11 Output/Artifact Store

Provide:

- streaming tail while execution runs;
- durable final stdout/stderr references;
- bounded retention;
- large artifact upload/download;
- integrity metadata.

Implementation may use object storage plus streaming service.

### 6.12 Network/Egress Controller

Responsibilities:

- outer egress enforcement independent of guest code;
- DNS policy;
- tenant/private-network routing;
- traffic accounting;
- prevention of host/K8s metadata access.

Use a policy object referenced by the work lease.

### 6.13 Temporary Endpoint Gateway

Creates authenticated temporary name/URL -> sandbox incarnation/port mappings.

Binding must include epoch. A stale binding from epoch 41 must never silently route to epoch 42 unless explicitly rebound.

No general hosting SLA.

### 6.14 Credential Broker

Issues/injects short-lived, task-scoped credentials or proxies signed operations.

Properties:

- no long-lived Kubernetes/cloud node credentials in guest;
- audit issuance and usage where possible;
- revocation/expiry;
- keep secret values out of control event/log paths.

### 6.15 Metering Service

Collect from host/runtime/supervisor sources:

- CPU seconds;
- memory usage/integral;
- storage and workspace growth;
- network bytes;
- process count;
- runtime live time;
- checkpoint bytes/I/O;
- startup/resume/exec latency.

Resource accounting must use outer authoritative boundaries (host cgroup/VM) rather than process self-report alone.

### 6.16 Garbage Collector

Reference-aware cleanup of:

- terminated runtimes;
- expired endpoint bindings;
- output blobs;
- old workspace generations;
- unused environment builds;
- checkpoints;
- node-local cache.

GC uses pins/retention roots so debugging/audit references are not broken.

## 7. Kubernetes topology

Recommended production shape:

```text
Kubernetes cluster

Control-plane node pools
  - API
  - sandbox manager/reconcilers
  - scheduler
  - environment/workspace control services
  - events/metering

Dedicated execution node pools
  - hardened Linux + KVM
  - Runtime Host DaemonSet/service
  - local NVMe cache
  - no application/control-plane secrets
  - tightly restricted Kubernetes identity

Runtime Host
  +-- microVM S1
  +-- microVM S2
  +-- microVM S3
  +-- ...
```

This avoids making the Kubernetes API server the per-agent tool-call scheduler and allows denser VM management.

Kubernetes remains responsible for execution-host capacity, health, rolling upgrades, autoscaling, and failure domains.

## 8. Workspace/storage design direction

Do not prematurely commit to one implementation, but preserve these layers:

```text
Environment immutable base
       |
Workspace committed generation G
       |
node-local materialization/cache
       |
private writable overlay for live incarnation
```

Candidate implementations can be benchmarked behind the same interface:

- block-device snapshots;
- object/CAS tree manifests + local overlay;
- filesystem snapshot technology;
- network/block-backed volumes;
- hybrid local overlay + journal/commit.

The benchmark must measure:

- materialization latency;
- commit latency;
- random metadata-heavy coding workload;
- Git operations;
- dependency trees/node_modules;
- node-loss recovery;
- storage amplification;
- dedup ratio;
- cost.

## 9. Process/background semantics

The host/VM boundary is authoritative for ownership.

Inside a runtime:

```text
shell
  +-- foreground process
  +-- foo &
       +-- fork
            +-- setsid/daemon
```

All remain inside the same VM/cgroup lease.

The supervisor may track explicit executions/process groups for convenience, but sandbox state must also inspect/account for residual descendants.

Quiescence policy may use:

- active supervisor executions;
- guest process inventory;
- CPU activity;
- known baseline service processes;
- endpoint bindings;
- startup service policy;
- grace periods.

Do not equate zero active API executions with idle.

## 10. Suspend/resume policy

### Workspace-only suspend

1. stop accepting new execution;
2. reach/cancel policy-defined safe point;
3. commit workspace generation;
4. record process/listener inventory as lost-on-resume metadata;
5. terminate runtime;
6. release RAM/CPU;
7. on resume rematerialize environment + workspace;
8. increment epoch;
9. run configured startup commands/services;
10. emit `ExecutionStateReset` + `SandboxResumed`.

### Execution-state checkpoint suspend

1. quiesce host/device operations as required;
2. commit/synchronize workspace state associated with checkpoint;
3. pause runtime;
4. create runtime checkpoint;
5. release runtime resources;
6. on restore verify backend/CPU/device compatibility;
7. restore checkpoint;
8. retain epoch only if continuity is guaranteed;
9. otherwise fall back to workspace-only recovery with epoch increment.

Policy engine decides which path is economical/correct.

## 11. Temporary service bridge

```text
client/browser
      |
      v
Endpoint Gateway
  - auth
  - tenant policy
  - binding TTL
  - sandbox_id + epoch
      |
private tunnel/route
      |
runtime incarnation : port
```

The gateway must fail closed when runtime/epoch binding is stale.

## 12. Agent integration contract

The sandbox does not speak A2A as its core protocol.

Expected layering:

```text
Jira/Rovo --A2A--> Agent Runtime --Sandbox API--> Sandbox Platform
Cursor-like coordinator ----------^ 
```

Core client operations should be sufficient to implement:

```text
CreateSandbox
GetSandbox
EnsureRunning / Suspend / Resume / Terminate
CreateExecution
GetExecution
StreamExecutionOutput
CancelExecution
CommitWorkspace
CreateEndpointBinding
DeleteEndpointBinding
SubscribeEvents
```

## 13. Reference Agent Driver / Conformance Harness

A first-class repository component, not throwaway test code.

### Driver model

```text
Task
  +-- event inbox
  +-- agent state machine
  +-- sandbox binding
  +-- child task/subagent handles
```

Initially deterministic. Later optional LLM adapters.

### Must simulate

- event-driven task wakeup;
- repeated turns;
- steering events at tool boundaries;
- background work across turns;
- parent/subagent fan-out;
- shared sandbox access;
- cancellation;
- runtime loss;
- stale epoch;
- failed/duplicate event delivery.

### Fault injection hooks

At controlled points:

- drop client response;
- kill guest supervisor;
- kill runtime;
- kill runtime host pod/process;
- kill K8s node (integration environment);
- disconnect event consumer;
- reorder/duplicate allowed events;
- fill workspace/storage quota;
- force OOM;
- fork bomb;
- invalidate checkpoint;
- clear node cache.

The harness is the executable specification of the sandbox contract.

## 14. Testing requirements by component

### Sandbox Manager

- deterministic state-machine unit tests;
- property tests for illegal transitions/fencing;
- DB transaction/outbox atomicity tests;
- crash/restart reconciliation tests.

### Workspace Service

- generation integrity tests;
- concurrent parent-generation conflict tests;
- node-loss/cold-rematerialization tests;
- large repo/dependency-tree benchmarks;
- corruption detection tests.

### Environment Builder

- reproducibility/identity tests;
- failed-build fallback tests;
- exact repo SHA capture;
- idempotent install replay tests.

### Runtime Host/Backend

- create/destroy leak tests;
- isolation tests;
- host crash behavior;
- resource enforcement tests;
- snapshot compatibility/fallback tests;
- high-density start/stop stress.

### Guest Supervisor/Execution

- foreground/async execution;
- streaming backpressure;
- disconnect/reconnect;
- cancellation;
- background descendants;
- fork/setsid/daemon behavior;
- concurrent clients.

### Networking

- egress allow/deny;
- metadata/K8s API denial;
- temporary endpoint TTL;
- epoch-stale route invalidation;
- bandwidth accounting.

### Events

- at-least-once duplicates;
- consumer outage/replay;
- ordering/versioning;
- terminal-event durability.

### Security

- threat-model-driven breakout suite;
- cross-tenant filesystem/network/process isolation;
- secret leakage/log redaction tests;
- host/K8s credential absence;
- image/runtime provenance checks.

### Scale

Benchmark separately:

- logical sandbox count;
- live runtime count;
- exec QPS;
- runtime starts/sec;
- workspace commits/sec;
- event throughput;
- control-plane DB/reconciler lag;
- host density and memory pressure.

## 15. Open design decisions to benchmark, not debate indefinitely

1. Firecracker vs Kata/gVisor for production isolation.
2. One microVM per Runtime Host vs Kubernetes pod-per-microVM integration.
3. Workspace backing: block snapshots vs CAS/tree vs hybrid.
4. Supervisor transport: vsock gRPC vs private network transport.
5. Event backend: queue/log technology.
6. Checkpoint policy/economics.
7. Memory overcommit/reclamation strategy.
8. Host cache eviction policy.

Each decision gets an ADR after conformance + workload benchmarks, not before.
