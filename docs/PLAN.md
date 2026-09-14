# Agent Sandbox Platform — Implementation Plan

**Version:** 0.1  
**Date:** 2026-09-13

## 1. Execution strategy

Implement correctness contracts before virtualization optimization.

The sequence is deliberately:

```text
Invariants
   -> API/domain model
   -> deterministic agent driver
   -> local runtime backend
   -> workspace generations + events
   -> async/background correctness
   -> Kubernetes runtime-host layer
   -> strong isolation backend
   -> suspend/checkpoint/network/security
   -> scale/chaos
   -> real agent integration
```

Do not start by writing a Firecracker operator or custom scheduler. That risks hiding contract mistakes beneath infrastructure complexity.

## 2. Repository shape

A suggested monorepo structure:

```text
/api/                     protobuf/OpenAPI schemas
/control-plane/
  sandbox-manager/
  execution-service/
  scheduler/
  event-service/
/workspace/
/environment-builder/
/runtime/
  backend-interface/
  local-backend/
  firecracker-backend/
  host-agent/
  guest-supervisor/
/network/
/credential-broker/
/metering/
/agent-driver/
/conformance/
/chaos/
/deploy/
  helm-or-kustomize/
/docs/
  adr/
```

Exact language choices are secondary to preserving process/interface boundaries. For a systems-heavy implementation, Rust or Go are reasonable for host/supervisor services; do not mix languages without a concrete benefit.

---

# 3. Milestone 0 — Freeze contracts and scaffolding

## Deliverables

- Commit these four architecture documents to `/docs`.
- Define core IDs/types and versioned API schema.
- Create ADR template.
- Establish CI with unit, integration, conformance, lint, and security-test jobs.
- Add architecture lint/check preventing forbidden dependency directions where practical.

## Required schemas

At minimum:

- Sandbox;
- Environment;
- Workspace/WorkspaceGeneration;
- RuntimeIncarnation;
- Execution;
- Lease;
- Checkpoint;
- EndpointBinding;
- Event envelope.

## Gate

No runtime implementation begins until API/domain types can represent every scenario in REQUIREMENTS.md without vendor-specific fields.

---

# 4. Milestone 1 — Deterministic agent driver and in-memory control model

## Goal

Create the executable specification before real infrastructure.

## Build

- `agent-driver` event-loop/task model;
- in-memory Sandbox Manager state machine;
- in-memory Execution service;
- fake Workspace store with generations;
- fake runtime backend;
- event stream/outbox simulation;
- fault-injection hooks.

## Implement conformance scenarios first

- basic coding loop;
- multi-turn sandbox;
- async execution completion;
- workspace-only reset/epoch increment;
- lost ACK/idempotent launch;
- multiple client attachment;
- parent + subagent separate sandbox;
- stale epoch rejection.

## Gate

All lifecycle and epoch behavior is deterministic and covered before a real process is executed.

---

# 5. Milestone 2 — Local execution backend + guest supervisor

## Goal

Run real arbitrary commands while preserving API semantics.

## Build

- local/container runtime adapter;
- supervisor RPC protocol;
- sync and async execution;
- stdout/stderr streaming with backpressure;
- status/cancel;
- process inventory;
- host-side resource/accounting shim;
- execution persistence/reconnect.

## Tests

- thousands of short execs against one runtime;
- client disconnect while process runs;
- `cmd &` background descendant;
- double-fork/setsid daemon;
- process tree termination;
- concurrent callers;
- large stdout/stderr.

## Gate

Conformance harness demonstrates that API execution completion and sandbox quiescence are independent.

---

# 6. Milestone 3 — Durable metadata, event outbox, and workspace generations

## Goal

Make logical sandbox state survive control-plane/runtime restarts.

## Build

- relational metadata persistence;
- optimistic version/fencing fields;
- transactional event outbox;
- durable event consumer/replay API;
- WorkspaceStore interface;
- initial durable workspace implementation;
- committed generation on explicit commit/execution boundary;
- integrity hashes/manifests;
- rollback/reset reporting for lost uncommitted state.

## Fault tests

Crash at every point between:

```text
execution exit
workspace commit
DB state update
outbox write
external event publish
```

Verify reconciliation converges to one valid state with no silent workspace advancement or duplicate logical execution.

## Gate

Destroy all local runtime state and restore the same logical sandbox from persistent metadata/workspace storage.

---

# 7. Milestone 4 — Prepared Environment Build pipeline

## Goal

Separate expensive reusable setup from per-run startup.

## Build

- Environment spec/version;
- async build lifecycle;
- repo clone/checkout at exact SHA;
- bounded install command;
- build logs/artifacts;
- immutable environment artifact;
- active/failed build selection;
- per-session startup command model.

## Tests

- broken build cannot replace active successful build;
- environment identity changes when relevant configuration or repo SHA changes;
- multi-repo environment;
- idempotent rebuild;
- cold vs prepared startup benchmark.

## Gate

New local-backend sandbox can start from a prepared artifact without repeating install/clone work.

---

# 8. Milestone 5 — Kubernetes execution fleet and Runtime Host

## Goal

Move execution onto Kubernetes without placing Kubernetes on each tool-call path.

## Build

- dedicated execution node pool deployment;
- Runtime Host service/DaemonSet;
- host registration/heartbeats/capacity;
- sandbox scheduler placement contract;
- host local cache;
- fenced create/terminate requests;
- supervisor transport proxy;
- runtime-incarnation reconciliation.

Initial backend may still be container/process based to isolate K8s scheduling/control-plane issues from Firecracker.

## Tests

- runtime host restart;
- pod restart;
- node drain;
- node loss;
- cold-node placement;
- duplicate fenced create;
- cache hit/miss behavior;
- high-density sandbox starts.

## Gate

A logical sandbox can be rematerialized on another Kubernetes node with unchanged ID and correct workspace generation/epoch semantics.

---

# 9. Milestone 6 — Strong isolation backend (Firecracker candidate)

## Goal

Provide production hostile-code isolation while retaining identical external API behavior.

## Build

- Firecracker backend behind `RuntimeBackend`;
- jailer/host hardening;
- kernel/rootfs artifact management;
- TAP/private networking;
- vsock/private supervisor channel;
- host cgroup wrapping and metering;
- runtime create/destroy/pause;
- compatibility metadata for snapshot restore.

## Security requirements

- no host filesystem access beyond explicit devices/shares;
- no Kubernetes service-account credentials in guest;
- block metadata/control-plane endpoints;
- cross-VM isolation tests;
- dedicated execution account/network boundaries where deployment architecture permits.

## Gate

Run the exact same conformance suite against local backend and Firecracker backend. Differences require explicit backend capability declarations, not silent behavior changes.

---

# 10. Milestone 7 — Async/background resource policy and quiescence

## Goal

Correctly handle arbitrary long-lived descendants while making resource economics bounded.

## Build

- lease policy enforcement;
- process/VM-level CPU and memory accounting;
- background-active detection;
- baseline startup-service designation;
- quiescence policy;
- background deadlines/throttling;
- whole-sandbox terminate;
- resource-limit events.

## Tests

- CPU burner in foreground/background;
- abandoned dev server;
- fork bomb;
- memory bomb/OOM;
- many idle watchers;
- app + DB + test suite;
- resource usage matches authoritative host counters.

## Gate

No subprocess creation strategy can create unowned compute or prevent policy-driven reclamation indefinitely.

---

# 11. Milestone 8 — Suspend/resume and execution checkpointing

## Goal

Reclaim idle RAM/CPU with correct model-world synchronization.

## Part A — workspace-only suspend

Implement first:

- stop admission;
- commit workspace;
- terminate runtime;
- reclaim resources;
- rematerialize;
- increment epoch;
- emit detailed `ExecutionStateReset`.

## Part B — backend execution checkpoint

Then implement Firecracker snapshot path:

- pause;
- snapshot VM/memory;
- snapshot compatibility metadata;
- restore;
- lazy memory loading where useful;
- fallback to workspace-only reset when incompatible/corrupt.

## Benchmark

For representative coding-agent workloads measure:

- snapshot bytes;
- dirty bytes;
- suspend latency;
- resume latency;
- RAM reclaimed;
- rebuild/restart time without snapshot;
- storage and I/O cost.

## Gate

Checkpointing is enabled by policy only where measured benefit exceeds reconstruction cost; correctness never depends on it.

---

# 12. Milestone 9 — Network policy, temporary endpoint bridge, credentials

## Build

- host-enforced egress policy;
- DNS handling;
- network byte metering;
- temporary EndpointBinding gateway;
- binding authorization/TTL;
- epoch-fenced routing;
- credential broker/short-lived token flow;
- secret-safe logging.

## Tests

- allow/deny destinations;
- attempt metadata/K8s API access;
- stale endpoint after epoch reset;
- endpoint removed after terminate;
- credential expiration/revocation;
- secret not present in transcript/control logs.

## Gate

A sandbox can run a local dev server and receive authorized temporary access without becoming a general-purpose hosted endpoint.

---

# 13. Milestone 10 — Scheduler, fairness, autoscaling, and cache economics

## Build

- tenant quotas;
- priority classes;
- interactive vs background classes;
- environment/workspace locality scoring;
- memory-pressure awareness;
- capacity admission;
- execution-host autoscaling signals;
- cache eviction policy.

Do not overfit predicted workload behavior until measurements exist.

## Benchmarks

- packing density;
- CPU utilization with LLM-like think gaps;
- memory occupancy;
- cold/warm startup distribution;
- noisy-neighbor behavior;
- tenant fairness;
- spot/preemption recovery if used.

## Gate

Demonstrate that a large dormant logical population consumes negligible execution-fleet memory and that live capacity scales with active work.

---

# 14. Milestone 11 — Full chaos/conformance qualification

Run fault injection continuously against mixed workloads.

Required injected failures:

- API process kill;
- sandbox-manager kill;
- DB connection interruption;
- event bus outage;
- runtime host kill;
- guest supervisor kill;
- microVM kill;
- node loss;
- local disk/cache loss;
- checkpoint corruption;
- output-store transient failure;
- duplicate and delayed messages;
- client lost ACK;
- workspace-store transient failure.

Assertions:

- no cross-tenant leakage;
- no silent state loss;
- no duplicate logical execution under same idempotency key;
- correct epoch reset when continuity is lost;
- committed workspace integrity;
- eventual reconciliation or explicit terminal failure.

---

# 15. Milestone 12 — Real agent compatibility

Only after deterministic conformance is stable.

## Integrations

1. Minimal LLM tool loop adapter.
2. OpenHands-style execution adapter/reference.
3. Codex/Claude-like shell workload traces where available.
4. A2A reference agent *above* sandbox API for Atlassian-style demonstration.
5. Cursor-like coordinator simulator with event subscriptions and subagent fan-out.

## Validate

- prompt/context layer never needs runtime-specific hacks;
- background completion can wake a dormant agent through events;
- steering/cancellation works at tool boundaries;
- subagents can choose shared or separate sandboxes;
- execution reset is understandable/actionable by agent runtime.

---

# 16. Milestone 13 — Production hardening

Before production multi-tenancy:

- security review/threat model;
- penetration/breakout testing;
- upgrade/rollback procedures;
- schema/event versioning policy;
- backup/restore tests;
- tenant deletion/data-retention flow;
- cost attribution validation;
- SLOs and alerts;
- runtime-host image/kernel patch process;
- capacity emergency controls;
- audit trail requirements.

---

# 17. Engineering workflow rules for the coding agent

1. Read `INVARIANTS.md` before changing state/lifecycle semantics.
2. Add or update conformance tests before implementing a new semantic behavior.
3. Do not expose Kubernetes or Firecracker objects through the public API.
4. Do not add LLM/provider-specific code to sandbox core packages.
5. All async state transitions must be retry-safe and version/fence checked.
6. Every durable event should originate from persisted state via an outbox/reconciliation pattern.
7. Every optimization must have a cold-path correctness test.
8. Treat node-local state as deletable at any time.
9. Never use guest self-report as the sole source of security/resource enforcement.
10. Create an ADR for any change to durability, epoch, workspace commit, isolation, or ownership semantics.

# 18. First implementation ticket sequence

The first coding agent should break work into small PR-sized tickets in approximately this order:

1. Domain IDs/enums/state-machine library.
2. Versioned API schemas.
3. In-memory Sandbox Manager.
4. Event envelope/outbox abstraction.
5. Deterministic agent-driver skeleton.
6. Fake RuntimeBackend.
7. First lifecycle/epoch conformance tests.
8. Local RuntimeBackend.
9. Guest Supervisor protocol.
10. Execution persistence/idempotency.
11. Background descendant conformance tests.
12. WorkspaceStore interface + local durable implementation.
13. Workspace generations/commit/recovery tests.
14. Persistent metadata DB + reconciler.
15. Environment artifact/build interface.
16. Kubernetes Runtime Host skeleton.

Do not create the Firecracker backend before tickets 1–16 are functionally coherent.
