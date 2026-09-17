# Agent Sandbox Platform — Coding Agent Handoff

**Version:** 0.1  
**Date:** 2026-09-13  
**Status:** Architecture baseline for implementation  

## Mission

Build a Kubernetes-native, multi-tenant sandbox execution fabric for autonomous and interactive agents. The target behavior is the intersection of:

- **Cursor Cloud Agents:** isolated development machines, prepared bootable environments, long-running/background work, event-driven wakeups, subagents, hibernation, and self-hosted execution pools.
- **Atlassian Rovo/Jira agents:** durable agent/task identity, event-driven execution, asynchronous subagents, durable handles, notification loops, and optional shared sandbox access.
- **OpenHands/Codex:** public reference points for the agent-to-execution boundary and local sandbox mechanics.

The platform is **not** an LLM agent framework. It is the stateful execution substrate that an agent framework drives.

## Read these in this order

1. [`INVARIANTS.md`](./INVARIANTS.md) — hard rules that implementation must not violate.
2. [`REQUIREMENTS.md`](./REQUIREMENTS.md) — externally observable behavior and acceptance requirements.
3. [`DESIGN.md`](./DESIGN.md) — functional decomposition, state model, APIs, integrations, and test boundaries.
4. [`PLAN.md`](./PLAN.md) — implementation sequence and milestone gates.

If a proposed implementation conflicts with an invariant, **change the implementation, not the invariant**, unless the invariant is explicitly revised by an architecture decision.

## Architecture in one picture

```text
                 AGENT / ORCHESTRATION PLANE

 Jira/Rovo   Cursor-like coordinator   Custom agent runtime
     \                |                       /
      \               |                      /
       +------ durable events / tasks -------+
                          |
                    Agent Runtime
             LLM/context/tool dispatch
                          |
                execution requests/events
                          |
                          v
                SANDBOX CONTROL PLANE

        API/Auth ─ Sandbox Manager ─ Scheduler
                     |       |          |
              Workspace   Events     Leases/Quota
                     |       |          |
              Environment  Metering   Placement
                     \       |         /
                      +------+--------+
                             |
                             v
                  KUBERNETES EXECUTION FLEET

                  per-node Runtime Host
                             |
                 isolated sandbox runtime
                   (Firecracker candidate)
                             |
                       Guest Supervisor
                             |
             shell / processes / files / ports
```

## The most important semantic distinction

A task has a **logical sandbox state** for as long as it needs execution capability. A physical microVM/container is only one materialization of that state.

```text
Agent Task
   |
   +-- Logical Sandbox
         +-- Environment ref
         +-- Workspace generation
         +-- Execution epoch
         +-- Executions
         +-- Policies / leases
         +-- optional checkpoint
                 |
                 v
         Physical runtime incarnation
         (may appear/disappear repeatedly)
```

Do not equate "sandbox" with "Kubernetes pod" or "microVM process."

## What the coding agent should build first

Do **not** begin with Firecracker.

First build:

1. domain/state model;
2. sandbox API contracts;
3. deterministic reference agent driver/conformance harness;
4. local process/container runtime adapter;
5. async execution/event semantics;
6. workspace generation semantics.

Only after those contracts pass should a Firecracker/Kubernetes backend be introduced.

This keeps the hard correctness model testable independently from the virtualization implementation.

## Implementation status

All 13 milestones in PLAN.md are implemented (Go, stdlib only). Map from
milestone to code:

- **M1–M5 — core lifecycle, durability, executions, workspace:**
  `domain/`, `control-plane/sandbox-manager/`, `control-plane/event-service/`,
  `workspace/`, `environment-builder/`; conformance in `conformance/`
  (lifecycle, epoch, workspace, chaos suites).
- **M6 — capabilities model + VM backend:** `runtime/backend-interface/` plus
  `runtime/local-backend/` (PROCESS), `runtime/isolated-backend/`
  (NAMESPACE/bwrap), and `runtime/firecracker-backend/` (VM — implemented,
  no longer deferred; conformance-gated on KVM hosts via FC_TEST=1);
  ADR-001.
- **M7 — policy enforcement:** quota, capability, and fork-bomb/limits
  conformance tests.
- **M8 — suspend/checkpoint:** manager suspend/resume + checkpoint
  conformance tests.
- **M9 — network + credentials:** `network/`, `credential-broker/`.
- **M10 — scheduler/fleet:** `control-plane/scheduler/`, placement and
  fleet conformance tests; plus the real-Kubernetes deployment path:
  `cmd/control-planed` + `cmd/host-agentd` + `runtime/host-agent/rpc`
  (HTTP/JSON fleet transport) and `deploy/k8s/` (k3s DaemonSet/Deployment
  manifests, image build, smoke test) — ADR-005.
- **M11 — chaos:** runtime-loss and node-loss chaos harness in
  `conformance/`.
- **M12 — agent integration seam:** `integration/` (tool loop, OpenHands
  action adapter, trace replay, A2A wake, coordinator);
  `conformance/integration_test.go`.
- **M13 — hardening:** `DeleteTenant`, manager metrics, backup/restore
  conformance (`conformance/operations_test.go`); ADR-002, ADR-003,
  `docs/SECURITY.md`, `docs/OPERATIONS.md`.

Run everything with `go test ./...` from the repository root.

## SandboxLab — deterministic simulation + scenario runner

`sandboxlab/` (ADR-010) runs the real control plane in-process on a virtual
clock: same seed ⇒ byte-identical trace. Declarative scenarios live in
`sandboxlab/scenarios/*.json` (embedded; the `go test` suite runs them all)
and are executable standalone via `cmd/sandbox-lab`:

```
go run ./cmd/sandbox-lab list
go run ./cmd/sandbox-lab run resume-storm -trace /tmp/resume.simtrace
go run ./cmd/sandbox-lab run-all builtins   # CI entry point
```

The repo has no Makefile/CI script (tests are run directly); `run-all` with
exit 0/1 is the CI integration point.

### Enriched trace + time-travel replay (phase 5)

`-trace` writes the v1 text simtrace (byte-identical per scenario+seed, for
CI diffs). `-trace2` writes the v2 JSONL artifact (`.simtrace.jsonl`):
every trace entry with seq, virtual time, causal parent seq, inline
invariant-violation records, world snapshots (hosts, sandboxes, placements,
fences, bindings) under an adaptive-stride policy, and the final invariant
report. The replay UI renders it as a time-travel view:

```
go run ./cmd/sandbox-lab run traffic-resume-race -trace2 /tmp/trr.simtrace.jsonl
go run ./cmd/sandbox-lab render /tmp/trr.simtrace.jsonl -o /tmp/trr.html  # self-contained, open from file://
go run ./cmd/sandbox-lab replay /tmp/trr.simtrace.jsonl -addr :8080       # serve over HTTP
```

The rendered page is a single HTML file with inline CSS/JS and zero
external resources: play/pause/step controls over virtual time, a timeline
scrubber with red INVARIANT_VIOLATION markers, host capacity bars and
sandbox cards colored by state, an inspector with causal-parent jump and
what-changed diffs, and the phase-3 invariant report (violations click
through to the offending seq).

### Resource contention (phase 6)

Hosts may declare `vcpu`, `io_mbps`, `net_mbps`, `vm_idle_vcpu`; ops then
compete for those pools under a fluid fair-sharing model — concurrent
restores on a saturated host stretch (~N× for N identical ops), idle VMs
tax boots, and the verdict prints p50/p99 op latencies. Hosts without
`vcpu` keep the legacy flat latencies byte-identically.

## Required reference harness

The repository must contain a deterministic `agent-driver` capable of simulating modern agent behavior without an LLM. It must support scenarios such as:

- many LLM turns against one sandbox;
- foreground and Bash-spawned background work;
- user steering while work continues;
- event-driven wakeup;
- parent/subagent with separate sandboxes;
- multiple callers sharing a sandbox;
- runtime loss and execution-epoch reset;
- suspend/resume;
- temporary service binding;
- idempotent execution retries;
- quota violation and fork bombs;
- node/host loss;
- large logical-agent population with a much smaller live-sandbox population.

Real LLM integrations are compatibility tests, not the correctness harness.

## Scope boundary

### Sandbox platform owns

- logical sandbox lifecycle;
- physical runtime lifecycle;
- workspaces and workspace generations;
- prepared environments;
- process execution;
- background processes;
- output streaming;
- temporary listeners/endpoints;
- network policy;
- credentials presented to execution;
- suspend/resume/checkpoint;
- resource leases and metering;
- scheduling and placement;
- execution events.

### Agent framework owns

- prompts;
- LLM selection and invocation;
- prompt/context caching;
- context compaction;
- reasoning loops;
- subagent reasoning;
- user-facing conversation;
- deciding which sandbox event should wake an LLM;
- A2A/MCP/product-specific orchestration.

## Research basis

Current behavior used to derive the requirements:

- Atlassian, *Opening the door to agent autonomy: The architecture behind Rovo’s agent harness* (2026-08-26): https://www.atlassian.com/blog/rovo/agent-autonomy
- Atlassian, *Integrate remote agents with Jira* (A2A 1.0): https://developer.atlassian.com/platform/forge/remote-agents-in-jira/
- Cursor, *Cloud Agents and Cursor Harness Improvements* (2026-08-19): https://cursor.com/changelog/08-19-26
- Cursor, *Cursor Projects* (2026-09-10): https://cursor.com/changelog/projects
- Cursor, *Cloud Agent Builds*: https://cursor.com/docs/cloud-agent/builds
- Cursor, *Cloud Agents*: https://cursor.com/docs/cloud-agent
- Cursor, *Security overview*: https://prod.cursor.com/docs/cloud-agent/security
- Firecracker design/API: https://github.com/firecracker-microvm/firecracker
- OpenAI Codex Linux sandbox: https://github.com/openai/codex/tree/main/codex-rs/sandboxing

These sources inform semantics; the platform must remain vendor-neutral.
