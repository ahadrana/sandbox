# Security Model and Threat Assessment

Status: design review for the current implementation (post-Milestone 13).
This document is the threat model required by PLAN §16. It states what the
platform defends against today, what it does not, and the bar for production
multi-tenancy.

## 1. Adversary model

The sandboxed workload is **hostile by default**:

- Repositories checked out into sandboxes may contain malicious code
  (build scripts, test harnesses, language-server plugins) that executes
  with sandbox privileges.
- LLM-generated commands may be prompt-injected: content read from a repo,
  a web page, or another agent's output can steer the model into issuing
  destructive or exfiltrating commands.
- Multi-agent runs introduce cross-agent influence: one agent's output is
  another agent's input, so a compromised or manipulated agent can attempt
  lateral movement through shared workspaces and the event bus.

The platform's job is to bound the blast radius of any single sandbox to
its tenant's resource envelope, and to keep the control plane's durable
state correct even when a sandbox (or the host running it) misbehaves.

## 2. Isolation posture by backend class

Per ADR-001, isolation classes are explicit in the public API:

| Class | Backend | Posture |
|---|---|---|
| `PROCESS` | `runtime/local-backend` | No security isolation. Commands run as the platform user on the host. Suitable for development and trusted workloads only. |
| `NAMESPACE` | `runtime/isolated-backend` | Linux namespace isolation via `bwrap`: private mount namespace with workspace bind-mounted, PID isolation, no host network, unprivileged user namespace. Filesystem visibility is limited to the sandbox workspace. |
| `VM` | (deferred) | Not implemented. ADR-001 records the decision to defer Firecracker until the control-plane semantics stabilize. |

Enforcement rules that hold regardless of class:

- **No guest self-report for enforcement.** Resource and lifecycle
  decisions are made by the manager/host-agent from host-observable state
  (PLAN §17 rule 9). Guest reports are hints, never proof.
- **Workspace access is scoped.** `Materialize` binds only the sandbox's
  own workspace generation; there is no API to reach another tenant's
  workspace path.
- **Network egress is policy-gated, not ambient.** The `network` package
  enforces per-sandbox allow/deny decisions; the `credential-broker`
  issues scoped, revocable credentials rather than handing sandboxes
  long-lived secrets.

## 3. Known gaps (honest list)

These are declared capability gaps, not bugs. They bound what the current
system may be used for:

1. **No VM-class backend.** `NAMESPACE` (bwrap) is the strongest
   isolation available. Kernel-exploit-level adversaries are out of scope
   until the VM backend lands (ADR-001).
2. **Host-level network enforcement is incomplete.** Egress policy is
   enforced at the platform layer (broker, policy checks), not with
   per-sandbox host firewall rules. A `NAMESPACE` sandbox has no host
   network by construction, but a `PROCESS` sandbox has full ambient
   network access of the platform user.
3. **Memory/CPU caps are best-effort.** Hard cgroup memory ceilings were
   flagged in Milestone 7 and remain policy-enforced at admission
   (quota/scheduler) rather than kernel-enforced per sandbox.
4. **No audit trail.** Lifecycle and credential events are emitted through
   the outbox, but there is no dedicated tamper-evident audit log.
5. **No penetration/breakout testing has been performed.** The bwrap
   profile has conformance tests for behavior, not adversarial review.

## 4. Control-plane integrity

Independent of sandbox isolation, the control plane is built so that
sandbox/host failure cannot corrupt durable state:

- Journal + snapshot durability with fsync before acknowledgment
  (ADR-002); every event originates from persisted state via the
  transactional outbox (PLAN §17 rule 6).
- Optimistic concurrency + fencing on all async transitions; the
  reconciler converges drifted state and refuses fenced generations.
- Idempotency keys scoped `sandboxID|key` make client retries safe;
  replayed keys return the original execution rather than duplicating it.
- Tenant deletion (`DeleteTenant`) terminates the tenant's sandboxes,
  unbinds endpoints, revokes broker credentials via the `CredentialRevoker`
  hook, garbage-collects workspace generations, and emits `TenantDeleted`.

## 5. Bar for production multi-tenancy

The platform is **not** ready for hostile multi-tenant production use.
Minimum criteria before that claim changes:

1. VM-class backend (ADR-001) as the default isolation class for untrusted
   workloads; `PROCESS` class restricted to single-tenant dev deployments.
2. Host-level network enforcement (per-sandbox egress rules) matching the
   declared `network` policy.
3. Kernel-enforced memory/CPU limits per sandbox.
4. Independent security review and breakout testing of the isolation
   profile.
5. Audit trail with retention policy.
6. Upgrade/rollback drills executed against real store trees (procedure in
   OPERATIONS.md) and backup/restore verification in CI (already covered
   by `TestBackupRestoreStoreTrees`).
