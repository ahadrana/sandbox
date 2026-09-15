# ADR 005 — Kubernetes manages execution-host capacity only; HTTP/JSON control-plane RPC as the initial transport

**Status:** Accepted
**Date:** 2026-09-15
**Context:** The platform needed its first real-Kubernetes deployment (review follow-up 3 was the code prerequisite). DESIGN §7 / PLAN §8 say K8s manages execution-host capacity while the sandbox scheduler keeps placement policy, and INV-019 forbids Kubernetes objects in any public surface. The fleet was in-process: manager → scheduler → host agent → backend in one Go binary. Two real decisions had to be made: what K8s owns, and what transport replaces the in-process fleet→host call graph.

## Decision

1. **K8s owns host lifecycle, nothing else.** `host-agentd` (HostAgent + Firecracker backend) runs as a privileged, hostNetwork DaemonSet on execution nodes; `control-planed` (manager + scheduler + fleet) is a Deployment + ClusterIP Service. There are no per-sandbox K8s objects — sandboxes, incarnations, epochs, and fences live entirely in the sandbox domain, satisfying INV-019 by construction. ServiceAccounts get no API token and no RBAC Roles because the platform never calls the K8s API.
2. **The fleet routes to remote hosts over narrow HTTP/JSON RPC** (`runtime/host-agent/rpc`). The fleet's `Host` interface is the exact call graph the in-process fleet already used; the RPC is a mechanical translation of it (same message shapes as the domain/api types, stdlib net/http only). Host agents register and heartbeat over the same channel; the control plane marks silent hosts down and the existing fleet tick logic declares them lost — fencing, placement, and loss semantics are unchanged from the in-process world and remain conformance-tested there. Each heartbeat carries a per-process boot ID; a changed boot ID (pod reschedule) re-registers the host through the fleet, which declares every incarnation the new process no longer runs as lost — this beats the down-tick path, because a DaemonSet replacement resumes heartbeats faster than the staleness window.
3. **Dev-only auth gap is explicit.** All endpoints check one shared token header; there is no TLS and no per-tenant identity. AuthN/TLS belongs to the gateway (DESIGN §6.1) and is deliberately not bolted onto this transport.

## Consequences

- The same `HostAgent` code serves in-process tests and the DaemonSet; the same fleet code routes in-process hosts (conformance) and remote hosts (deployment), so the conformance suite keeps guarding placement/loss semantics.
- control-planed state is in-memory; a control-plane restart loses the world (acceptable in dev; durable stores are the M3+ work).
- VM state is pod-lifetime (emptyDir); a host-agent pod restart means its microVMs die and the manager marks the affected sandboxes FAILED explicitly — verified by the failure drill in `deploy/k8s/smoke.sh`.
- TAP/egress networking inside the pod (`FC_NETWORKING`) is deferred: the image lacks iproute2/iptables; the datapath is already conformance-proven on-host.
- Kernel constraint on this host (AWS Graviton metal): its ACPI MADT marks only CPUs 0–3 as "enabled" (`/sys/devices/system/cpu/enabled` = `0-3`), and kernels ≥ 6.16 register sysfs CPU devices only for enabled CPUs — so on both 7.0.0-1012-aws and 6.17.0-1017-aws only cpu0–3 exist in sysfs with no `topology/` directories, which zeroes cadvisor's core count and crash-loops any kubelet (`could not detect number of cpus`). The cluster therefore runs kernel 6.8.0-1063-aws, which registers all present CPUs; firecracker/KVM are unaffected either way.
