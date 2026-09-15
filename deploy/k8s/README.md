# Sandbox platform on Kubernetes (dev topology, ADR 005)

Single-node k3s deployment proving the real fleet path:

```
sandboxctl/curl -> control-planed (Deployment, ClusterIP :8080)
   manager -> scheduler -> Fleet --HTTP/JSON--> host-agentd (DaemonSet)
     -> HostAgent -> firecracker backend -> jailer -> microVM -> vsock supervisor

endpoint traffic (ADR 007):
client -> endpoint-proxyd (Deployment, ClusterIP :8080)
   -> control-planed (/v1/bindings, /v1/route, /v1/sandboxes/{id}/resume|address)
   -> host-agent node :<target-port> (incarnation's data address)
```

Kubernetes manages **execution-host capacity only** (DaemonSet lifecycle);
per-sandbox objects never appear (INV-019). Placement policy stays in the
sandbox scheduler.

## Endpoint traffic flow (ADR 007)

`endpoint-proxyd` is the single ingress hop for endpoint bindings. A
request identifies its binding either by the `X-Endpoint-Binding` header
(explicit override) or by hostname — `<logical-name>.<ENDPOINT_DOMAIN>`
(dev: `endpoints.sandbox.local`) resolves through
`GET /v1/bindings/{name}` on the control plane. The proxy then:

1. Routes the binding via `GET /v1/route/{bindingID}` — the control plane
   evaluates the fail-closed gateway verdict server-side (unknown binding,
   non-ACTIVE state, TTL expiry, stale epoch fence all deny).
2. On a "sandbox not live" deny, single-flights
   `POST /v1/sandboxes/{id}/resume` (one resume shared by all waiters on
   that sandbox; bounded attempts; per-binding negative cache).
3. Resolves the upstream via `GET /v1/sandboxes/{id}/address` (the live
   incarnation's host, from its placement) and reverse-proxies to
   `host:<target-port>`. Verified-live bindings forward from a short-TTL
   cache with zero control-plane calls.

It is a separate Deployment, not a sidecar on host-agentd: there is one
logical ingress (single-flight dedup and the live cache only work
fleet-wide behind one hop), it scales independently of execution hosts,
and a sidecar in the hostNetwork pod would share the node's port space
with the backend's TAP/iptables datapath.

**Dev gap:** the upstream is the host node's address at the binding's
target port; publishing `host:port -> guest:port` (DNAT or a host-side
relay) is the firecracker backend's follow-up, so end-to-end guest
reachability arrives with it.

## Prereqs (deployment host)

- k3s server (`curl -sfL https://get.k3s.io | sudo sh -`, v1.32 channel used
  here — see note below), `kubectl` configured for the user
  (`KUBECONFIG=$HOME/.kube/config`).
- /dev/kvm, firecracker + patched jailer in `/usr/local/bin`, artifacts
  (`vmlinux.bin`, `rootfs.ext4`) in `~/fc-artifacts`.
- On this Graviton host: kernel 6.8.0-1063-aws (kernels ≥ 6.16 break the
  kubelet here — see Notes below).
- Go toolchain to build the static binaries.

## Deploy

```sh
REPO=$HOME/sandbox deploy/k8s/build-images.sh        # builds + imports images into k3s containerd
kubectl apply -f deploy/k8s/sandbox-platform.yaml
deploy/k8s/smoke.sh                                   # end-to-end: create -> microVM -> exec -> commit -> terminate
deploy/k8s/smoke.sh drill                             # failure drill: pod delete -> FAILED reconcile -> re-register
```

## Equivalent curl (what sandboxctl does)

```sh
kubectl -n sandbox-system port-forward svc/control-planed 18080:8080 &
T='X-Sandbox-Token: dev-token'
SB=$(curl -s -H "$T" -d '{"task_ref":"task-1"}' localhost:18080/v1/sandboxes | jq -r .SandboxID)
curl -s -H "$T" -d '{}' localhost:18080/v1/sandboxes/$SB/materialize
curl -s -H "$T" -d '{"command":"echo hi > f.txt"}' localhost:18080/v1/sandboxes/$SB/exec
curl -s -H "$T" -d '{}' localhost:18080/v1/sandboxes/$SB/commit
curl -s -H "$T" localhost:18080/v1/sandboxes/$SB/files
curl -s -H "$T" -d '{}' localhost:18080/v1/sandboxes/$SB/terminate
```

## Auth / security (DEV-ONLY gaps)

- Every endpoint (public API, host RPC, heartbeat) checks one shared header
  `X-Sandbox-Token` (`dev-token` in the manifests). No TLS, no per-tenant
  auth — real AuthN/TLS is the gateway's concern (DESIGN §6.1) and is
  deliberately out of scope for this dev topology.
- host-agentd pods are `privileged: true` + `hostNetwork: true` (firecracker
  needs /dev/kvm; the jailer needs mount/net/user namespaces and cgroup v2).
  ServiceAccounts have **no** API token and **no** RBAC Roles: the platform
  never calls the K8s API. `hostPID` is not shared.
- The jailer spawn goes through a static `sudoshim` (strips flags, execs) —
  the backend's `sudo jailer ...` convention; pods already run as root.

## State / loss semantics

- control-planed keeps in-memory workspace/store/outbox (restart loses
  control-plane state; durable stores are separate M3+ work).
- Host agents heartbeat every 2s with a per-process boot ID; the control
  plane simulates host loss after ~6s of silence, the fleet declares the
  host lost after 3 missed ticks, and the manager marks affected sandboxes
  `FAILED` explicitly (`smoke.sh drill` verifies). A DaemonSet replacement
  re-registers under the same host ID (node name) with a new boot ID, which
  also declares the previous process's incarnations lost (pod restart =
  microVM loss = explicit reconcile), then serves new placements.

## Notes / simplifications in this topology

- `FC_NETWORKING` is off: no per-incarnation TAP/egress inside the pod yet
  (the datapath itself is proven on-host by `TestEgressPolicy`). The image
  already ships the datapath tooling the egress feature needs when enabled
  (Batch 1 follow-up): `ip`/`iptables` (+ xtables-nft plugins) for the TAP
  and egress chains, `conntrack` for the policy-generation conntrack flush,
  and `sysctl` for `ip_forward`; a privileged `netinit` initContainer
  applies `net.ipv4.ip_forward=1` and
  `net.ipv4.ip_unprivileged_port_start=0` (the per-incarnation DNS-learning
  proxies bind :53 on their TAP host addresses) on the host netns at pod
  start. The backend also applies both sysctls itself at runtime.
- k3s (v1.36 and v1.32 alike) crash-looped on this host's 7.0.0-1012-aws
  AND 6.17.0-1017-aws kernels: `kubelet: could not detect number of cpus`.
  The host's ACPI MADT marks only CPUs 0-3 enabled and kernels ≥ 6.16 only
  register sysfs CPU devices for enabled CPUs, so cadvisor's topology
  discovery finds no cores. The cluster runs kernel 6.8.0-1063-aws, which
  registers all 16 present CPUs; firecracker/KVM are unaffected.
- Kernel/roots artifacts and the patched jailer are baked into the image;
  VM state lives in an `emptyDir` (pod restart = microVM loss = explicit
  reconcile).
