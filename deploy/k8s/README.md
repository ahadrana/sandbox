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
   non-ACTIVE state, TTL expiry, stale epoch fence all deny). The verdict
   carries typed flags: `Resumable` marks denies a resume can cure (binding
   SUSPENDED / sandbox not live); a client-side `LookupError` mark
   (transport/5xx talking to the control plane) surfaces as 502, never a
   403 and never a resume trigger. Unknown hostnames fail closed with 404
   and are negatively cached (NameNegativeTTL) so a name spray never
   reaches the control plane; the manager resolves names via an O(1)
   index, not a scan.
2. On a `Resumable` deny, single-flights
   `POST /v1/sandboxes/{id}/resume` (one resume shared by all waiters on
   that sandbox; bounded attempts; per-binding negative cache). The resume
   call's transport timeout (75s) exceeds the proxy's 60s ResumeTimeout so
   a slow-but-healthy restore never burns attempt budget on a client-side
   deadline.
3. Resolves the upstream via `GET /v1/sandboxes/{id}/address` (the live
   incarnation's host, from its placement) and reverse-proxies to
   `host:<target-port>` — the published endpoint (below). Verified-live
   bindings forward from a short-TTL cache with zero control-plane calls.

It is a separate Deployment, not a sidecar on host-agentd: there is one
logical ingress (single-flight dedup and the live cache only work
fleet-wide behind one hop), it scales independently of execution hosts,
and a sidecar in the hostNetwork pod would share the node's port space
with the backend's TAP/iptables datapath.

## Routed restore (ADR 008/009): the resume keeps continuity

With the manager's runtime being a fleet of host agents, `Resume` routes
`Fleet.Restore` to the checkpoint's ORIGIN host first — the bits are
host-local and no transfer is needed. When the origin cannot place it
(full, facts-changed across a kernel upgrade), the restore fails over to a
guard-matching peer that PULLS the snapshot package from the origin over
the host-agent RPC (ADR-009: manifest + blob streaming under the same
token auth, per-file sha256 verified against capture-time hashes, staged
atomic install, source-side GC pinning). The host agent re-registers the
reclaimed incarnation from the self-describing checkpoint metadata under a
fresh placement fence. The execution epoch is preserved, so the suspended
binding's epoch fence still matches: it reactivates, its host port is
republished, and the proxy's triggering request returns the guest's
response (200), not a 503. A checkpoint whose origin host is GONE (down —
it cannot serve the package either) fails honestly and the manager falls
back to workspace-only recovery (epoch bump; bindings stay suspended). A
shared snapshot store for the origin-destroyed case is a documented
follow-up. This single-node deployment still pins every sandbox to its one
host, so the cross-host path is exercised by the two-agent single-node
test topology, not by this cluster.

Two deployment facts make this work in the container image: util-linux
`mount`/`umount` are baked in (the jailed snapshot path bind-mounts the
incarnation's snapshot root into the jail), and that bind mount happens at
jail PREPARATION time — the jailer unshares a private mount namespace and
a container root is not a shared peer of it, so a mount performed at
snapshot time would never reach the running VMM.

## Host->guest port publishing (the data-plane last hop)

When the manager creates an endpoint binding on a running sandbox it calls
the runtime's `PortPublisher` seam (`PublishPort(handle, guestPort,
hostPort)`); the firecracker backend DNATs the host port to the
incarnation's TAP IP in a per-incarnation nat chain (`FC-PUB-<slot>`)
hooked from PREROUTING (external and pod clients) and OUTPUT (host-local
clients, loopback excluded — loopback would hairpin into a black hole).
Both hooks match `-m addrtype --dst-type LOCAL` (review C1): only traffic
destined to the host's OWN addresses is redirected — host outbound
connections to a remote service on the same port, and forwarded/routed
traffic, are never hijacked into a guest.
The host port IS the binding's target port: no remapping, so the address
clients hold never lies; a second sandbox publishing the same host port
fails the binding creation with a typed port-conflict error. Suspend,
unbind, and TTL expiry unpublish; Terminate/KillRuntime/restore tear the
whole chain down with the incarnation's networking, and resume republishes
on the (possibly new) host. Replies need no MASQUERADE (they traverse the
host and conntrack reverses the DNAT); note DNAT'd replies are evaluated
by the guest egress chain, so publishing composes with default-allow
policies — under default-deny the client destinations must be allowed.
Publishing steals the port on every host address, so the backend enforces
a port policy (review H1): the well-known floor (<1024, covers SSH) is
never publishable, and a deny-list — defaulting to the platform/node
service ports 6443 (apiserver), 8080 (platform dev port: agent RPC,
control-plane, endpoint-proxyd), 10250 (kubelet), extendable via the
host-agentd env `FC_PUBLISH_DENY_PORTS="9090,3000"` — rejects ports bound
by node services, all with typed port-conflict errors. The host agent
additionally refuses its own RPC listen port (`ProtectPorts`), and the
publish/unpublish RPCs are fence-validated like every other routed op.

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
  control-plane state; durable stores are separate M3+ work). Because the
  store is ephemeral, sandbox/incarnation IDs are boot-scoped
  (`sb-<base36>-N`): after a control-plane restart the ID counter restarts
  at 1, and the scope segment keeps the new boot's IDs disjoint from the
  incarnation records a long-lived host agent still holds — the host
  re-registers, the previous boot's incarnations are scrubbed as orphans,
  and new placements can never collide with them.
- Host agents heartbeat every 2s with a per-process boot ID; the control
  plane simulates host loss after ~6s of silence, the fleet declares the
  host lost after 3 missed ticks, and the manager marks affected sandboxes
  `FAILED` explicitly (`smoke.sh drill` verifies). Every accepted heartbeat
  also clears the fleet's down latch (`Fleet.HostSeen`), so a host that
  stalls once and resumes is placement-eligible again immediately — the
  latch is never permanent while heartbeats arrive. A DaemonSet replacement
  re-registers under the same host ID (node name) with a new boot ID, which
  also declares the previous process's incarnations lost (pod restart =
  microVM loss = explicit reconcile), then serves new placements.
- Fleet registration pins the host ID from the authenticated heartbeat
  (`rpc.NewClientWithID`): the fleet must never be keyed by an RPC-queried
  host ID, because a transient failure there returns "" and corrupts every
  host index (a later placement then resolves a HostID the fleet never
  recorded).

## Notes / simplifications in this topology

- `FC_NETWORKING` is on: every incarnation gets a TAP behind host egress
  chains (the datapath proven on-host by `TestEgressPolicy`), and endpoint
  bindings publish host:port -> guest:port DNAT rules (ADR-007). The image
  ships the datapath tooling this needs: `ip`/`iptables` (+ xtables-nft
  plugins) for the TAP and egress/publish chains, `conntrack` for the
  policy-generation conntrack flush, and `sysctl` for `ip_forward`; a
  privileged `netinit` initContainer applies `net.ipv4.ip_forward=1` and
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

## Simulation harness: sandbox-sim

`cmd/sandbox-sim` validates the deployed cluster with N concurrent
sandboxes and visualizes it live. It creates each sandbox with a guest
workload (a python HTTP server answering `hello from sandbox sim-i
counter=<n>` where the counter lives in guest tmpfs — a genuine RAM
continuity marker) plus an endpoint binding (`sim-i`, target port 8000+i),
then runs a scenario loop and records every action in a ring buffer:

- `steady` — periodic exec ticks (counter increments) and endpoint curls
  through endpoint-proxyd.
- `churn` — random suspend → routed-restore cycles; after each resume the
  sim checks continuity (epoch preserved AND tmpfs counter not regressed)
  and marks PASS/FAIL.
- `storm` — bursts of concurrent endpoint requests at a suspended sandbox,
  exercising the proxy's single-flight resume.

Run (against the port-forwarded control plane):

```
kubectl -n sandbox-system port-forward svc/control-planed 18080:8080 &
kubectl -n sandbox-system port-forward svc/endpoint-proxyd 18081:8080 &
go build ./cmd/sandbox-sim
./sandbox-sim -cp http://localhost:18080 -proxy http://localhost:18081 \
  -token dev-token -sandboxes 4 -scenario churn -ui :9100
```

The UI is a single self-contained page at `http://<node>:9100` (sandbox
cards color-coded by state with epoch/ws-generation/continuity, an
aggregate stats header, and a scrolling event log; click a card to
filter). `/api/state` serves the same data as JSON (sandboxes, events,
stats). Note: the control plane has no list-sandboxes endpoint, so ground
truth is refreshed per-sandbox — the sim only tracks sandboxes it created.

"Good" looks like: all sandboxes live with exec ticks and endpoint 200s
flowing, churn restores at 100% continuity PASS (epoch preserved, counter
intact), and a suspended sandbox answering a proxied request with the
guest's 200 after single-flight resume (observed: 1.5–15s cold-restore
latency, then millisecond responses).
