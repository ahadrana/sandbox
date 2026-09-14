// Package firecrackerbackend is a VM-class runtime backend (ADR-0001
// acceptance path) that drives real Firecracker microVMs on a KVM-capable
// host. It implements backendinterface.Backend plus the sandbox-manager
// Runtime surface without leaking Firecracker concepts through the contract.
//
// Stage-2 scope and honest limits:
//
//   - VMM lifecycle: one `firecracker --api-sock` process per incarnation,
//     with a per-incarnation directory (api.sock, console.log, a copy of the
//     rootfs, a generated workspace ext4 image). Jailer wrapping is a
//     follow-up; Config.JailerBin is accepted but unused (see Config docs).
//   - Rootfs is a full per-incarnation copy (~300MB); copy-on-write overlays
//     (qcow2/reflink) are a noted improvement.
//   - Workspace materialization: Spec.WorkspaceManifest is baked into a
//     second virtio-block drive (ext4 image built host-side with debugfs,
//     no root required) mounted in-guest at /workspace by a systemd unit
//     injected into the rootfs copy. The unit prints AGENT_WORKSPACE_READY
//     to the serial console as a readiness/mount marker.
//   - Exec data path (stage 3): a static guest-supervisor daemon
//     (runtime/guest-supervisor/cmd/guest-supervisor, linux/arm64) is
//     injected into the rootfs copy, starts via systemd after the workspace
//     mount, and serves the supervisor protocol (length-prefixed JSON over
//     vsock port 5000, shared types in runtime/guest-supervisor/protocol.go).
//     The host transport dials Firecracker's vsock UDS (CONNECT handshake),
//     one connection per request, so blocking Waits don't starve other calls
//     and snapshot-restore reconnect is transparent. Exec/Wait/Status/
//     Cancel/ReadOutput/ProcessInventory/TerminateBackground mirror the local
//     backend's semantics; WorkspaceFiles reads the live guest /workspace
//     (host-side mirror kept as pre-boot/no-agent fallback). Writes also
//     update the mirror for dirty tracking (INV-006).
//   - Snapshots are full Firecracker snapshots (paused VM: mem + state +
//     reflink copies of both drives) stored under <root>/snapshots/<inc> so
//     they survive Terminate/KillRuntime of the source VM. Snapshot GC is a
//     retention follow-up.
//   - No network device is attached: guests have no network at all, so
//     NetworkIsolated is declared false (nothing to isolate) and stage 4
//     adds the egress-policy datapath.
//
// Readiness: Create/Start wait for the API socket to answer and for the
// serial console log to reach the login prompt (boot) or the workspace
// marker, with bounded timeouts. All API calls carry Config.APITimeout.
// Close reaps every spawned firecracker process.
package firecrackerbackend
