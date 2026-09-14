// Package firecrackerbackend is a VM-class runtime backend (ADR-0001
// acceptance path) that drives real Firecracker microVMs on a KVM-capable
// host. It implements backendinterface.Backend plus the sandbox-manager
// Runtime surface without leaking Firecracker concepts through the contract.
//
// Stage-2 scope and honest limits:
//
//   - VMM lifecycle: one `firecracker --api-sock` process per incarnation,
//     with a per-incarnation directory (api.sock, console.log, a copy of the
//     rootfs, a generated workspace ext4 image). When Config.JailerBin is
//     set, VMMs spawn through the Firecracker jailer (chroot + namespaces +
//     cgroup v2, via passwordless sudo); if the jailer cannot be used the
//     backend falls back to raw spawns and reports why via JailerStatus.
//     aarch64 note: the stock jailer (<= v1.17) hard-fails on hosts whose
//     kernel lacks CONFIG_ARM64_CPUID_REGS (no sysfs midr_el1); a jailer
//     patched to skip the missing file is required there.
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
//     Cancel/ReadOutput/ProcessInventory/TerminateBackground run through the
//     shared wire client (runtime/guest-supervisor/client.go) — the same
//     semantics the local/isolated backends get from the same daemon;
//     WorkspaceFiles reads the live guest /workspace
//     (host-side mirror kept as pre-boot/no-agent fallback). Writes also
//     update the mirror for dirty tracking (INV-006).
//   - Snapshots are full Firecracker snapshots (paused VM: mem + state +
//     reflink copies of both drives) stored under <root>/snapshots/<inc>/<ts>
//     so they survive Terminate/KillRuntime of the source VM. Oldest
//     snapshots beyond Config.MaxSnapshotsPerIncarnation (default 3) are
//     garbage-collected after each Snapshot.
//   - Networking (stage 4, Config.Networking): each incarnation gets a
//     deterministic TAP device and /30 pair in 192.168.0.0/16, host NAT
//     (MASQUERADE via the default uplink, ip_forward enabled once), and a
//     per-incarnation iptables FORWARD chain enforcing the
//     network.EgressPolicy carried in Spec.Env["AGENT_SANDBOX_EGRESS"] —
//     169.254.169.254 is always dropped first, then deny entries, then
//     allows, with a final DROP when DefaultAllow is false. With Networking
//     off no NIC is attached at all and NetworkIsolated is declared false.
//     Requires passwordless sudo and ip/iptables on the host.
//
// Readiness: Create/Start wait for the API socket to answer and for the
// serial console log to reach the login prompt (boot) or the workspace
// marker, with bounded timeouts. All API calls carry Config.APITimeout.
// Close reaps every spawned firecracker process.
package firecrackerbackend
