# ADR-0001: Runtime isolation backend — Firecracker ACCEPTED (implemented)

- **Status:** accepted (implemented)
- **Date:** 2026-09-13 (mechanism accepted); 2026-09-14 (Firecracker backend implemented, decision closed)
- **Deciders:** platform team

## Context

PLAN §9 calls for a strong-isolation backend with Firecracker as the primary
candidate. The original dev environment had no `/dev/kvm`, so the
Firecracker-vs-alternatives decision was initially deferred behind the
capability-declaration contract. A KVM-capable host (linux/arm64,
Firecracker + jailer v1.17) is now available and the backend is implemented
and conformance-gated (M6).

Relevant invariants: INV-026 (runtime substitutable; differences via declared
capabilities, never silent), INV-027 (isolation stronger than Kubernetes
namespaces), FR-ISO-004 (stable interface), FR-SEC-001 (no control-plane
credentials in guest).

## Decision

1. **Firecracker is ACCEPTED as the VM-class production backend.**
   `runtime/firecracker-backend/` implements `backendinterface.Backend` plus
   the full sandbox-manager `Runtime` surface with zero public-API changes
   and declares `IsolationClass: VM`. Kata/gVisor were not re-benchmarked:
   Firecracker meets every acceptance criterion below, and the capability
   contract keeps the platform vendor-neutral should that change.
2. **Backend capability declarations remain the contract.** Behavioral
   differences between backends are expressed as declared capabilities;
   conformance tests skip on missing capabilities instead of failing on
   silent differences.

### Capability matrix

| Capability | fake | local | isolated (bwrap) | firecracker |
|---|---|---|---|---|
| IsolationClass | PROCESS | PROCESS | NAMESPACE | VM |
| SupportsPause / Snapshot / Restore | yes/yes/yes (simulated) | yes (SIGSTOP/SIGCONT) | as local | yes (full VM snapshot to disk) |
| SupportsCheckpoint | yes (simulated) | yes (STOP/CONT, RAM retained) | as local | yes (snapshot-class) |
| CheckpointReclaimsMemory | no | no (honest 0) | no | **yes** (VMM terminated after capture; Restore boots from snapshot) |
| NetworkIsolated | n/a | no | yes | yes when `Config.Networking` (declared false otherwise: no NIC attached at all) |
| HostCredentialFree | yes | no | yes | yes |

`CheckpointReclaimsMemory` is the one semantic addition the firecracker
backend motivated: a snapshot-class checkpoint captures full VM state to
disk, so the manager terminates the VMM after capture and reports the actual
reclaimed RSS in the `SandboxSuspended` event, while `Resume` restores from
the checkpoint with genuine continuity (epoch retained, guest PIDs
unchanged). STOP/CONT backends keep the old honest-0 behavior; the shared
conformance assertions were not weakened — the difference is declared
(INV-026).

3. **Conformance gate (M6).** The conformance suite runs the firecracker
   backend as a third adapter (`runBoth` → fake + local + firecracker when
   `FC_TEST=1` + KVM + artifacts; clean skips otherwise). All core contract
   scenarios pass against it: basic coding loop, multi-turn, async
   completion, workspace-only reset/epoch, multiple clients, subagent
   isolation, stale epoch/fencing, background-active→quiescent, execution
   persistence, runtime-loss finalization, cross-tenant denial, uncommitted
   loss reporting, tool loop, quota retry — plus a firecracker-specific
   checkpoint suspend/resume test asserting RAM reclaimed > 0 and guest PID
   continuity. Fake-only scripted-fault tests (lost ACKs, corrupt
   checkpoints) and scale/chaos suites (dormant scale, packing density,
   node-loss chaos, hundreds of incarnations) stay on their current
   backends: they exercise control-plane determinism, not runtime
   semantics, and VM boot cost makes them impractical — this is the
   capability-declaration model applied to test selection, not a semantic
   gap.

## Acceptance criteria — status

- [x] implements `backendinterface.Backend` + supervisor data path, zero
  public-API changes, `IsolationClass: VM`;
- [x] passes the conformance suite run against it (skips only on declared
  missing capabilities);
- [x] PLAN §9 security: no host filesystem access beyond the virtio-block
  drives (rootfs + workspace image) and the vsock control channel; no host
  credentials in the guest (exec environment is explicit);
  metadata endpoint `169.254.169.254` always dropped; cross-VM isolation
  via separate rootfs/workspace drives per incarnation;
- [x] snapshot compatibility: full Firecracker snapshots carry class
  metadata (`firecracker_full`) and restore is gated on it;
- [~] jailer/host hardening: implemented (see caveats), production node
  provisioning remains.

## Implementation notes and caveats

- **Jailer.** When `Config.JailerBin` is set, VMMs spawn through the
  Firecracker jailer (chroot + mount/PID namespaces + cgroup v2) via
  passwordless sudo; failure falls back to raw spawns with the reason
  surfaced via `Backend.JailerStatus()`. **aarch64 caveat:** the stock
  jailer (≤ v1.17, still on main) hard-fails on hosts whose kernel lacks
  `CONFIG_ARM64_CPUID_REGS` because `copy_midr_el1_info` treats the missing
  sysfs `midr_el1` as fatal; a jailer patched to skip the missing file is
  installed on the conformance host. An upstream fix should be proposed.
- **Networking enforcement.** With `Config.Networking`, each incarnation
  gets a TAP device and /30 pair allocated from a process-local slot
  allocator in 192.168.0.0/16 (hash-preferred slot with linear-scan
  collision resolution; a live incarnation's TAP is never clobbered, slots
  are recorded in snapshot metadata for restore), host
  MASQUERADE via the default uplink, and per-incarnation iptables chains
  enforcing `network.EgressPolicy`. Chain order: `169.254.169.254` DROP
  first, then link-local (`169.254.0.0/16`) and the **whole VM subnet
  (`192.168.0.0/16`) DROP — guests cannot reach each other or host tap
  services** — then policy denies, allows, and a final DROP when
  `DefaultAllow` is false. **Anti-spoofing:** tap-ingress packets whose
  source is not the VM's assigned /30 IP are dropped before the chain (in
  both FORWARD and INPUT); the chain jump itself also carries the source
  match. **IPv6:** disabled in-guest via sysctl AND all tap-ingress IPv6
  dropped host-side in a per-incarnation ip6tables DROP chain (host IPv6
  forwarding stays off). DNS: the base rootfs ships an empty resolv.conf;
  the guest unit points it at a public resolver, so DNS is ordinary egress
  subject to the same policy. With networking off, no NIC exists at all
  (fail-closed) and `NetworkIsolated` is declared false.
- **Snapshot GC.** Snapshots are per-incarnation timestamped dirs;
  `MaxSnapshotsPerIncarnation` (default 3) GCs oldest;
  `DeleteSnapshotsOnTerminate` optionally purges on Terminate.
- **Guest supervisor.** Exec runs through a static in-guest daemon over
  vsock (length-prefixed JSON), giving real process inventory (including
  setsid daemons), background termination, and live workspace reads —
  same semantics as the local backend.

## Consequences

- Positive: VM-class isolation is implemented and conformance-gated;
  INV-027's VM boundary exists on KVM hardware; checkpoint suspend actually
  reclaims RAM with retained epoch.
- Negative: requires KVM + (for jailer/networking) passwordless sudo on the
  host; dev/CI environments without KVM still skip all firecracker tests.
- Follow-ups: upstream the jailer `midr_el1` tolerance patch; fleet/host-agent
  wiring for firecracker (host-agent is currently typed to
  `*localbackend.Backend`; generalize to the Runtime surface); dedicated
  execution-node provisioning (cgroup limits, node-level network policy);
  cross-VM breakout suites (M11); production benchmark record.

## Compliance

- [x] Does not weaken INV-005..INV-016 or make state loss silent
- [x] Conformance tests updated/added before semantic change
- [x] No vendor-specific concepts leak into the API (Firecracker appears
  nowhere in `backendinterface` or the public schema)
