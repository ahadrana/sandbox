# Architecture Comparison — CubeSandbox (Tencent, Apache-2.0) vs This Platform

**Date:** 2026-09-15
**Basis:** five parallel deep reviews of `CubeSandbox/` (Cubelet, CubeShim, hypervisor fork, guest-init, CubeMaster, cube-lifecycle-manager, CubeS3lvol, cubecow, CubeNet, CubeEgress, CubeProxy, CubeTemplateCenter, agent, sdk, CubeOps). License is Apache-2.0 (Tencent) with Kata/containerd derivatives — code borrowing is permitted with attribution.

## What CubeSandbox is

Kata Containers re-factored for AI-sandbox density, E2B-compatible: containerd Shim v2 (Rust) + kata-derived guest agent + a Cloud Hypervisor fork, Redis-coordinated control plane, SPDK-based S3-backed NVMe block storage, eBPF TC networking with an OpenResty L7 MITM egress proxy, and a template service producing pre-snapshotted memory images for ~60ms sandbox creation.

## Honest verdict: different products

Their sandbox *is* the VM — flat model, identity dies with the VM, pause-snapshots are the only continuity. Ours is a durable logical sandbox with workspace generations, execution epochs, and a transactional outbox (INV-001..INV-009). They optimized for E2B-compatible ephemeral compute at scale; we optimized for agent-session correctness under failure. Their README lists "Sandbox Fault Recovery" as *coming soon*; our conformance/chaos harness has no equivalent in their tree. **Where they are genuinely ahead is engineering depth in the data plane** — storage, networking, cold-start — which is exactly where we're thinnest.

## Where they're clearly stronger

1. **Networking**: eBPF per-sandbox policy in map-in-map LPM tries (O(1) updates, no iptables lock), **in-kernel DNS snooping** that learns (IP,TTL) entries from allowed queries (solves our resolve-once-staleness), **policy generations in the datapath** that RST established flows on policy change or snapshot rollback (the direct analog of our execution epochs, enforced in the datapath), L7 credential injection gated by 8 checks (SNI==Host, upstream cert verify...) with fail-silent drop + audit fingerprints.
2. **Storage**: cubecow flat-snapshot model over FICLONE reflink (O(1), crash recovery = directory scan); CubeS3lvol S3-backed NVMe with WAL discipline, dual-state committed/pending chunk maps, manifest-uploaded-last export protocol. Their code comments document invariants with unusual candor.
3. **Cold start**: templates are pre-snapshotted memory images; TAP pool pre-warming; agent delivered on a separate virtio-pmem ext4 (upgrades don't rebuild guest images); guest-ready via MMIO signal, not polling.
4. **Data plane for developers**: HTTP+ndjson exec/file/PTY to an in-guest `envd` behind an nginx router with per-sandbox hostnames and traffic tokens — language-agnostic SDKs for free.
5. **Operational seasoning**: sandboxlock TTLs sized to RPC budgets + `context.WithoutCancel`, conditional-UPDATE reconcilers, sweeper bootstrap-warmup gates, single-flight resume coalescing, `cpuid_hash`+kernel-release guards on cross-node snapshot restore.

## Where we're stronger

- Correctness machinery: workspace generations, execution epochs, transactional outbox, deterministic conformance + chaos suites. They have none of this; Redis is their source of truth, streams are capped/disposable.
- Fencing: our placement-generation CAS vs their non-expiring hostname owner-marker (admittedly weak in their own docs).
- Attack surface: no MITM CA trusted by every guest; our credential broker never terminates guest TLS. Jailer/chroot per VMM vs their seccomp-only.
- Reproducibility: one Go module, no containerd/Redis/SPDK/patched-OpenResty dependency surface.
- IPv6 fail-closed by design; theirs is IPv4-only by omission.

## What to borrow (prioritized)

**P0 — directly applicable, high value:**
1. **Policy generations in egress enforcement**: stamp a generation into our iptables chains (chain name/comment + conntrack flush on bump) so policy changes and snapshot restores invalidate established flows. Maps our epoch semantics into the datapath. (`CubeNet tap.go BumpMvmVersion`) — **DONE (Batch 1):** chain names carry `FC-EGR-<slot>-g<N>`; `Backend.SetEgressPolicy` and snapshot restore (generation persisted in snapshot metadata) bump it + flush guest conntrack; `Backend.EgressStatus` exposes it.
2. **DNS-snooping egress learning without eBPF**: run a small host-side DNS proxy per TAP; guest resolv.conf points at it; allowed-name responses install (IP,TTL) allow entries, reaped on expiry. Replaces our resolve-once-at-apply + FM4 re-resolver, and closes their DoH bypass hole. (`CubeNet cubevs.go dns_query_track`) — **DONE (Batch 1):** per-incarnation DNS proxy on the TAP host :53 (UDP+TCP), names gated via `network.EvaluateEgress`, A answers learned as /32 allows with TTL reaper; FM4 re-resolver removed. Honest limit kept: a guest hardcoding its own resolver bypasses learning (fail-closed by omission under default-deny).
3. **Agent-on-pmem delivery**: ship guest-supervisor as a separate read-only ext4 on a second virtio device mounted by guest init; upgrades decouple from rootfs builds. (`guest-init/`, ~200 lines) — **DONE (Batch 2):** one content-addressed read-only tools ext4 (`tools-<sha256>.ext4`, label `fc-tools`) per supervisor binary, attached as a third virtio-blk drive to every microVM; the injected unit mounts it (idempotent `mountpoint || mount` by label with /dev/vdb..vdd fallbacks) and runs `/opt/fc-tools/guest-supervisor`. Old tools images are never deleted (saved VMM state references them); GC is a follow-up.
4. **Self-describing snapshot packages**: snapshot dir carries the full recreate payload (workspace generation, epoch, egress policy, supervisor/kernel versions) — enables cross-node restore later; their version matrix flags stale templates. (`pause_package.go`, `snapshot/mod.rs`) — **DONE (Batch 2):** `meta.json` records spec + supervisor sha256, kernel-image sha256, firecracker `--version`, and host facts (arch, kernel release, CPU part). Restore validates every populated field and fails with a typed `SnapshotIncompatibleError` on mismatch; the recorded tools image is reused on restore even across supervisor upgrades.
5. **Atomic fail-closed iptables updates**: build scratch chain → verify with `-C` → swap. (`cube-proxy-iptables-init.sh`) — **DONE (Batch 1):** all chain installations (setup, learned-entry batches, generation swaps) build `FC-TMP-*`, verify each rule with `-C`, retarget the jumps, then delete the old chain; fault-injection test proves the old chain survives a mid-install failure with no scratch leakage.

**P1 — architectural upgrades:**
6. **Incremental memory snapshots**: Firecracker already supports dirty-page tracking; their soft-dirty (`clear_refs`+pagemap bit 55) and pagemap_anon fallback with range coalescing is the reference implementation. Big checkpoint-economics win for M8 economics. (`hypervisor/vmm/src/soft_dirty.rs`) — **DONE (Batch 3):** ADR-006. `Config.IncrementalSnapshots` boots VMs with KVM dirty-page tracking (`track_dirty_pages`); `Snapshot` emits a sparse `Diff` memory file chained to its parent (meta records `kind`/`parent`/`depth` + per-link mem/vm-state sha256), collapsing to a new full base at `MaxSnapshotChainDepth` (default 4). Restore walks and validates the chain (P0.4 facts + hashes per link), then merges host-side via `SEEK_DATA`/`SEEK_HOLE` extent copy (Firecracker v1.17 cannot load diff mem files — verified against its docs; no layered restore exists). Mid-chain deletion is refused by the GC (ancestors of any checkpoint are kept); merged artifacts are deterministic, sidecar-hashed, and GC'd when unreferenced. Their soft-dirty pagemap mechanism was rejected — Firecracker's native KVM dirty log provides the same lifecycle.
7. **Restore placement guards**: `cpuid_hash` + host kernel release must match for cross-host snapshot restore; origin-node-first preference in the scheduler. (`restoreplace/placement.go`) — **DONE (Batch 2):** `scheduler.HostView` carries host `KernelRelease`/`CPUPart` (populated by `HostAgent.View` from `runtime/hostfacts`), `Request.CheckpointGuard` carries the checkpoint's guard, and the +3 checkpoint-locality bonus only applies when facts match exactly (a mismatching host scores as no-checkpoint). Snapshot `CheckpointData.Metadata` now exposes `arch`/`kernel_release`/`cpu_part` for guard construction.
8. **HSet-snapshot + capped-stream consumer pattern** for pushing sandbox/endpoint state to a gateway tier, with a centralized key-schema package (one module owns keys, ops, payloads, ownership rules) — applies to our event-service/outbox contracts.
9. **Traffic-triggered resume**: proxy detects request-to-suspended-sandbox, single-flights a resume, then forwards — the cold-start counterpart of INV-002.
10. **WAL discipline audit** of our durable stores against their four rules: one batch in flight, ack after fsync, CRC'd batch-close, torn-tail-discard-whole; plus recovery-time-bound checkpoint interval for outbox compaction. — **DONE (Batch 2):** audited `control-plane/sandbox-manager/filestore.go` and `workspace/durable.go` (audit notes in both file headers). FileStore journal lines now carry a CRC32 prefix (mismatch = corruption; legacy plain-JSON lines still replay; corrupt-then-valid stays a loud error; torn tail discarded whole). Compaction knobs added: `FileStoreOptions{CompactAfterBytes, CompactAfterLines}` (defaults 8 MiB / 50k lines) with inline compaction in Commit; durable.go needed no code change (sha256 content addressing covers rule 3).

**P2 — cheap DX/ops wins:**
11. Guest-ready MMIO/PIO signal instead of readiness polling.
12. TAP pool pre-warming; flattened workspace-generation model (parent always the committed root) to bound chains with depth metrics; per-sandbox traffic tokens at our endpoint gateway; client-side validation in sandboxctl; jittered cache TTLs + negative-cache sentinels; credential-use audit fingerprints (`fp-<sha256[:8]>`) so audit correlates without storing secrets.
13. **Claude Code `PreToolUse`-style hook example**: transparently redirect agent Bash calls into a sandbox, fail-closed, session-scoped — a go-to-market pattern worth replicating against our API. (`examples/claude-code-integration`)

**Not borrowing:** E2B API compatibility (forces their flat model), containerd/Kata stack (dependency weight vs our single-module reproducibility), CubeS3lvol code (SPDK/DPDK commitment; adopt its protocol ideas only), Redis-as-truth (weaker than our outbox for audit/replay), their metering (there is none).

## Suggested sequencing

P0 items are independent and small (each <1 package). P1.6 (incremental snapshots) and P1.9 (traffic-resume) are the two that change platform economics and should get ADRs when scheduled.
