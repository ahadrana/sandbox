# ADR-0006: Incremental (diff) memory snapshots — ACCEPTED

- **Status:** accepted
- **Date:** 2026-09-15
- **Deciders:** platform team

## Context

Every `Snapshot` today writes a full guest-memory image
(`mem.file` = entire guest RAM, default 256 MiB, reflink-shared blocks
notwithstanding) plus both drive copies, even when the guest touched a few
megabytes since the last checkpoint. Checkpoint frequency is the M8
economics lever: suspend/resume cost is dominated by memory-file bytes
written at capture and merged/read at restore, so full-only snapshots cap
how often the control plane can afford to checkpoint (PLAN M8, cost per
suspended sandbox-hour).

CubeSandbox solves the same problem with host-side soft-dirty tracking
(`clear_refs` + pagemap bit 55, with a pagemap_anon fallback) layered over
their own VMM fork. Their `hypervisor/vmm/src/soft_dirty.rs` is the
reference implementation of the *strategy* (delta relative to the previous
snapshot, arm the tracker after each snapshot, coalesce dirty ranges); we
adopt the strategy, not the mechanism, because our VMM is stock
Firecracker.

Firecracker v1.17 (verified against
`docs/snapshotting/snapshot-support.md` at tag v1.17.0):

- supports `snapshot_type: "Diff"` on `PUT /snapshot/create`: the memory
  file is a **sparse file** holding only pages dirtied since the previous
  snapshot create (or VM creation), written at their guest-physical
  offsets;
- offers two dirty-page trackers: KVM dirty logging
  (`track_dirty_pages: true` in `/machine-config` at boot, or in
  `/snapshot/load` at restore — exact, small runtime cost) and a
  `mincore(2)` fallback (inexact, includes merely-accessed pages, requires
  swap off);
- **cannot restore a diff memory file directly**: `/snapshot/load`
  requires a complete memory file. Diffs must be merged host-side onto the
  base in creation order (their `snapshot-editor edit-memory rebase`);
  the microVM state file to use is the one from the *last* merged layer;
- `/snapshot/load` resets the dirty bitmap, and `track_dirty_pages` is not
  persisted in snapshots — it must be re-requested on every load that
  should support further diffs;
- marks diff snapshots "developer preview" (guest_memfd work), and notes
  dirty tracking negates most huge-page benefits (we use none);
- the memory file passed to `/snapshot/load` backs guest RAM via
  MAP_PRIVATE **for the VM's entire lifetime** and must be treated as
  immutable — so a merged memory file is a long-lived artifact, not a
  temp file.

## Decision

1. **Firecracker diff snapshots with KVM dirty-page tracking are the
   incremental checkpoint mechanism.** `Config.IncrementalSnapshots`
   (default off) enables the feature: new VMs boot with
   `track_dirty_pages: true`, restores pass `track_dirty_pages` on
   `/snapshot/load`, and `Snapshot` may emit a diff memory file instead of
   a full one. We use the KVM tracker, not the mincore fallback: our hosts
   control swap, and exact dirty sets are what make the economics work.
2. **The first checkpoint of every chain is a full snapshot (generation-0
   base).** Every snapshot dir remains self-describing (P0.4); `meta.json`
   additionally records `kind` (`"full"`/`"diff"`, empty = full for
   pre-ADR snapshots), `parent` (name of the parent snapshot dir within
   the same snapshot root), `depth` (diffs above the base; 0 for full),
   and sha256 of both `mem.file` and `vm.state` (integrity for every link
   of the chain).
3. **Restore merges the chain host-side.** Firecracker v1.17 has no
   layered restore (verified above), so `Restore` walks `parent` pointers
   to the full base — validating the P0.4 package facts *and* the recorded
   sha256 of every link — then materializes a merged memory file:
   reflink-copy the base, then apply each diff's sparse extents
   (`SEEK_DATA`/`SEEK_HOLE`) in creation order. The merged file is named
   deterministically (`.merged-<tip dir name>`) next to the chain, is
   reused across restores of the same tip (chain dirs are immutable), and
   is deliberately **not** deleted after load: it backs the restored VM's
   RAM for its lifetime. The tip's `vm.state` is used for the load, per
   Firecracker's merging rules. A restored incarnation's next checkpoint
   chains on top of the tip it was restored from (the load reset the
   dirty bitmap, so the next diff is exactly the delta since restore).
4. **Max chain depth with auto-collapse.** `Config.MaxSnapshotChainDepth`
   (default 4): when a new checkpoint would exceed the depth, `Snapshot`
   emits a new full snapshot instead (a fresh generation-0 base).
   Unbounded chains would re-inflate restore latency and merge I/O; the
   cap bounds both.
5. **Mid-chain deletion is refused, never rebased.** The snapshot GC
   computes the set of dirs referenced as any chain's `parent` and skips
   them; only unreferenced tips (or whole chains after a collapse) are
   reclaimable. Rebase-on-delete would require rewriting every descendant
   diff (read-modify-write of the whole chain under failure) for a
   bookkeeping convenience; refusal keeps every on-disk artifact
   append-only and immutable. Restore of a checkpoint whose ancestor is
   missing fails loudly during chain validation (typed error), so a
   manual out-of-band deletion is detected, never silently mis-restored.
   Merged artifacts are GC'd once their tip dir is gone and no live
   incarnation restored from them.
6. **CubeSandbox's soft-dirty pagemap approach is rejected** for this
   platform: it exists because their VMM fork lacks native dirty tracking.
   Firecracker's KVM dirty log provides the same guarantee (exact dirty
   set, reset on each snapshot create) without parsing
   `/proc/self/pagemap` per snapshot, without `CONFIG_MEM_SOFT_DIRTY`
   kernel probes, and without reimplementing range coalescing against
   guest-physical layout. Their lifecycle (base → arm tracker → delta per
   window) is exactly what Firecracker implements internally.

### Chain-integrity invariants

- **CI-1 (immutability).** A snapshot dir is write-once: after `meta.json`
  lands, no file in the dir is ever modified. Merged artifacts live
  outside the chain dirs and are derived (recomputable) data.
- **CI-2 (parent linkage).** A diff's `parent` always names an existing
  dir in the same snapshot root whose `depth` is exactly one less; chain
  walks are depth-capped and reject cycles, missing links, and depth
  discontinuities with a typed error.
- **CI-3 (integrity).** Every restore validates the recorded sha256 of
  every `mem.file` and `vm.state` in the chain before use; corruption of
  any link — including a mid-chain diff — is detected as corruption
  (`SnapshotIncompatibleError`), never silently merged.
- **CI-4 (self-description).** The P0.4 package facts (spec, version
  matrix, host facts, tools image) are recorded and validated for every
  link, so an incremental package is no less portable-checkable than a
  full one.
- **CI-5 (merge order).** Diffs apply to the base strictly in creation
  order, and the `vm.state` used is always the tip's — Firecracker's own
  rebase contract.

## Consequences

- Positive: checkpoint capture cost drops from O(guest RAM) to O(dirtied
  pages) per incremental snapshot, making frequent suspend/checkpoint
  cycles affordable (M8); restore pays a bounded merge (chain depth ≤ 4).
- Positive: chains are append-only and every link hash-verified; the
  failure modes (missing link, corrupt link, tampered link) are all loud
  and typed.
- Negative: KVM dirty logging costs a few percent of guest CPU and
  conflicts with huge pages (we use neither huge pages nor the mincore
  fallback); diff snapshots are Firecracker "developer preview".
- Negative: merged memory files add disk usage (one full-RAM file per
  restored diff tip, reclaimed by GC); restores from a diff tip keep the
  merged file for the VM's lifetime.
- Follow-ups: cross-node chain transfer (needs base-first replication and
  P1.7 guard enforcement at the manager), incremental drive state (drives
  are still full reflink copies per checkpoint), manager-visible chain
  depth accounting.

## Compliance

- [x] Does not weaken INV-005..INV-016: incremental packages are validated
  more strictly than full ones (per-link hashes), and every failure is a
  loud typed error.
- [x] Conformance tests added before reliance: chain round-trip, depth
  collapse, and mid-chain corruption detection are FC_TEST-gated
  regression tests; merge logic has KVM-free unit tests.
- [x] No vendor-specific concepts leak into the API: chain structure lives
  in snapshot metadata; `CheckpointData` carries `kind`/`parent`/`depth`
  as opaque metadata keys.
