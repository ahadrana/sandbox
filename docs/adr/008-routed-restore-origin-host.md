# ADR-0008: Routed checkpoint restore, origin-host-only — ACCEPTED

- **Status:** accepted
- **Date:** 2026-09-15
- **Deciders:** platform team

## Context

ADR-007 made endpoint traffic able to trigger a resume, but the payoff was
incomplete in any *deployed* topology: the manager's runtime there is a
`Fleet` of host agents reached over the host-agent RPC, and `Fleet.Restore`
was a stub returning `ErrUnsupported`. Every traffic-triggered resume
therefore fell back to workspace-only recovery: the execution epoch bumped,
the ADR-007 binding fence (binding epoch == sandbox epoch) stopped
matching, bindings stayed `EndpointSuspended`, and the resume-proxy's
triggering request was denied — the proxy resumed the sandbox yet still
returned 503.

The platform facts that shape the design:

- Checkpoint bits are **host-local artifacts**. A firecracker checkpoint is
  a snapshot directory on the writing host (`Metadata["snapshot_dir"]`,
  plus the chain parents under the same root); `CheckpointData` carries it
  by reference. The host-agent RPC has no blob transfer — and a RAM image
  is the largest object the platform handles.
- A reclaim-class suspend (`CheckpointReclaimsMemory`) terminates the
  incarnation after capture: the fleet erases the placement and the host
  agent scrubs its accounting record. A routed restore must therefore
  re-place, re-fence, and re-register — from the checkpoint alone.
- The manager already falls back to workspace-only recovery whenever
  `Runtime.Restore` fails (INV-009: never false continuity). An honest
  restore failure is safe.

## Decision

Routed restore is **origin-host-only** (option (a)): a checkpoint boots
exclusively on the host that wrote it. There is no cross-host transfer.

1. **Checkpoints are self-describing for routing and accounting.**
   `HostAgent.Snapshot` enriches `CheckpointData.Metadata` with the host's
   accounting facts (`sandbox_id`, `environment_id`, `memory_bytes`,
   `fence`); the manager records `origin_host` at checkpoint time (via the
   fleet's `PlacementTracker`) *before* a reclaim-class suspend terminates
   the incarnation and erases the placement.
2. **`Fleet.Restore` routes to the origin host.** A checkpoint whose
   incarnation is still live (STOP/CONT class — never terminated) resumes
   in place: no re-placement, no new fence, no extra capacity charge. A
   reclaimed incarnation is re-placed on `Metadata["origin_host"]`: the
   host must be registered and not down, the checkpoint's recorded host
   facts (`kernel_release`, `cpu_part`) must match the host's view exactly
   (a mismatched host could never boot it, ADR-001 P0.4), and the
   scheduler `Place`s on the single admissible host — re-validating
   capacity and issuing a fresh placement fence. The restored incarnation
   is registered in the fleet's placement tables under that fence.
3. **`HostAgent.Restore` re-registers the accounting.** A stale fence is
   rejected with `ErrStaleFence`; a reclaimed incarnation is charged slots
   and memory exactly once and re-enters `bySandbox`, so subsequent routed
   calls succeed and a host re-registration does not scrub the restored
   incarnation as an orphan.
4. **The RPC gains one op, `restore`**, carrying the existing
   `CheckpointData` wire type. The fleet refreshes the placement fence in a
   *copy* of the metadata (the manager's checkpoint record is shared
   state); the wire shape is otherwise unchanged.
5. **Capabilities stay honest.** `Fleet.Capabilities().SupportsRestore` is
   again the intersection of the hosts' declarations (the forced `false`
   is removed), with this ADR's scoping: restore is routed, but
   origin-host-only. The local backend now declares `SupportsRestore` —
   its STOP/CONT restore is genuine continuity (INV-009-validated SIGCONT).

Epoch handling is unchanged: `Manager.Resume` calls `Runtime.Restore` and,
on success, takes the continuity path — same incarnation, same epoch, no
`ExecutionStateReset`, ADR-007 bindings reactivate and republish. Only now
the fleet path actually succeeds.

## Alternatives considered

- **(b) Cross-host checkpoint transfer.** Ship the snapshot directory to
  the best-scored compatible host at restore time. Rejected for now: the
  RPC carries checkpoints by reference and has no streaming/framing for
  gigabyte RAM images; transfer also interacts with the incremental-chain
  layout (ADR-006: parents must travel too) and with the by-reference
  tools-image cache. This is the natural follow-up when cold-start on a
  drained host matters.
- **Any-host restore with the P0.4 typed failure as the filter.** Rely on
  the backend's snapshot-package validation to reject wrong hosts.
  Rejected as a *routing* strategy: the scheduler would place on hosts
  that can only fail, and the failure would surface late (after the
  guest-visible resume already started).

## Consequences

- Deployed traffic-triggered resume now delivers continuity: suspend
  snapshots and reclaims, the proxy's triggering request single-flights a
  resume that restores on the origin host with the epoch preserved, the
  binding reactivates, and the request returns the guest's 200.
- A suspended sandbox whose origin host is lost (or full, or whose facts
  changed across a kernel upgrade) cannot continuity-restore: the fleet
  fails honestly and the manager falls back to workspace-only recovery —
  the pre-ADR-008 behavior, never a false continuity.
- Cross-host restore remains the documented follow-up: snapshot-blob
  streaming in the host-agent RPC (with the ADR-006 chain), or a shared
  snapshot store.
- Accepted gap: placement fences are memory-only per host (pre-existing,
  see scheduler); a restore-issued fence is not persisted into the backend
  spec the way `Create` records `AGENT_SANDBOX_PLACEMENT_FENCE`, so a
  host-agent restart after a restore reverts the recoverable fence to the
  create-time one. The window requires a stale control-plane decision
  racing a host restart and is no worse than the pre-existing fence
  persistence story.
