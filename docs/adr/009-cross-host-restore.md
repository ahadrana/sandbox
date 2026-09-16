# ADR-0009: Cross-host checkpoint restore via host-to-host pull streaming — ACCEPTED

- **Status:** accepted
- **Date:** 2026-09-16
- **Deciders:** platform team

## Context

ADR-008 routed checkpoint restore to the origin host only: checkpoint bits
are host-local artifacts and the RPC carried them by reference. The accepted
gap: a suspended sandbox whose origin host is full, drained, or whose facts
changed across a kernel upgrade cannot continuity-restore — the fleet fails
honestly and the manager falls back to workspace-only recovery (epoch bump,
`ExecutionStateReset`, lost guest RAM). That gap is the M8 economics
follow-up: host maintenance and rebalancing are normal fleet events, and
every one of them currently costs continuity for every sandbox suspended on
the affected host.

The platform facts that shape the design:

- A snapshot package is a **chain** (ADR-006): a full base plus zero or more
  diff link dirs under `<Root>/snapshots/<incarnation>/`, each link dir
  holding `meta.json`, `mem.file`, `vm.state`, `rootfs.ext4`,
  `workspace.img`. The saved VMM state also references a content-addressed
  **tools image** under `<Root>/tools/tools-<sha>.ext4`. A restore needs the
  whole chain plus that image — nothing else crosses hosts (workspace
  generations are already durable in the control-plane store and travel by
  reference through the existing assemble path).
- The host-agent RPC (ADR-005) is a JSON envelope over `POST /rpc` with a
  shared token header — no streaming. A guest RAM image is the largest
  object the platform handles (default 256 MiB, sparse diffs notwithstanding).
- Snapshot GC is aggressive by design (retention + tools-image collection
  after every `Snapshot`): a package being read by a peer host must not be
  reclaimed mid-stream.
- ADR-008's restore atomicity (pending placement, rollback-terminate,
  idempotent same-fence replay) is the settled contract any transfer must
  inherit — a failed transfer must leave nothing visible and retry clean.
- `SnapshotIncompatibleError` (P0.4/CI-4) already makes a restore on a
  facts-mismatched host a loud typed failure; the fleet's guard pre-filter
  makes such placements unreachable in the first place.

## Decision

Cross-host restore uses **host-to-host pull streaming**: the destination
host pulls the snapshot package directly from the origin host over the
host-agent RPC, then restores through the unchanged ADR-008 path.

1. **Raw blob streaming rides the same HTTP server and token auth.** The
   host-agent RPC gains two read endpoints and one op:
   `package_manifest` (JSON op: incarnation + tip dir name → ordered file
   list with sizes and sha256s, covering every chain link's five files plus
   the referenced tools image) and `GET /v1/snapshots/blob?incarnation=…&rel=…`
   (raw file content; `rel` is validated against a strict whitelist —
   `<numeric link dir>/<known filename>` or `tools/tools-<sha>.ext4` — so no
   path outside the snapshot/tools roots is servable). The third op,
   `restore_from`, carries the checkpoint plus the origin host's base URL
   and asks the receiving host to pull-then-restore. Auth is the existing
   `X-Sandbox-Token` header on every endpoint; TLS/AuthN remains the
   gateway's concern (DESIGN §6.1), unchanged from ADR-005.
2. **Integrity is end-to-end per file.** The manifest records sha256 for
   every file; for `mem.file`/`vm.state` these are the ADR-006 CI-3 hashes
   recorded at capture, so the destination verifies streamed bytes against
   the *capture-time* digest, not a digest computed at serve time. After
   landing, the destination runs the unmodified restore path, which
   re-validates every link's recorded hashes and package facts
   (`loadSnapshotChain`) — corruption or tampering anywhere in the chain is
   a typed `SnapshotIncompatibleError`, never a silent mis-restore.
3. **Transfer is staged and atomic.** The destination streams files into a
   staging dir (`<Root>/snapshots/<inc>/.xfer-<tip>/`), verifies each
   file's sha256 against the manifest as it lands, rewrites `tools_image`
   in each staged `meta.json` to the destination's tools path, then renames
   each link dir into place (same-filesystem rename is atomic; chain dirs
   are immutable by CI-1, so a link dir that already exists from a previous
   attempt is complete and is skipped). The tools image lands via
   tmp-write + rename under `<Root>/tools/`. Any failure removes the
   staging dir: no partial package is ever visible, and a retry either
   resumes past already-installed link dirs or restarts cleanly. Merged
   artifacts (`.merged-*`) are derived data and never transferred; the
   destination rebuilds them on demand.
4. **The destination rewrites `snapshot_dir` and reuses the ADR-008 restore
   unchanged.** `HostAgent.RestoreFrom` (new) performs the pull via a
   `PackageSource` interface (implemented in-process by `*HostAgent`, over
   HTTP by `rpc.Client`), points the checkpoint metadata copy at the local
   snapshot root, and calls the existing validated `Restore` — including
   its fence checks, capacity accounting, and idempotent same-fence replay.
   A replayed `restore_from` whose incarnation is already live skips the
   transfer entirely.
5. **Placement: origin preferred, guard-matching peers as failover.**
   `Fleet.Restore` keeps the ADR-008 origin fast path (no transfer — the
   bits are already local). Only when origin placement is impossible —
   host down, facts mismatch, or capacity exhausted — does the fleet place
   on the best guard-matching (`arch`, `kernel_release`, `cpu_part`)
   non-down peer with capacity and invoke `RestoreFrom(cp, source)` there,
   with the origin host as the source. The pending-placement /
   rollback-terminate / idempotent-replay machinery (ADR-008 amendment)
   wraps the whole transfer+restore: a failed transfer cleans staging on
   the destination, the fleet drops the pending placement, and the
   best-effort rollback terminate covers the lost-ACK window exactly as
   before. If the origin host is down it cannot serve the package either —
   cross-host restore then fails honestly and the manager's workspace-only
   fallback applies (INV-009). Cross-host restore rescues the
   origin-full / origin-incompatible / host-drained cases, not the
   origin-destroyed case (that needs a shared store; see alternatives).
6. **Source-side GC pinning.** A manifest request pins the incarnation's
   snapshot chain against `gcSnapshots` with a bounded lease (refreshed by
   every manifest/blob request, expiry swept lazily); while any pin is
   active, that incarnation's chain dirs — and via the existing
   meta-reference scan the tools image they name — are retained. The lease
   bounds the damage of a destination that disappears mid-transfer; the
   next lease expiry restores normal retention.
7. **Capabilities stay honest.** `SupportsRestore` semantics are updated:
   restore is routed and now works on *any* guard-matching host when the
   origin is reachable as a package source — still gated on facts match
   (P0.4 validation on the destination is the backstop), never an
   unconditional promise. Origin-destroyed remains an honest failure.

## Alternatives considered

- **Control-plane relay.** Route the bytes through the control plane
  (manager fetches from origin, pushes to destination). Rejected: it adds a
  full extra hop for the largest object in the system and turns the control
  plane — the durability brain — into a data pipe, against INV-025's
  separation of control and data planes. The control plane already holds
  the routing facts (origin host address from the host registry); it should
  direct the transfer, not carry it.
- **Shared snapshot store (NFS/object store).** Every host writes
  checkpoints to shared storage; any host restores by reference. Rejected
  for now: operationally heavier (a new stateful dependency with its own
  availability story), it changes the failure modes of *every* checkpoint
  rather than only the failover path, and it is untestable on our single
  bare-metal node — the provable topology today is two host-agent processes
  on one node with separate state dirs, which exercises exactly the pull
  path this ADR ships. A shared store remains the answer for the
  origin-destroyed case, which pull streaming cannot solve.

## Consequences

- Positive: host drains, kernel upgrades (with a guard-matching peer), and
  capacity exhaustion no longer cost suspended sandboxes their continuity;
  the epoch is preserved and guest RAM survives, now across hosts.
- Positive: transfer integrity is anchored to capture-time hashes and the
  destination runs the unmodified chain validation — the failure modes
  (corrupt link, truncated stream, tampered file) are all loud and typed.
- Positive: the transfer is invisible to the manager — `Runtime.Restore`
  either succeeds (continuity) or fails honestly (workspace-only
  fallback), exactly the ADR-008 contract.
- Negative: the origin host must be alive to serve the package;
  origin-destroyed restore still requires the shared-store follow-up.
- Negative: raw-spawn (unjailed) snapshots record absolute host paths in
  the saved VMM state, so a raw-spawn package restores only into the same
  backend `Root` layout; jailed deployments record chroot-relative paths
  and are fully portable. Cross-host restore is therefore supported for
  jailed deployments (the production configuration) and same-root raw
  layouts; anything else fails loudly at `snapshotLoad`, never silently.
- Negative: the blob endpoint moves gigabytes without TLS under the shared
  dev token — acceptable within ADR-005's dev-transport scoping, and the
  per-file sha256 verification bounds the integrity risk; confidentiality
  on the wire remains the gateway's concern.
- Follow-ups: shared snapshot store for origin-destroyed restore; transfer
  progress accounting in host heartbeats; resumable (offset-based) blob
  fetch for very large memory files.

## Compliance

- [x] Does not weaken INV-005..INV-016: the destination re-validates the
  full ADR-006 chain (CI-2..CI-5) after transfer; restore atomicity
  invariants from the ADR-008 amendment hold across the transfer window;
  every failure is a loud typed error with workspace-only fallback.
- [x] Conformance tests added before reliance: KVM-free manifest/fetch
  round-trip, hash-mismatch rejection, interrupted-transfer cleanup +
  retry, chain transfer with mutated memory, GC pinning, and fleet
  placement failover; FC_TEST-gated two-host-agent restore with a real
  microVM (guest RAM marker + epoch preserved).
- [x] No vendor-specific concepts leak into the API: the transfer is
  expressed as snapshot-package manifest + blobs; `CheckpointData` metadata
  gains no user-visible keys.
