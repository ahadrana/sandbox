# ADR-0002: Durability and execution-epoch semantics

- **Status:** accepted
- **Date:** 2026-09-13
- **Deciders:** platform team

## Context

The control plane must survive its own crashes, runtime host loss, and
torn writes without silent state loss or duplicate logical work (PLAN §6,
§16 hardening review; INV-001..INV-011).

## Decision

1. **Journal + snapshot durability.** The control-plane store is an
   append-only JSON journal (`journal.jsonl`) with fsync per commit plus an
   optional compacted snapshot. A torn final journal line (crash mid-write)
   is tolerated on load. All state changes flow through one transaction
   (`Tx`) applied atomically.
2. **Transactional outbox.** Events are appended to the durable outbox in
   the same lock critical section as the state change they describe; a
   state change and its event are durable together or not at all. Consumers
   dedup by event ID; replay from cursor is loss-free.
3. **Idempotent-by-cause commit.** Workspace commits carry
   `cause_execution_id`; replayed commits with the same cause return the
   existing generation. Execution outcomes are persisted before the
   commit/finalize chain so recovery can finalize exactly once.
4. **Epoch retention only on verified continuity.** An execution epoch is
   retained across suspend/resume ONLY when a checkpoint restore verifies
   continuity (every checkpointed PID alive and still owned by the same
   incarnation — M8 STOP/CONT path). Any doubt (dead process, corrupt or
   incompatible checkpoint metadata, control-plane restart losing the
   backend payload) falls back to workspace-only recovery: epoch increment
   + `ExecutionStateReset` with explicit lost classes. Never false
   continuity (INV-009).
5. **Reconciler fencing rules.** On control-plane restart: interrupted
   sandboxes are fenced to a safe state (live-but-unverifiable runtimes go
   SUSPENDED; confirmed-lost runtimes go FAILED with an event);
   non-terminal executions are finalized from a stored outcome or failed
   explicitly — never silently completed. Placement fences are monotonic
   per sandbox; stale fences are rejected host-side.
6. **Idempotency-key discipline for clients.** Keys are scoped
   `sandboxID|key`. A client that restarts (or restores from backup) MUST
   use a fresh key stream; reusing keys replays the original execution —
   that replay is the contract working, and both the chaos harness and the
   backup/restore procedure encode it.

## Consequences

- Recovery metadata (`UncommittedStateLost`, `LostClasses`) is mandatory
  whenever volatile state was lost; the chaos suite asserts no silent loss.
- Workspace-only suspend is the universal fallback; checkpoint continuity
  is an optimization with an honesty requirement (RAM is never reported
  reclaimed under STOP/CONT).
