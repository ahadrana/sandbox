# Operations Guide

Covers backup/restore, tenant deletion, and upgrade/rollback for the
current single-node implementation (FileStore metadata + durable workspace
tree).

## 1. What state exists

Two durable trees, both plain files on disk:

- **Metadata store** (`workspace.OpenFileStore` / `sandbox-manager` store
  root): `journal.jsonl` (append-only event/state journal) and
  `snapshot.json` (compacted state). The journal is the source of truth;
  the snapshot is a recovery accelerator (ADR-002).
- **Workspace store** (`workspace.OpenDurable` tree): per-sandbox
  workspace generations and commit data.

Both trees are self-contained directories. There is no external database.

## 2. Backup

Quiesce writers (or accept a crash-consistent copy — the journal is
append-only with fsync, so a copied tree is always recoverable up to its
last fsynced record):

```sh
cp -a /path/to/metadata-store  /backup/metadata-store-$(date +%Y%m%d)
cp -a /path/to/workspace-tree  /backup/workspace-tree-$(date +%Y%m%d)
```

`copyDir`-style recursive copies are sufficient; no special tooling is
needed. This exact procedure is exercised by
`conformance/operations_test.go::TestBackupRestoreStoreTrees`.

## 3. Restore

1. Stop the platform process.
2. Replace the live store directories with the backup copies.
3. Reopen the stores from the restored trees (`workspace.OpenFileStore`
   and `workspace.OpenDurable` pointed at the copies), then rebuild the
   manager with `NewFromStore`.
4. On start, the reconciler replays the journal, converges any
   interrupted transitions, and drains the persisted outbox — executions
   that were in flight at backup time resume from durable state.

**Client caveat:** idempotency keys are scoped `sandboxID|key`. A client
whose key stream was derived from a per-process principal (e.g.
`idem-<principalID>-<counter>`) must reconnect with a **fresh principal**
after a restore; reusing the old key stream would replay the old
executions instead of starting new ones. This is the contract working as
designed, not a restore failure.

## 4. Tenant deletion

`SandboxManager.DeleteTenant(tenantID)` is the single entry point. It is
ordered and durable:

1. Terminates every sandbox owned by the tenant (execution cancellation,
   backend teardown).
2. Unbinds the tenant's endpoints (via the same `terminateLocked` path,
   so endpoint state stays consistent).
3. Deletes the tenant's quota record.
4. Invokes the configured `CredentialRevoker` hook so the credential
   broker revokes all credentials issued to the tenant.
5. Garbage-collects the tenant's workspace generations (`ws.GC` per
   workspace).
6. Emits a `TenantDeleted` event through the outbox with payload keys
   `sandboxes_terminated` and `workspace_generations_gced`.

Data-retention note: deletion removes live state and collectible workspace
generations. Journal records (append-only history) are retained until
snapshot compaction reclaims them; if a retention policy requires erasing
history, compact the store after deletion and verify the journal no
longer references the tenant.

## 5. Upgrade and rollback

Schema policy is additive-only (ADR-003): new event fields may be added,
existing field meanings never change, state enums are append-only.
Consumers must skip events with a higher `schema_version` than they
understand rather than failing.

Consequences for operations:

- **Rolling forward:** a new binary can always read stores written by an
  older one. No migration step exists today.
- **Rolling back:** an older binary can read stores written by a newer
  one only while all persisted records still use schema versions the old
  binary understands. In practice: restore the store trees from the
  pre-upgrade backup (§3), then start the old binary. Because journal
  records are additive, records written by the new binary after the
  backup are lost on rollback — treat rollback as a point-in-time
  restore, not an in-place downgrade.
- **Drills:** before relying on this in production, run an
  upgrade → write traffic → rollback-to-backup drill against real store
  trees and confirm the reconciler converges cleanly in both directions.

## 6. Observability

`SandboxManager.Metrics()` returns a `MetricsSnapshot`: sandboxes and
executions by state (computed live), cumulative events by type,
placement failures, and reconciler actions. These counters are the
minimum signal set for health checks and alert wiring; SLO definitions
and alert thresholds remain open PLAN §16 work.
