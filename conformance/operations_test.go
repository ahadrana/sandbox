// Production-hardening conformance (PLAN §16): backup/restore of the
// durable stores, tenant deletion, and operational metrics.
package conformance

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	credentialbroker "github.com/agent-sandbox/platform/credential-broker"
	"github.com/agent-sandbox/platform/domain"
	fakebackend "github.com/agent-sandbox/platform/runtime/fake-backend"
	"github.com/agent-sandbox/platform/workspace"
)

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Backup/restore (docs/OPERATIONS.md): the FileStore and workspace store
// are file trees — copy them, restore into a fresh manager, and continue.
func TestBackupRestoreStoreTrees(t *testing.T) {
	clock := domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	storeDir, wsDir := t.TempDir(), t.TempDir()
	store, err := sandboxmanager.OpenFileStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := workspace.OpenDurable(wsDir, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	outbox := eventservice.NewOutbox()
	rt := fakebackend.New()
	mgr := sandboxmanager.New(clock, ids, ws, rt, outbox, store, "host-1")
	d := agentdriver.New(mgr, "tenant-1", "principal-1", 55)
	sb, _ := d.CreateSandbox("task-backup")
	mustMaterialize(t, d, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{Writes: map[string]string{"keep.txt": "precious"}}); err != nil {
		t.Fatal(err)
	}

	// "Backup": copy both store trees. "Restore": open fresh instances
	// from the copies and rebuild the manager.
	backupStore, backupWS := t.TempDir(), t.TempDir()
	copyDir(t, storeDir, backupStore)
	copyDir(t, wsDir, backupWS)
	store2, err := sandboxmanager.OpenFileStore(backupStore)
	if err != nil {
		t.Fatal(err)
	}
	ws2, err := workspace.OpenDurable(backupWS, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	outbox2 := eventservice.NewOutbox()
	mgr2, err := sandboxmanager.NewFromStore(clock, ids, store2, ws2, fakebackend.New(), outbox2, "host-1")
	if err != nil {
		t.Fatal(err)
	}
	restored, err := mgr2.GetSandbox(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ws2.ReadManifest(restored.WorkspaceID, restored.WorkspaceGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if manifest["keep.txt"] != "precious" {
		t.Fatalf("committed data did not survive restore: %v", manifest)
	}
	// And the platform continues on the restored copy. The client uses a
	// fresh idempotency-key stream (new principal): reusing pre-backup keys
	// would idempotently replay pre-backup executions — that replay
	// protection is the contract working (see docs/OPERATIONS.md).
	d2 := agentdriver.New(mgr2, "tenant-1", "principal-restored", 56)
	if _, err := d2.EnsureMaterialized(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := d2.ExecSync(sb.SandboxID, domain.Operation{Writes: map[string]string{"after.txt": "continues"}}); err != nil {
		t.Fatal(err)
	}
}

// Tenant deletion: sandboxes terminated, endpoints unbound, credentials
// revoked, workspace generations GC'd, event emitted.
func TestDeleteTenant(t *testing.T) {
	s := newSystem(t, "fake")
	d := agentdriver.New(s.mgr, "tenant-doomed", "principal-1", 57)
	sb, _ := d.CreateSandbox("task-doomed")
	mustMaterialize(t, d, sb.SandboxID)
	b, err := s.mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
		Version: api.SchemaVersionV1, SandboxID: sb.SandboxID,
		TargetPort: 8080, LogicalName: "web", AuthPolicy: "bearer", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.mgr.SetQuota(domain.Quota{TenantID: "tenant-doomed", MaxLiveSandboxes: 5})

	broker, err := credentialbroker.New([]byte("ops-key"), "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, claims, err := broker.Issue("tenant-doomed", "task-doomed", []string{"read"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	s.mgr.CredentialRevoker = func(tenantID string) {
		for _, e := range broker.AuditEntries() {
			if e.Kind == "issue" && strings.Contains(e.Detail, "tenant="+tenantID) {
				broker.Revoke(e.Subject, now)
			}
		}
	}

	if err := s.mgr.DeleteTenant("tenant-doomed"); err != nil {
		t.Fatal(err)
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxTerminated {
		t.Fatalf("sandbox state = %s, want TERMINATED", got)
	}
	bindings := s.mgr.ListEndpointBindings(sb.SandboxID)
	if len(bindings) != 1 || bindings[0].State != domain.EndpointUnbound {
		t.Fatalf("binding not unbound: %+v", bindings)
	}
	if _, err := broker.Verify(token, now); err == nil {
		t.Fatal("tenant credential still valid after deletion")
	}
	consumer := eventservice.NewConsumer()
	if got := eventsOfType(consumer.Poll(s.outbox), domain.EventTenantDeleted); len(got) != 1 {
		t.Fatalf("missing TenantDeleted event: %v", got)
	}
	_ = claims
	_ = b
}

// Metrics: a workload produces sensible operational counts.
func TestManagerMetrics(t *testing.T) {
	s := newSystem(t, "fake")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 58)
	sb1, _ := d.CreateSandbox("task-m1")
	mustMaterialize(t, d, sb1.SandboxID)
	if _, err := d.ExecSync(sb1.SandboxID, domain.Operation{Writes: map[string]string{"f": "x"}}); err != nil {
		t.Fatal(err)
	}
	sb2, _ := d.CreateSandbox("task-m2")
	mustMaterialize(t, d, sb2.SandboxID)
	if err := s.mgr.Suspend(sb2.SandboxID); err != nil {
		t.Fatal(err)
	}

	snap := s.mgr.Metrics()
	if snap.SandboxesByState["SUSPENDED"] != 1 {
		t.Fatalf("suspended count wrong: %+v", snap.SandboxesByState)
	}
	live := snap.SandboxesByState["RUNNING"] + snap.SandboxesByState["QUIESCENT"] + snap.SandboxesByState["BACKGROUND_ACTIVE"]
	if live != 1 {
		t.Fatalf("live count wrong: %+v", snap.SandboxesByState)
	}
	if snap.ExecutionsByState["COMPLETED"] != 1 {
		t.Fatalf("completed executions wrong: %+v", snap.ExecutionsByState)
	}
	if snap.EventsByType["SandboxSuspended"] != 1 || snap.EventsByType["ExecutionCompleted"] != 1 {
		t.Fatalf("event counters wrong: %+v", snap.EventsByType)
	}
	if snap.PlacementFailures != 0 {
		t.Fatalf("unexpected placement failures: %+v", snap)
	}
}
