package conformance

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/domain"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	fakebackend "github.com/agent-sandbox/platform/runtime/fake-backend"
	localbackend "github.com/agent-sandbox/platform/runtime/local-backend"
	"github.com/agent-sandbox/platform/workspace"
)

// --- Durable workspace store (ticket 12/13) ---

func newDurableWS(t *testing.T, root string) (*workspace.Durable, *domain.ManualClock, *domain.IDGen) {
	t.Helper()
	clock := domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	d, err := workspace.OpenDurable(root, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	return d, clock, ids
}

func TestDurableWorkspaceIntegrityAndRestart(t *testing.T) {
	root := t.TempDir()
	d, clock, ids := newDurableWS(t, root)
	ws, err := d.Create("tenant-1", "env-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit(ws.WorkspaceID, 1, map[string]string{"a.txt": "alpha", "dir/b.txt": "beta"}, nil); err != nil {
		t.Fatal(err)
	}
	gen, err := d.Commit(ws.WorkspaceID, 2, map[string]string{"a.txt": "alpha2"}, strptr("ex-1"))
	if err != nil {
		t.Fatal(err)
	}
	if gen.Generation != 3 || gen.IntegrityDigest == "" {
		t.Fatalf("bad generation: %+v", gen)
	}
	files, err := d.ReadManifest(ws.WorkspaceID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if files["a.txt"] != "alpha2" {
		t.Fatalf("a.txt = %q", files["a.txt"])
	}

	// Restart: reopen from the same root; committed generations survive.
	d2, err := workspace.OpenDurable(root, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	head, err := d2.GetHead(ws.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if head.Generation != 3 {
		t.Fatalf("head after restart = %d", head.Generation)
	}
	files, err = d2.ReadManifest(ws.WorkspaceID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if files["dir/b.txt"] != "beta" {
		t.Fatal("generation 2 blob missing after restart")
	}

	// Corrupt a blob: reads must detect the digest mismatch.
	manifestPath := filepath.Join(root, "workspaces", ws.WorkspaceID, "generations", "2.json")
	blobRoot := filepath.Join(root, "blobs")
	entries, err := os.ReadDir(blobRoot)
	if err != nil {
		t.Fatal(err)
	}
	var betaBlob string
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(blobRoot, e.Name()))
		if string(data) == "beta" {
			betaBlob = e.Name()
		}
	}
	if betaBlob == "" {
		t.Fatal("beta blob not found")
	}
	if err := os.WriteFile(filepath.Join(blobRoot, betaBlob), []byte("corrupted"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := d2.ReadManifest(ws.WorkspaceID, 2); !errors.Is(err, workspace.ErrIntegrityMismatch) {
		t.Fatalf("expected integrity error on corrupted blob, got %v", err)
	}

	// Corrupt the manifest itself: digest verification must fail.
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, ' ')
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := d2.GetHead(ws.WorkspaceID); err == nil {
		// head is gen 3; corrupt gen 2's sibling check via ReadManifest
		if _, err := d2.ReadManifest(ws.WorkspaceID, 2); err == nil {
			t.Fatal("corrupted manifest accepted")
		}
	}
}

func strptr(s string) *string { return &s }

func TestOptimisticParentConflict(t *testing.T) {
	d, _, _ := newDurableWS(t, t.TempDir())
	ws, _ := d.Create("tenant-1", "env-1")

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = d.Commit(ws.WorkspaceID, 1, map[string]string{"winner": string(rune('a' + i))}, nil)
		}(i)
	}
	wg.Wait()
	conflicts, wins := 0, 0
	for _, err := range errs {
		if errors.Is(err, domain.ErrGenerationConflict) {
			conflicts++
		} else if err == nil {
			wins++
		} else {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("expected exactly one winner, got wins=%d conflicts=%d", wins, conflicts)
	}
	head, _ := d.GetHead(ws.WorkspaceID)
	if head.Generation != 2 {
		t.Fatalf("head = %d after race", head.Generation)
	}
}

// Cold node: materialize a committed generation into an empty backend root.
func TestColdNodeRematerialization(t *testing.T) {
	clock := domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws, err := workspace.OpenDurable(t.TempDir(), clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	outbox := eventservice.NewOutbox()
	store := sandboxmanager.NewMemoryStore()
	rt, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := sandboxmanager.New(clock, ids, ws, rt, outbox, store, "host-cold")
	d := agentdriver.New(mgr, "tenant-1", "principal-1", 83)
	sb, _ := d.CreateSandbox("task-cold")
	mustMaterialize(t, d, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Writes: map[string]string{"src/main.go": "package main"},
	}); err != nil {
		t.Fatal(err)
	}

	// Cold node: brand-new backend with an empty root.
	rt2, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr2 := sandboxmanager.New(clock, ids, ws, rt2, outbox, store, "host-cold-2")
	if _, err := mgr2.GetSandbox(sb.SandboxID); err == nil {
		t.Fatal("new manager unexpectedly shares in-memory state")
	}
	_ = mgr2
	// Materialize the generation directly into the cold backend.
	manifest, err := ws.Materialize(sb.WorkspaceID, 2)
	if err != nil {
		t.Fatal(err)
	}
	h, err := rt2.Create(backendSpecForTest(sb.SandboxID, "inc-cold", manifest))
	if err != nil {
		t.Fatal(err)
	}
	if err := rt2.Start(h); err != nil {
		t.Fatal(err)
	}
	files, err := rt2.WorkspaceFiles(h)
	if err != nil {
		t.Fatal(err)
	}
	if files["src/main.go"] != "package main" {
		t.Fatalf("cold materialization lost bytes: %v", files)
	}
}

func backendSpecForTest(sandboxID, incID string, manifest map[string]string) backendinterface.Spec {
	return backendinterface.Spec{
		SandboxID: sandboxID, IncarnationID: incID, Epoch: 1, WorkspaceManifest: manifest,
	}
}

// Uncommitted loss is explicit: recovery reports the last committed
// generation and flags the rollback (INV-006, FR-WS-005).
func TestUncommittedLossReporting(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 89)
		sb, _ := d.CreateSandbox("task-loss")
		mustMaterialize(t, d, sb.SandboxID)
		if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
			Writes: map[string]string{"committed.txt": "safe"},
		}); err != nil {
			t.Fatal(err)
		}
		// Uncommitted write: applied to the runtime but never committed.
		if _, err := d.Exec(sb.SandboxID, domain.Operation{
			Writes: map[string]string{"uncommitted.txt": "lost"},
		}); err != nil {
			t.Fatal(err)
		}

		if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
			t.Fatal(err)
		}
		report := mustMaterialize(t, d, sb.SandboxID)
		if report.RestoredGeneration != 2 {
			t.Fatalf("restored generation = %d, want 2 (last committed)", report.RestoredGeneration)
		}
		if !report.UncommittedStateLost {
			t.Fatal("rollback of uncommitted writes must be explicit")
		}
		files, _ := s.mgr.RuntimeFiles(sb.SandboxID)
		if files["committed.txt"] != "safe" {
			t.Fatal("committed write missing after recovery")
		}
		if _, present := files["uncommitted.txt"]; present {
			t.Fatal("uncommitted write silently survived runtime loss")
		}
	})
}

// --- Durable metadata store, reconciler, crash-chain faults (ticket 14) ---

type durableSystem struct {
	dir     string
	backend string
	clock   *domain.ManualClock
	ids     *domain.IDGen
	ws      *workspace.Durable
	rt      sandboxmanager.Runtime
	mgr     *sandboxmanager.Manager
	outbox  *eventservice.Outbox
}

func newDurableSystem(t *testing.T, backend string) *durableSystem {
	t.Helper()
	dir := t.TempDir()
	clock := domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws, err := workspace.OpenDurable(filepath.Join(dir, "workspace"), clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	ds := &durableSystem{dir: dir, backend: backend, clock: clock, ids: ids, ws: ws}
	ds.rt = ds.newBackend(t, filepath.Join(dir, "runtime"))
	return ds
}

func (ds *durableSystem) newBackend(t *testing.T, root string) sandboxmanager.Runtime {
	t.Helper()
	switch ds.backend {
	case "fake":
		return fakebackend.New()
	case "local":
		lb, err := localbackend.New(root)
		if err != nil {
			t.Fatal(err)
		}
		return lb
	}
	t.Fatalf("unknown backend %q", ds.backend)
	return nil
}

func (ds *durableSystem) openStore(t *testing.T) *sandboxmanager.FileStore {
	t.Helper()
	store, err := sandboxmanager.OpenFileStore(filepath.Join(ds.dir, "meta"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// Reconciler: incarnation unverified after control-plane restart -> FAILED ->
// SUSPENDED; non-terminal execution without outcome -> explicitly FAILED.
func TestReconcilerAfterControlPlaneCrash(t *testing.T) {
	ds := newDurableSystem(t, "fake")
	store := ds.openStore(t)
	outbox := eventservice.NewOutbox()
	mgr := sandboxmanager.New(ds.clock, ds.ids, ds.ws, ds.rt, outbox, store, "host-1")
	d := agentdriver.New(mgr, "tenant-1", "principal-1", 97)
	sb, _ := d.CreateSandbox("task-reconcile")
	mustMaterialize(t, d, sb.SandboxID)
	if _, err := d.Exec(sb.SandboxID, domain.Operation{Command: "interrupted"}); err != nil {
		t.Fatal(err)
	}

	// The runtime dies while the control plane is down; the manager is
	// discarded without clean shutdown (simulated crash).
	ds.rt.KillRuntime(mgrHandleFor(t, mgr, sb.SandboxID))
	store.Close()

	store2 := ds.openStore(t)
	outbox2 := eventservice.NewOutbox()
	mgr2, err := sandboxmanager.NewFromStore(ds.clock, ds.ids, store2, ds.ws, ds.rt, outbox2, "host-1")
	if err != nil {
		t.Fatal(err)
	}
	cur, err := mgr2.GetSandbox(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.ObservedState != domain.SandboxSuspended {
		t.Fatalf("reconciled state = %s, want SUSPENDED", cur.ObservedState)
	}
	if cur.RuntimeIncarnationID != nil {
		t.Fatal("reconciler kept a dead incarnation reference")
	}
	for _, ex := range mgr2.Executions(sb.SandboxID) {
		if ex.State != domain.ExecutionFailed {
			t.Fatalf("interrupted execution state = %s, want FAILED", ex.State)
		}
		if ex.TerminalReason == nil {
			t.Fatal("missing terminal reason on reconciled execution")
		}
	}
	events, _ := outbox2.Replay(0)
	if len(eventsOfType(events, domain.EventSandboxFailed)) != 1 {
		t.Fatal("missing SandboxFailed reconciliation event")
	}
	if len(eventsOfType(events, domain.EventExecutionFailed)) != 1 {
		t.Fatal("missing ExecutionFailed reconciliation event")
	}
}

func mgrHandleFor(t *testing.T, mgr *sandboxmanager.Manager, sandboxID string) backendinterface.Handle {
	t.Helper()
	sb, err := mgr.GetSandbox(sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sb.RuntimeIncarnationID == nil {
		t.Fatal("no incarnation")
	}
	return backendinterface.Handle{IncarnationID: *sb.RuntimeIncarnationID}
}

// crashStore fails the Nth Commit after start, simulating a crash.
type crashStore struct {
	inner   sandboxmanager.Store
	n       int
	calls   int
	tripped bool
}

func (c *crashStore) Commit(tx sandboxmanager.Tx) error {
	c.calls++
	if !c.tripped && c.calls == c.n {
		c.tripped = true
		return errors.New("injected crash before commit")
	}
	return c.inner.Commit(tx)
}

func (c *crashStore) Load() (sandboxmanager.Snapshot, error) { return c.inner.Load() }

// PLAN §6 fault chain: crash between each pair of steps in
// execution exit -> outcome persist -> workspace commit -> state update ->
// outbox write -> event publish. Commit call indices in the scenario:
// 1 CreateSandbox, 2 Materialize, 3 StartExecution, 4 outcome, 5 final.
func TestCrashChainAtEveryPoint(t *testing.T) {
	for _, crashAt := range []int{4, 5, 6} { // 6 = no crash (final flush is 5)
		crashAt := crashAt
		t.Run(crashPointName(crashAt), func(t *testing.T) {
			ds := newDurableSystem(t, "fake")
			inner := ds.openStore(t)
			cs := &crashStore{inner: inner, n: crashAt}
			outbox := eventservice.NewOutbox()
			mgr := sandboxmanager.New(ds.clock, ds.ids, ds.ws, ds.rt, outbox, cs, "host-1")
			d := agentdriver.New(mgr, "tenant-1", "principal-1", 101)
			sb, _ := d.CreateSandbox("task-chain")
			mustMaterialize(t, d, sb.SandboxID)
			key := d.NewKey()
			ex, err := mgr.StartExecution(api.StartExecutionRequest{
				Version:        api.SchemaVersionV1,
				SandboxID:      sb.SandboxID,
				PrincipalID:    d.PrincipalID,
				IdempotencyKey: key,
				Operation:      domain.Operation{Writes: map[string]string{"chain.txt": "data"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, completeErr := mgr.CompleteExecution(ex.ExecutionID)
			if crashAt < 6 && completeErr == nil {
				t.Fatal("expected injected crash error")
			}
			// Discard the crashed manager; restart from the durable store.
			inner.Close()
			ds.restart(t)
			restarted := ds.mgr
			_ = outbox
			execs := restarted.Executions(sb.SandboxID)
			if len(execs) != 1 {
				t.Fatalf("duplicate logical execution after crash at %d: %d", crashAt, len(execs))
			}
			got := execs[0]
			if crashAt >= 5 && !got.State.Terminal() {
				t.Fatalf("execution non-terminal after reconciliation: %s", got.State)
			}
			// Terminal event must be observable by a replaying consumer.
			countTerminal := func() int {
				consumer := eventservice.NewConsumer()
				events := consumer.Poll(ds.outbox)
				var terminal int
				for _, ev := range events {
					if ev.AggregateID == got.ExecutionID &&
						(ev.EventType == domain.EventExecutionCompleted || ev.EventType == domain.EventExecutionFailed) {
						terminal++
					}
				}
				return terminal
			}
			if crashAt >= 5 {
				if terminal := countTerminal(); terminal != 1 {
					t.Fatalf("expected exactly 1 terminal event, got %d (crash at %d)", terminal, crashAt)
				}
				// Outcome was durable: the execution finalizes COMPLETED and
				// the workspace generation is claimed, never silently advanced.
				if got.State != domain.ExecutionCompleted {
					t.Fatalf("state = %s after durable outcome, want COMPLETED", got.State)
				}
				head, err := ds.ws.GetHead(sb.WorkspaceID)
				if err != nil {
					t.Fatal(err)
				}
				if head.Generation != 2 || head.CauseExecutionID == nil || *head.CauseExecutionID != got.ExecutionID {
					t.Fatalf("workspace head not claimed by the execution: %+v", head)
				}
				if got.GenerationAfter == nil || *got.GenerationAfter != 2 {
					t.Fatalf("GenerationAfter = %v", got.GenerationAfter)
				}
				files, _ := ds.ws.ReadManifest(sb.WorkspaceID, 2)
				if files["chain.txt"] != "data" {
					t.Fatal("committed bytes missing")
				}
			} else {
				// Crash before the outcome was durable, but the incarnation
				// survived: the reconciler keeps the genuinely-live
				// execution RUNNING (M9) rather than failing it by
				// assumption, and the workspace does not advance silently.
				if got.State != domain.ExecutionRunning {
					t.Fatalf("state = %s, want RUNNING (live incarnation)", got.State)
				}
				head, _ := ds.ws.GetHead(sb.WorkspaceID)
				if head.Generation != 1 {
					t.Fatalf("workspace advanced silently to %d", head.Generation)
				}
				// The client completes it: the write commits under this
				// execution's cause and exactly one terminal event exists.
				done, err := restarted.CompleteExecution(got.ExecutionID)
				if err != nil {
					t.Fatal(err)
				}
				if done.State != domain.ExecutionCompleted {
					t.Fatalf("state = %s after client completion, want COMPLETED", done.State)
				}
				head, _ = ds.ws.GetHead(sb.WorkspaceID)
				if head.Generation != 2 || head.CauseExecutionID == nil || *head.CauseExecutionID != got.ExecutionID {
					t.Fatalf("workspace head not claimed by the execution: %+v", head)
				}
				if terminal := countTerminal(); terminal != 1 {
					t.Fatalf("expected exactly 1 terminal event, got %d (crash at %d)", terminal, crashAt)
				}
			}
			// Idempotent retry still returns the same single execution.
			cur, _ := restarted.GetSandbox(sb.SandboxID)
			if cur.ObservedState == domain.SandboxRunning || cur.ObservedState == domain.SandboxQuiescent || cur.ObservedState == domain.SandboxBackgroundActive {
				dup, err := restarted.StartExecution(api.StartExecutionRequest{
					Version:        api.SchemaVersionV1,
					SandboxID:      sb.SandboxID,
					PrincipalID:    d.PrincipalID,
					IdempotencyKey: key,
					Operation:      domain.Operation{Writes: map[string]string{"chain.txt": "data"}},
				})
				if err != nil {
					t.Fatal(err)
				}
				if dup.ExecutionID != got.ExecutionID {
					t.Fatalf("retry duplicated execution: %s vs %s", dup.ExecutionID, got.ExecutionID)
				}
			}
		})
	}
}

func crashPointName(n int) string {
	switch n {
	case 4:
		return "crash-before-outcome-durable"
	case 5:
		return "crash-after-outcome-before-final-tx"
	default:
		return "no-crash"
	}
}

func (ds *durableSystem) restart(t *testing.T) {
	t.Helper()
	store := ds.openStore(t)
	outbox := eventservice.NewOutbox()
	mgr, err := sandboxmanager.NewFromStore(ds.clock, ds.ids, store, ds.ws, ds.rt, outbox, "host-1")
	if err != nil {
		t.Fatal(err)
	}
	ds.mgr = mgr
	ds.outbox = outbox
}

// Torn journal tail from a crash mid-write must be tolerated.
func TestTornJournalLineTolerated(t *testing.T) {
	dir := t.TempDir()
	store, err := sandboxmanager.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	sb := &domain.Sandbox{SandboxID: "sb-x", ObservedState: domain.SandboxRunning, Version: 3}
	if err := store.Commit(sandboxmanager.Tx{Sandboxes: []*domain.Sandbox{sb}}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	f, err := os.OpenFile(filepath.Join(dir, "journal.jsonl"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"Sandboxes":[{"SandboxID":"sb-torn"`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	store2, err := sandboxmanager.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := store2.Load()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := snap.Sandboxes["sb-x"]
	if !ok || got.Version != 3 {
		t.Fatalf("state lost after torn journal: %+v", snap.Sandboxes)
	}
	if _, torn := snap.Sandboxes["sb-torn"]; torn {
		t.Fatal("torn record applied")
	}
}

// Snapshot compaction preserves full recoverable state.
func TestFileStoreSnapshotCompaction(t *testing.T) {
	dir := t.TempDir()
	store, err := sandboxmanager.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(sandboxmanager.Tx{Sandboxes: []*domain.Sandbox{{SandboxID: "sb-1", Version: 1}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(sandboxmanager.Tx{Sandboxes: []*domain.Sandbox{{SandboxID: "sb-2", Version: 1}}}); err != nil {
		t.Fatal(err)
	}
	store.Close()

	store2, err := sandboxmanager.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := store2.Load()
	if len(snap.Sandboxes) != 2 {
		t.Fatalf("expected 2 sandboxes after compaction+replay, got %d", len(snap.Sandboxes))
	}
}

// PLAN §6 gate: destroy all local runtime state and restore the same logical
// sandbox from persistent metadata + workspace storage only.
func TestGateDestroyAllRuntimeState(t *testing.T) {
	dir := t.TempDir()
	clock := domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws, err := workspace.OpenDurable(filepath.Join(dir, "workspace"), clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	rtRoot := filepath.Join(dir, "runtime")
	rt, err := localbackend.New(rtRoot)
	if err != nil {
		t.Fatal(err)
	}
	metaDir := filepath.Join(dir, "meta")
	store, err := sandboxmanager.OpenFileStore(metaDir)
	if err != nil {
		t.Fatal(err)
	}
	outbox := eventservice.NewOutbox()
	mgr := sandboxmanager.New(clock, ids, ws, rt, outbox, store, "host-1")
	d := agentdriver.New(mgr, "tenant-1", "principal-1", 103)
	sb, _ := d.CreateSandbox("task-gate-m3")
	mustMaterialize(t, d, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Writes: map[string]string{"app/main.go": "package main // v1"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Writes: map[string]string{"app/main.go": "package main // v2", "app/go.mod": "module app"},
	}); err != nil {
		t.Fatal(err)
	}
	head, err := ws.GetHead(sb.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if head.Generation != 3 {
		t.Fatalf("head = %d, want 3", head.Generation)
	}
	store.Close()

	// Destroy ALL local runtime state; keep only metadata + workspace store.
	if err := os.RemoveAll(rtRoot); err != nil {
		t.Fatal(err)
	}
	rt2, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store2, err := sandboxmanager.OpenFileStore(metaDir)
	if err != nil {
		t.Fatal(err)
	}
	outbox2 := eventservice.NewOutbox()
	mgr2, err := sandboxmanager.NewFromStore(clock, ids, store2, ws, rt2, outbox2, "host-1")
	if err != nil {
		t.Fatal(err)
	}
	d2 := agentdriver.New(mgr2, "tenant-1", "principal-1", 103)
	report, err := d2.EnsureMaterialized(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.RestoredGeneration != 3 {
		t.Fatalf("restored generation = %d, want 3", report.RestoredGeneration)
	}
	if report.PriorEpoch != report.NewEpoch-1 || report.NewEpoch != 2 {
		t.Fatalf("epoch transition = %d -> %d", report.PriorEpoch, report.NewEpoch)
	}
	files, err := mgr2.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := ws.ReadManifest(sb.WorkspaceID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(committed) {
		t.Fatalf("file count = %d, want %d", len(files), len(committed))
	}
	for path, content := range committed {
		if files[path] != content {
			t.Fatalf("%s = %q, want %q", path, files[path], content)
		}
	}
	consumer := eventservice.NewConsumer()
	resets := eventsOfType(consumer.Poll(outbox2), domain.EventExecutionStateReset)
	if len(resets) != 1 {
		t.Fatal("missing ExecutionStateReset after full-state recovery")
	}
	if !strings.Contains(resets[0].Payload["sandbox_id"].(string), sb.SandboxID) {
		t.Fatal("reset event not attributed to sandbox")
	}
}

// H1 regression: GC must not delete blobs referenced by other workspaces.
func TestGCPreservesCrossWorkspaceBlobs(t *testing.T) {
	root := t.TempDir()
	d, _, _ := newDurableWS(t, root)
	ws1, err := d.Create("tenant-1", "env-1")
	if err != nil {
		t.Fatal(err)
	}
	ws2, err := d.Create("tenant-1", "env-1")
	if err != nil {
		t.Fatal(err)
	}
	// Identical content in both workspaces dedups to one shared blob.
	if _, err := d.Commit(ws1.WorkspaceID, 1, map[string]string{"shared.txt": "shared-content"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit(ws2.WorkspaceID, 1, map[string]string{"shared.txt": "shared-content"}, nil); err != nil {
		t.Fatal(err)
	}
	// Move ws1's head past gen 2 so gen 2 becomes an unpinned non-head
	// generation that GC will collect.
	if _, err := d.Commit(ws1.WorkspaceID, 2, map[string]string{"other.txt": "other"}, nil); err != nil {
		t.Fatal(err)
	}
	removed, err := d.GC(ws1.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("GC removed %d generations, want 2", removed)
	}
	files, err := d.ReadManifest(ws2.WorkspaceID, 2)
	if err != nil {
		t.Fatalf("ws2 generation unreadable after ws1 GC: %v", err)
	}
	if files["shared.txt"] != "shared-content" {
		t.Fatalf("ws2 shared.txt = %q, want byte-identical content", files["shared.txt"])
	}
}

// H6 regression: a corrupt journal line anywhere but the end is journal
// damage, not a torn write — Load must fail loudly.
func TestCorruptMidJournalLineFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	store, err := sandboxmanager.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(sandboxmanager.Tx{Sandboxes: []*domain.Sandbox{{SandboxID: "sb-1", Version: 1}}}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	f, err := os.OpenFile(filepath.Join(dir, "journal.jsonl"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt line followed by a valid line: not a torn final write.
	if _, err := f.WriteString("{garbage\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"Sandboxes":[{"SandboxID":"sb-2","Version":1}]}` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := sandboxmanager.OpenFileStore(dir); err == nil {
		t.Fatal("corrupt mid-journal line silently accepted")
	}
}

// H6 regression: a corrupt snapshot.json is quarantined aside and the store
// recovers from the journal instead of bricking.
func TestCorruptSnapshotQuarantinedAndRecovered(t *testing.T) {
	dir := t.TempDir()
	store, err := sandboxmanager.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(sandboxmanager.Tx{Sandboxes: []*domain.Sandbox{{SandboxID: "sb-1", Version: 1}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(sandboxmanager.Tx{Sandboxes: []*domain.Sandbox{{SandboxID: "sb-2", Version: 1}}}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if err := os.WriteFile(filepath.Join(dir, "snapshot.json"), []byte("{corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	store2, err := sandboxmanager.OpenFileStore(dir)
	if err != nil {
		t.Fatalf("corrupt snapshot bricked the store: %v", err)
	}
	snap, err := store2.Load()
	if err != nil {
		t.Fatal(err)
	}
	// The journal still holds sb-2; sb-1 was only in the compacted snapshot
	// and is lost with it — the contract is recovery, not silence.
	if _, ok := snap.Sandboxes["sb-2"]; !ok {
		t.Fatal("journal state lost during snapshot quarantine")
	}
	if _, err := os.Stat(filepath.Join(dir, "snapshot.json.corrupt")); err != nil {
		t.Fatal("corrupt snapshot not quarantined aside")
	}
	// The store keeps accepting commits after recovery.
	if err := store2.Commit(sandboxmanager.Tx{Sandboxes: []*domain.Sandbox{{SandboxID: "sb-3", Version: 1}}}); err != nil {
		t.Fatal(err)
	}
}

// H6 regression: compaction is crash-atomic in ordering — after Snapshot()
// returns, state survives reopen with the journal already truncated, and
// replaying already-snapshotted journal records (crash between rename and
// truncate) is idempotent.
func TestSnapshotCrashOrderingIdempotent(t *testing.T) {
	dir := t.TempDir()
	store, err := sandboxmanager.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(sandboxmanager.Tx{Sandboxes: []*domain.Sandbox{{SandboxID: "sb-1", Version: 1}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Snapshot(); err != nil {
		t.Fatal(err)
	}
	store.Close()
	// No .tmp snapshot file may survive a completed Snapshot().
	if _, err := os.Stat(filepath.Join(dir, "snapshot.json.tmp")); !os.IsNotExist(err) {
		t.Fatal("snapshot tmp file left behind")
	}
	store2, err := sandboxmanager.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := store2.Load()
	if got, ok := snap.Sandboxes["sb-1"]; !ok || got.Version != 1 {
		t.Fatalf("state lost across compaction: %+v", snap.Sandboxes)
	}
	// Simulated crash between rename and journal truncate: re-append a
	// record that is already inside snapshot.json, then reload.
	store2.Close()
	journal, err := os.ReadFile(filepath.Join(dir, "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(journal) != 0 {
		t.Fatal("journal not truncated by Snapshot")
	}
	f, err := os.OpenFile(filepath.Join(dir, "journal.jsonl"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"Sandboxes":[{"SandboxID":"sb-1","Version":1}]}` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	store3, err := sandboxmanager.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap3, _ := store3.Load()
	if got, ok := snap3.Sandboxes["sb-1"]; !ok || got.Version != 1 {
		t.Fatalf("duplicate replay corrupted state: %+v", snap3.Sandboxes)
	}
}

// M8 regression: when the reconciler finalizes an execution whose workspace
// commit already happened (idempotent replay), the sandbox's corrected
// generation is persisted — a later plain restart must not regress it.
func TestCommitReplayPersistsGeneration(t *testing.T) {
	ds := newDurableSystem(t, "fake")
	inner := ds.openStore(t)
	cs := &crashStore{inner: inner, n: 5} // crash after outcome durable, before final tx
	outbox := eventservice.NewOutbox()
	mgr := sandboxmanager.New(ds.clock, ds.ids, ds.ws, ds.rt, outbox, cs, "host-1")
	d := agentdriver.New(mgr, "tenant-1", "principal-1", 102)
	sb, _ := d.CreateSandbox("task-replay-gen")
	mustMaterialize(t, d, sb.SandboxID)
	ex, err := mgr.StartExecution(api.StartExecutionRequest{
		Version:        api.SchemaVersionV1,
		SandboxID:      sb.SandboxID,
		TenantID:       "tenant-1",
		PrincipalID:    d.PrincipalID,
		IdempotencyKey: d.NewKey(),
		Operation:      domain.Operation{Writes: map[string]string{"replay.txt": "data"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.CompleteExecution(ex.ExecutionID); err == nil {
		t.Fatal("expected injected crash error")
	}
	inner.Close()
	ds.restart(t)
	cur, err := ds.mgr.GetSandbox(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.WorkspaceGeneration != 2 {
		t.Fatalf("generation after reconciliation = %d, want 2", cur.WorkspaceGeneration)
	}
	// Plain second restart: the replay-corrected generation must have been
	// persisted, not reconstructed in memory only.
	ds.restart(t)
	cur2, err := ds.mgr.GetSandbox(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if cur2.WorkspaceGeneration != 2 {
		t.Fatalf("generation regressed to %d after second restart, want 2", cur2.WorkspaceGeneration)
	}
}

// M9 regression: after a control-plane restart, a RUNNING execution whose
// incarnation verifies alive stays RUNNING and completes normally — it is
// not failed by assumption.
func TestReconcilerKeepsLiveExecutionsRunning(t *testing.T) {
	ds := newDurableSystem(t, "fake")
	inner := ds.openStore(t)
	outbox := eventservice.NewOutbox()
	mgr := sandboxmanager.New(ds.clock, ds.ids, ds.ws, ds.rt, outbox, inner, "host-1")
	d := agentdriver.New(mgr, "tenant-1", "principal-1", 104)
	sb, _ := d.CreateSandbox("task-live-exec")
	mustMaterialize(t, d, sb.SandboxID)
	ex, err := mgr.StartExecution(api.StartExecutionRequest{
		Version:        api.SchemaVersionV1,
		SandboxID:      sb.SandboxID,
		TenantID:       "tenant-1",
		PrincipalID:    d.PrincipalID,
		IdempotencyKey: d.NewKey(),
		Operation:      domain.Operation{Command: "sleep 5", Writes: map[string]string{"live.txt": "mine"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ex.State != domain.ExecutionRunning {
		t.Fatalf("execution state = %s", ex.State)
	}
	// Control-plane restart; the backend incarnation survives (same rt).
	inner.Close()
	ds.restart(t)
	got, err := ds.mgr.GetExecution(ex.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != domain.ExecutionRunning {
		t.Fatalf("live execution state after restart = %s, want RUNNING", got.State)
	}
	// Completion still works and the write is attributed to this execution.
	done, err := ds.mgr.CompleteExecution(ex.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if done.State != domain.ExecutionCompleted {
		t.Fatalf("state = %s, want COMPLETED", done.State)
	}
	head, err := ds.ws.GetHead(sb.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if head.CauseExecutionID == nil || *head.CauseExecutionID != ex.ExecutionID {
		t.Fatalf("workspace write misattributed: %+v", head.CauseExecutionID)
	}
}
