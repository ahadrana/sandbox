// Package conformance is the executable specification of the platform
// lifecycle/epoch contract (PLAN.md §4-5 gates, REQUIREMENTS §5). The suite
// runs against the fake backend, the local process backend, and — when the
// host offers KVM + Firecracker artifacts (FC_TEST=1) — the firecracker VM
// backend (ADR-0001 M6 gate, INV-026); a few scripted-fault tests are
// fake-only and a few real-process tests local-only.
package conformance

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
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

type system struct {
	mgr     *sandboxmanager.Manager
	store   *sandboxmanager.MemoryStore
	ws      *workspace.Memory
	outbox  *eventservice.Outbox
	clock   *domain.ManualClock
	ids     *domain.IDGen
	rt      sandboxmanager.Runtime
	backend string // "fake" | "local"
}

func newSystem(t *testing.T, backend string) *system {
	t.Helper()
	clock := domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	outbox := eventservice.NewOutbox()
	store := sandboxmanager.NewMemoryStore()
	var rt sandboxmanager.Runtime
	switch backend {
	case "fake":
		rt = fakebackend.New()
	case "local":
		lb, err := localbackend.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		rt = lb
	case "firecracker":
		rt = firecrackerRuntime(t)
	default:
		t.Fatalf("unknown backend %q", backend)
	}
	mgr := sandboxmanager.New(clock, ids, ws, rt, outbox, store, "host-1")
	return &system{mgr: mgr, store: store, ws: ws, outbox: outbox, clock: clock, ids: ids, rt: rt, backend: backend}
}

// fakeBackend returns the fake backend or skips the test.
func (s *system) fakeBackend(t *testing.T) *fakebackend.Backend {
	t.Helper()
	fb, ok := s.rt.(*fakebackend.Backend)
	if !ok {
		t.Skip("fake-backend-only test")
	}
	return fb
}

// localBackend returns the local backend or skips the test.
func (s *system) localBackend(t *testing.T) *localbackend.Backend {
	t.Helper()
	lb, ok := s.rt.(*localbackend.Backend)
	if !ok {
		t.Skip("local-backend-only test")
	}
	return lb
}

// runBoth runs a conformance scenario against every applicable backend:
// fake + local always, and the firecracker VM backend when the host offers
// it (FC_TEST=1, KVM, artifacts — otherwise that subtest skips with a clear
// message). Semantic differences must surface as capability declarations,
// never as weakened shared assertions (INV-026).
func runBoth(t *testing.T, fn func(t *testing.T, s *system)) {
	for _, backend := range []string{"fake", "local", "firecracker"} {
		t.Run(backend, func(t *testing.T) {
			fn(t, newSystem(t, backend))
		})
	}
}

func eventsOfType(events []domain.Event, et domain.EventType) []domain.Event {
	var out []domain.Event
	for _, ev := range events {
		if ev.EventType == et {
			out = append(out, ev)
		}
	}
	return out
}

func mustMaterialize(t *testing.T, d *agentdriver.Driver, sandboxID string) *api.RestoreReport {
	t.Helper()
	report, err := d.EnsureMaterialized(sandboxID)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	return report
}

func mustGetSandbox(t *testing.T, s *system, id string) *domain.Sandbox {
	t.Helper()
	sb, err := s.mgr.GetSandbox(id)
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	return sb
}

// pollUntil calls fn every 5ms until it returns true or the deadline passes.
func pollUntil(t *testing.T, deadline time.Duration, what string, fn func() bool) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// waitSandboxState ticks the manager until the sandbox reaches want or the
// deadline passes (deterministic on fake, real-time on local).
func waitSandboxState(t *testing.T, s *system, id string, want domain.SandboxState) {
	t.Helper()
	pollUntil(t, 10*time.Second, fmt.Sprintf("sandbox state %s", want), func() bool {
		if err := s.mgr.Tick(100 * time.Millisecond); err != nil {
			t.Fatalf("tick: %v", err)
		}
		return mustGetSandbox(t, s, id).ObservedState == want
	})
}

// 1. Basic coding loop: materialize -> write -> exec -> commit -> destroy
// runtime -> rematerialize -> committed bytes present (INV-001, INV-005).
func TestBasicCodingLoop(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 42)
		sb, err := d.CreateSandbox("task-basic")
		if err != nil {
			t.Fatal(err)
		}
		mustMaterialize(t, d, sb.SandboxID)

		content := d.RandomContent(64)
		ex, err := d.ExecSync(sb.SandboxID, domain.Operation{
			Command: "write main.go && go test ./...",
			Writes:  map[string]string{"main.go": content},
		})
		if err != nil {
			t.Fatal(err)
		}
		if ex.State != domain.ExecutionCompleted {
			t.Fatalf("execution state = %s", ex.State)
		}
		if ex.GenerationAfter == nil || *ex.GenerationAfter != 2 {
			t.Fatalf("expected generation 2 committed, got %v", ex.GenerationAfter)
		}

		if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
			t.Fatal(err)
		}
		report := mustMaterialize(t, d, sb.SandboxID)
		if report.RestoredGeneration != 2 {
			t.Fatalf("restored generation = %d, want 2", report.RestoredGeneration)
		}
		files, err := s.mgr.RuntimeFiles(sb.SandboxID)
		if err != nil {
			t.Fatal(err)
		}
		if files["main.go"] != content {
			t.Fatal("committed bytes missing after rematerialization")
		}
		if got := mustGetSandbox(t, s, sb.SandboxID).SandboxID; got != sb.SandboxID {
			t.Fatal("sandbox identity changed across runtime loss")
		}
	})
}

// 2. Multi-turn sandbox: sequential execs on one warm incarnation, epoch stable.
func TestMultiTurnSandbox(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 7)
		sb, _ := d.CreateSandbox("task-multi")
		mustMaterialize(t, d, sb.SandboxID)

		incarnations := map[string]bool{}
		for i := 0; i < 4; i++ {
			if _, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "true"}); err != nil {
				t.Fatal(err)
			}
			cur := mustGetSandbox(t, s, sb.SandboxID)
			if cur.ExecutionEpoch != 1 {
				t.Fatalf("epoch changed to %d during warm multi-turn use", cur.ExecutionEpoch)
			}
			incarnations[*cur.RuntimeIncarnationID] = true
		}
		if len(incarnations) != 1 {
			t.Fatalf("expected one incarnation across turns, got %d", len(incarnations))
		}
	})
}

// 3. Async execution completion: handle survives "client disconnect";
// completion event arrives; terminal state retrievable (INV-010, FR-EV-004).
func TestAsyncExecutionCompletion(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 11)
		sb, _ := d.CreateSandbox("task-async")
		mustMaterialize(t, d, sb.SandboxID)

		ex, err := d.Exec(sb.SandboxID, domain.Operation{Command: "true"})
		if err != nil {
			t.Fatal(err)
		}
		if ex.State != domain.ExecutionRunning {
			t.Fatalf("state = %s", ex.State)
		}
		// "client disconnects": only the durable execution ID is retained.
		execID := ex.ExecutionID

		if _, err := s.mgr.CompleteExecution(execID); err != nil {
			t.Fatal(err)
		}
		got, err := s.mgr.GetExecution(execID)
		if err != nil {
			t.Fatal(err)
		}
		if got.State != domain.ExecutionCompleted || got.ExitCode == nil || *got.ExitCode != 0 {
			t.Fatalf("terminal state wrong: %+v", got)
		}
		if got.StdoutRef == nil {
			t.Fatal("missing output refs")
		}

		consumer := eventservice.NewConsumer()
		events := consumer.Poll(s.outbox)
		if len(eventsOfType(events, domain.EventExecutionCompleted)) != 1 {
			t.Fatal("missing ExecutionCompleted event for reconnecting consumer")
		}
	})
}

// 4. Workspace-only reset: runtime destroyed, restored from committed
// generation, epoch N -> N+1, ExecutionStateReset with lost classes
// (INV-006, INV-007, INV-008).
func TestWorkspaceOnlyResetEpochIncrement(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 13)
		sb, _ := d.CreateSandbox("task-reset")
		mustMaterialize(t, d, sb.SandboxID)
		if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
			Command: "write",
			Writes:  map[string]string{"a.txt": "committed"},
		}); err != nil {
			t.Fatal(err)
		}

		if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
			t.Fatal(err)
		}
		report := mustMaterialize(t, d, sb.SandboxID)
		if report.PriorEpoch != 1 || report.NewEpoch != 2 {
			t.Fatalf("epoch %d -> %d, want 1 -> 2", report.PriorEpoch, report.NewEpoch)
		}
		if !report.UncommittedStateLost {
			t.Fatal("uncommitted loss must be explicit")
		}
		cur := mustGetSandbox(t, s, sb.SandboxID)
		if cur.ExecutionEpoch != 2 {
			t.Fatalf("sandbox epoch = %d", cur.ExecutionEpoch)
		}

		consumer := eventservice.NewConsumer()
		resets := eventsOfType(consumer.Poll(s.outbox), domain.EventExecutionStateReset)
		if len(resets) != 1 {
			t.Fatalf("expected 1 ExecutionStateReset, got %d", len(resets))
		}
		p := resets[0].Payload
		if p["prior_epoch"] != int64(1) || p["new_epoch"] != int64(2) {
			t.Fatalf("reset payload epochs wrong: %v", p)
		}
		if p["workspace_generation"] != int64(2) {
			t.Fatalf("reset reports generation %v, want 2", p["workspace_generation"])
		}
		lost, ok := p["lost_classes"].([]domain.LostStateClass)
		if !ok || len(lost) != 4 {
			t.Fatalf("lost classes wrong: %v", p["lost_classes"])
		}
		files, _ := s.mgr.RuntimeFiles(sb.SandboxID)
		if files["a.txt"] != "committed" {
			t.Fatal("committed generation not restored")
		}
	})
}

// 5. Lost ACK / idempotent launch: retry with the same key yields exactly
// one logical execution (INV-011). Fake-only: needs scripted ACK loss.
func TestLostAckIdempotentLaunch(t *testing.T) {
	s := newSystem(t, "fake")
	fb := s.fakeBackend(t)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 17)
	sb, _ := d.CreateSandbox("task-idem")
	mustMaterialize(t, d, sb.SandboxID)

	fb.Faults.LoseAcks = true
	key := d.NewKey()
	req := api.StartExecutionRequest{
		Version:        api.SchemaVersionV1,
		SandboxID:      sb.SandboxID,
		PrincipalID:    d.PrincipalID,
		IdempotencyKey: key,
		Operation:      domain.Operation{Command: "flaky launch", Writes: map[string]string{"x": "1"}},
	}
	first, err := s.mgr.StartExecution(req)
	var ackErr backendinterface.AckLostError
	if !errors.As(err, &ackErr) {
		t.Fatalf("expected lost-ack error, got %v", err)
	}
	second, err := s.mgr.StartExecution(req)
	if err != nil {
		t.Fatalf("retry after lost ack should return the existing execution, got %v", err)
	}
	if first.ExecutionID != second.ExecutionID {
		t.Fatalf("retry created new execution: %s vs %s", first.ExecutionID, second.ExecutionID)
	}
	fb.Faults.LoseAcks = false
	if got := len(s.mgr.Executions(sb.SandboxID)); got != 1 {
		t.Fatalf("expected exactly 1 execution, got %d", got)
	}
}

// 6. Multiple client attachment: two principals, attribution and separate
// execution IDs (INV-028, FR-MC-002).
func TestMultipleClientAttachment(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d1 := agentdriver.New(s.mgr, "tenant-1", "principal-A", 19)
		d2 := agentdriver.New(s.mgr, "tenant-1", "principal-B", 23)
		sb, _ := d1.CreateSandbox("task-shared")
		mustMaterialize(t, d1, sb.SandboxID)

		ex1, err := d1.ExecSync(sb.SandboxID, domain.Operation{Command: "true"})
		if err != nil {
			t.Fatal(err)
		}
		ex2, err := d2.ExecSync(sb.SandboxID, domain.Operation{Command: "true"})
		if err != nil {
			t.Fatal(err)
		}
		if ex1.ExecutionID == ex2.ExecutionID {
			t.Fatal("executions share an ID")
		}
		if ex1.PrincipalID != "principal-A" || ex2.PrincipalID != "principal-B" {
			t.Fatalf("attribution wrong: %s / %s", ex1.PrincipalID, ex2.PrincipalID)
		}
		if ex1.SandboxID != sb.SandboxID || ex2.SandboxID != sb.SandboxID {
			t.Fatal("executions not bound to the shared sandbox")
		}
	})
}

// 7. Parent + subagent on separate sandboxes: isolated workspaces
// (FR-MC-005, INV-022).
func TestParentSubagentSeparateSandboxes(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		parent := agentdriver.New(s.mgr, "tenant-1", "parent", 29)
		sub := agentdriver.New(s.mgr, "tenant-1", "subagent", 31)
		psb, _ := parent.CreateSandbox("task-parent")
		ssb, _ := sub.CreateSandbox("task-subagent")
		mustMaterialize(t, parent, psb.SandboxID)
		mustMaterialize(t, sub, ssb.SandboxID)

		if psb.WorkspaceID == ssb.WorkspaceID {
			t.Fatal("sandboxes share a workspace")
		}
		if _, err := parent.ExecSync(psb.SandboxID, domain.Operation{
			Command: "write parent secret",
			Writes:  map[string]string{"parent.txt": "p"},
		}); err != nil {
			t.Fatal(err)
		}
		files, err := s.mgr.RuntimeFiles(ssb.SandboxID)
		if err != nil {
			t.Fatal(err)
		}
		if _, leaked := files["parent.txt"]; leaked {
			t.Fatal("parent write visible in subagent workspace")
		}
	})
}

// 8. Stale epoch rejection after reset (FR-EP-004).
func TestStaleEpochRejection(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 37)
		sb, _ := d.CreateSandbox("task-epoch")
		mustMaterialize(t, d, sb.SandboxID)

		if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.mgr.Materialize(sb.SandboxID); err != nil {
			t.Fatal(err)
		}
		_, err := s.mgr.StartExecution(api.StartExecutionRequest{
			Version:                api.SchemaVersionV1,
			SandboxID:              sb.SandboxID,
			PrincipalID:            d.PrincipalID,
			IdempotencyKey:         d.NewKey(),
			Operation:              domain.Operation{Command: "talk to stale server"},
			ExpectedEpoch:          1,
			DependsOnVolatileState: true,
		})
		if !errors.Is(err, domain.ErrEpochConflict) {
			t.Fatalf("expected epoch conflict, got %v", err)
		}
		var ec *domain.EpochConflictError
		if !errors.As(err, &ec) || ec.Expected != 1 || ec.Actual != 2 {
			t.Fatalf("conflict detail wrong: %v", err)
		}
	})
}

// 9. Background-active: exec spawning a descendant completes while the
// sandbox reports BACKGROUND_ACTIVE, then QUIESCENT after exit (INV-012).
func TestBackgroundActiveThenQuiescent(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 41)
		sb, _ := d.CreateSandbox("task-bg")
		mustMaterialize(t, d, sb.SandboxID)

		ex, err := d.ExecSync(sb.SandboxID, domain.Operation{
			SpawnBackground: []domain.BackgroundSpec{{Name: "sleeper", Ticks: 2}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if ex.State != domain.ExecutionCompleted {
			t.Fatalf("execution state = %s", ex.State)
		}
		if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxBackgroundActive {
			t.Fatalf("sandbox state = %s, want BACKGROUND_ACTIVE", got)
		}
		waitSandboxState(t, s, sb.SandboxID, domain.SandboxQuiescent)
	})
}

// Illegal transitions must be rejected by the state machines.
func TestIllegalTransitionsRejected(t *testing.T) {
	if err := domain.TransitionSandbox(domain.SandboxTerminated, domain.SandboxRunning); !errors.Is(err, domain.ErrIllegalTransition) {
		t.Fatalf("TERMINATED->RUNNING: %v", err)
	}
	if err := domain.TransitionSandbox(domain.SandboxUnmaterialized, domain.SandboxRunning); !errors.Is(err, domain.ErrIllegalTransition) {
		t.Fatalf("UNMATERIALIZED->RUNNING: %v", err)
	}
	if err := domain.TransitionExecution(domain.ExecutionCompleted, domain.ExecutionRunning); !errors.Is(err, domain.ErrIllegalTransition) {
		t.Fatalf("COMPLETED->RUNNING: %v", err)
	}
	// M1: self-transitions are illegal from every state, including terminal.
	for _, st := range []domain.SandboxState{
		domain.SandboxUnmaterialized, domain.SandboxStarting, domain.SandboxRunning,
		domain.SandboxQuiescent, domain.SandboxSuspended, domain.SandboxFailed, domain.SandboxTerminated,
	} {
		if err := domain.TransitionSandbox(st, st); !errors.Is(err, domain.ErrIllegalTransition) {
			t.Fatalf("self-transition %s->%s: %v", st, st, err)
		}
	}
	for _, st := range []domain.ExecutionState{
		domain.ExecutionPending, domain.ExecutionRunning, domain.ExecutionCompleted, domain.ExecutionCancelled,
	} {
		if err := domain.TransitionExecution(st, st); !errors.Is(err, domain.ErrIllegalTransition) {
			t.Fatalf("execution self-transition %s->%s: %v", st, st, err)
		}
	}
	if err := domain.TransitionSandbox(domain.SandboxRunning, domain.SandboxQuiescent); err != nil {
		t.Fatalf("legal RUNNING->QUIESCENT rejected: %v", err)
	}
}

// M1 regression: cancelling an already-terminal execution is an idempotent
// read — it returns the terminal state without a duplicate event.
func TestCancelTerminalExecutionIdempotent(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 51)
		sb, _ := d.CreateSandbox("task-cancel-terminal")
		mustMaterialize(t, d, sb.SandboxID)
		ex, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "true"})
		if err != nil {
			t.Fatal(err)
		}
		before, _ := s.outbox.Replay(0)
		cancelEventsBefore := len(eventsOfType(before, domain.EventExecutionCancelled))
		got, err := s.mgr.CancelExecution(ex.ExecutionID)
		if err != nil {
			t.Fatalf("cancel of terminal execution errored: %v", err)
		}
		if got.State != domain.ExecutionCompleted {
			t.Fatalf("state = %s, want COMPLETED (unchanged)", got.State)
		}
		after, _ := s.outbox.Replay(0)
		if got := len(eventsOfType(after, domain.EventExecutionCancelled)); got != cancelEventsBefore {
			t.Fatalf("duplicate cancel event emitted: %d -> %d", cancelEventsBefore, got)
		}
	})
}

// Consumer dedup: replayed events with duplicate IDs are delivered once.
func TestEventConsumerDedup(t *testing.T) {
	s := newSystem(t, "fake")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 43)
	sb, _ := d.CreateSandbox("task-events")
	mustMaterialize(t, d, sb.SandboxID)

	c := eventservice.NewConsumer()
	first := c.Poll(s.outbox)
	c.Reset()
	second := c.Poll(s.outbox)
	if len(first) == 0 {
		t.Fatal("no events delivered")
	}
	if len(second) != 0 {
		t.Fatalf("duplicate delivery after reset: %d events", len(second))
	}
}

// Execution persistence: a rebuilt manager serves full terminal execution
// fields and keeps idempotency dedup (FR-AV-001, INV-010, INV-011).
func TestExecutionPersistenceAcrossManagerRestart(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 47)
		sb, _ := d.CreateSandbox("task-persist")
		mustMaterialize(t, d, sb.SandboxID)

		key := d.NewKey()
		ex, err := s.mgr.StartExecution(api.StartExecutionRequest{
			Version:        api.SchemaVersionV1,
			SandboxID:      sb.SandboxID,
			PrincipalID:    d.PrincipalID,
			IdempotencyKey: key,
			Operation:      domain.Operation{Command: "true"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.mgr.CompleteExecution(ex.ExecutionID); err != nil {
			t.Fatal(err)
		}

		// "restart": a new manager over the same store/outbox/backend.
		mgr2, err := sandboxmanager.NewFromStore(s.clock, s.ids, s.store, s.ws, s.rt, s.outbox, "host-1")
		if err != nil {
			t.Fatal(err)
		}
		got, err := mgr2.GetExecution(ex.ExecutionID)
		if err != nil {
			t.Fatalf("execution not queryable after restart: %v", err)
		}
		if got.State != domain.ExecutionCompleted || got.ExitCode == nil || *got.ExitCode != 0 {
			t.Fatalf("terminal fields lost: %+v", got)
		}
		if got.StdoutRef == nil || got.StartedAt == nil || got.CompletedAt == nil || got.PrincipalID != "principal-1" {
			t.Fatalf("execution fields incomplete after restart: %+v", got)
		}
		dup, err := mgr2.StartExecution(api.StartExecutionRequest{
			Version:        api.SchemaVersionV1,
			SandboxID:      sb.SandboxID,
			PrincipalID:    d.PrincipalID,
			IdempotencyKey: key,
			Operation:      domain.Operation{Command: "true"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if dup.ExecutionID != ex.ExecutionID {
			t.Fatalf("idempotency lost across restart: %s vs %s", dup.ExecutionID, ex.ExecutionID)
		}
		if got := len(mgr2.Executions(sb.SandboxID)); got != 1 {
			t.Fatalf("expected 1 execution after restart, got %d", got)
		}
	})
}

// --- Local-backend process-semantics tests (M2 gate) ---

// M2 gate: API execution completion and sandbox quiescence are independent
// (INV-012, FR-BG-002). Real `cmd &` descendant detected via process
// inventory.
func TestExecutionCompletionIsNotSandboxQuiescence(t *testing.T) {
	s := newSystem(t, "local")
	s.localBackend(t)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 53)
	sb, _ := d.CreateSandbox("task-gate")
	mustMaterialize(t, d, sb.SandboxID)

	ex, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "sleep 0.6 &"})
	if err != nil {
		t.Fatal(err)
	}
	if ex.State != domain.ExecutionCompleted {
		t.Fatalf("execution state = %s", ex.State)
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxBackgroundActive {
		t.Fatalf("sandbox state = %s, want BACKGROUND_ACTIVE while descendant lives", got)
	}
	if s.mgr.LiveDescendants(sb.SandboxID) == 0 {
		t.Fatal("process inventory does not see the background descendant")
	}
	waitSandboxState(t, s, sb.SandboxID, domain.SandboxQuiescent)
	if n := s.mgr.LiveDescendants(sb.SandboxID); n != 0 {
		t.Fatalf("descendants still owned after quiescence: %d", n)
	}
}

// A few hundred short execs against one warm incarnation (FR-EX-008).
func TestManyShortExecsOneIncarnation(t *testing.T) {
	s := newSystem(t, "local")
	s.localBackend(t)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 59)
	sb, _ := d.CreateSandbox("task-many")
	mustMaterialize(t, d, sb.SandboxID)

	const n = 300
	for i := 0; i < n; i++ {
		ex, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "true"})
		if err != nil {
			t.Fatalf("exec %d: %v", i, err)
		}
		if ex.State != domain.ExecutionCompleted {
			t.Fatalf("exec %d state = %s", i, ex.State)
		}
	}
	cur := mustGetSandbox(t, s, sb.SandboxID)
	if cur.ExecutionEpoch != 1 {
		t.Fatalf("epoch = %d after %d execs", cur.ExecutionEpoch, n)
	}
	if got := len(s.mgr.Executions(sb.SandboxID)); got != n {
		t.Fatalf("expected %d executions, got %d", n, got)
	}
}

// Client disconnect while the process runs; terminal result retrievable
// afterwards, including captured output (FR-EX-006, INV-010).
func TestDisconnectWhileProcessRuns(t *testing.T) {
	s := newSystem(t, "local")
	s.localBackend(t)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 61)
	sb, _ := d.CreateSandbox("task-disconnect")
	mustMaterialize(t, d, sb.SandboxID)

	ex, err := d.Exec(sb.SandboxID, domain.Operation{Command: "sleep 0.3; echo survived-disconnect"})
	if err != nil {
		t.Fatal(err)
	}
	execID := ex.ExecutionID // "client disconnects" here

	if _, err := s.mgr.CompleteExecution(execID); err != nil {
		t.Fatal(err)
	}
	got, err := s.mgr.GetExecution(execID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != domain.ExecutionCompleted || *got.ExitCode != 0 {
		t.Fatalf("terminal state wrong after disconnect: %+v", got)
	}
	data, err := os.ReadFile(strings.TrimPrefix(*got.StdoutRef, "file://"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "survived-disconnect") {
		t.Fatalf("stdout lost across disconnect: %q", data)
	}
}

// Double-fork/setsid daemon remains sandbox-owned: inventory sees it and
// terminate kills it (INV-013, FR-BG-001).
func TestSetsidDaemonStaysOwned(t *testing.T) {
	s := newSystem(t, "local")
	lb := s.localBackend(t)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 67)
	sb, _ := d.CreateSandbox("task-daemon")
	mustMaterialize(t, d, sb.SandboxID)

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "setsid sh -c 'sleep 30' < /dev/null > /dev/null 2>&1 &",
	}); err != nil {
		t.Fatal(err)
	}
	h := backendinterface.Handle{IncarnationID: *mustGetSandbox(t, s, sb.SandboxID).RuntimeIncarnationID}
	pollUntil(t, 5*time.Second, "daemon visible in inventory", func() bool {
		inv, _ := lb.ProcessInventory(h)
		return len(inv) > 0
	})
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxBackgroundActive {
		t.Fatalf("sandbox state = %s with daemon alive", got)
	}

	if err := s.mgr.Terminate(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, 5*time.Second, "daemon killed on terminate", func() bool {
		inv, _ := lb.ProcessInventory(h)
		return len(inv) == 0
	})
}

// Killing the incarnation kills the whole process tree: no orphans and the
// process group is gone (FR-BG-005).
func TestProcessTreeTermination(t *testing.T) {
	s := newSystem(t, "local")
	lb := s.localBackend(t)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 71)
	sb, _ := d.CreateSandbox("task-tree")
	mustMaterialize(t, d, sb.SandboxID)

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "sleep 30 & sleep 30 & sleep 30 &",
	}); err != nil {
		t.Fatal(err)
	}
	h := backendinterface.Handle{IncarnationID: *mustGetSandbox(t, s, sb.SandboxID).RuntimeIncarnationID}
	var pgid int
	pollUntil(t, 5*time.Second, "background tree visible", func() bool {
		inv, _ := lb.ProcessInventory(h)
		if len(inv) >= 3 {
			pgid = inv[0].PGID
			return true
		}
		return false
	})

	if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, 5*time.Second, "inventory empty after kill", func() bool {
		inv, _ := lb.ProcessInventory(h)
		return len(inv) == 0
	})
	pollUntil(t, 5*time.Second, "process group gone", func() bool {
		if err := syscall.Kill(-pgid, 0); err == syscall.ESRCH {
			return true
		}
		// Tolerate unreaped zombies still holding the group.
		inv, _ := lb.ProcessInventory(h)
		return len(inv) == 0 && !pgidHasLiveMember(pgid)
	})
}

// pgidHasLiveMember reports whether any non-zombie process belongs to pgid.
func pgidHasLiveMember(pgid int) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		pid, err := atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		str := string(stat)
		i := strings.LastIndex(str, ")")
		if i < 0 {
			continue
		}
		fields := strings.Fields(str[i+1:])
		if len(fields) < 3 {
			continue
		}
		p, err := atoi(fields[2])
		if err != nil || p != pgid {
			continue
		}
		if fields[0] != "Z" {
			return true
		}
	}
	return false
}

func atoi(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// Concurrent callers on one sandbox: all results correctly attributed
// (FR-MC-001..003).
func TestConcurrentCallers(t *testing.T) {
	s := newSystem(t, "local")
	s.localBackend(t)
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-conc", EnvironmentID: "env-base-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.mgr.Materialize(sb.SandboxID); err != nil {
		t.Fatal(err)
	}

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	ids := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := agentdriver.New(s.mgr, "tenant-1", fmt.Sprintf("principal-%d", i), int64(100+i))
			ex, err := d.Exec(sb.SandboxID, domain.Operation{Command: fmt.Sprintf("echo caller-%d", i)})
			if err != nil {
				errs <- err
				return
			}
			if _, err := s.mgr.CompleteExecution(ex.ExecutionID); err != nil {
				errs <- err
				return
			}
			ids <- ex.ExecutionID
		}(i)
	}
	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for id := range ids {
		seen[id] = true
	}
	if len(seen) != n {
		t.Fatalf("expected %d distinct executions, got %d", n, len(seen))
	}
	for _, ex := range s.mgr.Executions(sb.SandboxID) {
		if ex.State != domain.ExecutionCompleted {
			t.Fatalf("execution %s state = %s", ex.ExecutionID, ex.State)
		}
		if ex.PrincipalID == "" {
			t.Fatalf("execution %s lost attribution", ex.ExecutionID)
		}
	}
}

// Large stdout is captured to output refs; control events carry refs only
// (INV-025, FR-EV-003).
func TestLargeOutputCapturedByRef(t *testing.T) {
	s := newSystem(t, "local")
	s.localBackend(t)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 73)
	sb, _ := d.CreateSandbox("task-big")
	mustMaterialize(t, d, sb.SandboxID)

	ex, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "head -c 5000000 /dev/zero | tr '\\000' 'a'",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ex.State != domain.ExecutionCompleted {
		t.Fatalf("state = %s", ex.State)
	}
	st, err := os.Stat(strings.TrimPrefix(*ex.StdoutRef, "file://"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 5000000 {
		t.Fatalf("captured stdout = %d bytes, want 5000000", st.Size())
	}
	events, _ := s.outbox.Replay(0)
	completed := eventsOfType(events, domain.EventExecutionCompleted)
	if len(completed) != 1 {
		t.Fatal("missing ExecutionCompleted event")
	}
	ref, ok := completed[0].Payload["stdout_ref"].(string)
	if !ok || !strings.HasPrefix(ref, "file://") {
		t.Fatalf("event carries no stdout ref: %v", completed[0].Payload)
	}
	for _, ev := range events {
		for k, v := range ev.Payload {
			if str, ok := v.(string); ok && len(str) > 4096 {
				t.Fatalf("event %s payload %q embeds bulk data (%d bytes)", ev.EventType, k, len(str))
			}
		}
	}
}

// H3 regression: an execution's recorded GenerationAfter is a value copy;
// later commits must not rewrite the earlier execution's audit record.
func TestGenerationAfterIsValueCopy(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 99)
		sb, _ := d.CreateSandbox("task-gen-copy")
		mustMaterialize(t, d, sb.SandboxID)

		ex1, err := d.ExecSync(sb.SandboxID, domain.Operation{
			Command: "write a.txt",
			Writes:  map[string]string{"a.txt": "one"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if ex1.GenerationAfter == nil || *ex1.GenerationAfter != 2 {
			t.Fatalf("ex1 GenerationAfter = %v, want 2", ex1.GenerationAfter)
		}
		if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
			Command: "write b.txt",
			Writes:  map[string]string{"b.txt": "two"},
		}); err != nil {
			t.Fatal(err)
		}
		got, err := s.mgr.GetExecution(ex1.ExecutionID)
		if err != nil {
			t.Fatal(err)
		}
		if got.GenerationAfter == nil || *got.GenerationAfter != 2 {
			t.Fatalf("ex1 GenerationAfter after second commit = %v, want 2", got.GenerationAfter)
		}
	})
}

// H5 regression: runtime loss finalizes in-flight executions FAILED with an
// explicit terminal reason; no control-plane restart is needed to observe a
// terminal state, and a late CompleteExecution is a clean error.
func TestRuntimeLossFinalizesExecutions(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 77)
		sb, _ := d.CreateSandbox("task-loss-finalize")
		mustMaterialize(t, d, sb.SandboxID)
		ex, err := s.mgr.StartExecution(api.StartExecutionRequest{
			SandboxID:   sb.SandboxID,
			PrincipalID: "principal-1",
			Operation:   domain.Operation{Command: "sleep 60"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if ex.State != domain.ExecutionRunning {
			t.Fatalf("execution state = %s, want RUNNING", ex.State)
		}
		if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
			t.Fatal(err)
		}
		got, err := s.mgr.GetExecution(ex.ExecutionID)
		if err != nil {
			t.Fatal(err)
		}
		if got.State != domain.ExecutionFailed {
			t.Fatalf("execution state after runtime loss = %s, want FAILED", got.State)
		}
		if got.TerminalReason == nil || *got.TerminalReason == "" {
			t.Fatal("terminal reason not recorded")
		}
		if got.CompletedAt == nil {
			t.Fatal("CompletedAt not recorded")
		}
		if _, err := s.mgr.CompleteExecution(ex.ExecutionID); err == nil {
			t.Fatal("CompleteExecution on finalized execution should be a clean error")
		}
		// Events: ExecutionFailed emitted through the outbox.
		events, _ := s.outbox.Replay(0)
		if len(eventsOfType(events, domain.EventExecutionFailed)) == 0 {
			t.Fatal("no ExecutionFailed event emitted")
		}
	})
}

// M2 regression: ExpectedEpoch fences even when DependsOnVolatileState is
// unset — supplying an expected epoch is itself the fence request.
func TestEpochFenceWithoutVolatileFlag(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 38)
		sb, _ := d.CreateSandbox("task-epoch-fence")
		mustMaterialize(t, d, sb.SandboxID)
		if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.mgr.Materialize(sb.SandboxID); err != nil {
			t.Fatal(err)
		}
		_, err := s.mgr.StartExecution(api.StartExecutionRequest{
			Version:        api.SchemaVersionV1,
			SandboxID:      sb.SandboxID,
			PrincipalID:    d.PrincipalID,
			IdempotencyKey: d.NewKey(),
			Operation:      domain.Operation{Command: "true"},
			ExpectedEpoch:  1,
		})
		if !errors.Is(err, domain.ErrEpochConflict) {
			t.Fatalf("expected epoch conflict without volatile flag, got %v", err)
		}
	})
}

// M3 regression: cross-tenant access is denied with a typed error; an
// omitted tenant defaults to the owner (INV-028).
func TestCrossTenantAccessDenied(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 61)
		sb, _ := d.CreateSandbox("task-authz")
		mustMaterialize(t, d, sb.SandboxID)

		_, err := s.mgr.StartExecution(api.StartExecutionRequest{
			Version: api.SchemaVersionV1, SandboxID: sb.SandboxID, TenantID: "tenant-2",
			PrincipalID: "mallory", Operation: domain.Operation{Command: "true"},
		})
		var unauth *domain.UnauthorizedError
		if !errors.As(err, &unauth) || !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatalf("cross-tenant exec not denied with UnauthorizedError: %v", err)
		}
		if _, err := s.mgr.CommitWorkspace(api.CommitWorkspaceRequest{
			Version: api.SchemaVersionV1, SandboxID: sb.SandboxID, TenantID: "tenant-2",
		}); !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatalf("cross-tenant commit not denied: %v", err)
		}
		if _, err := s.mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
			Version: api.SchemaVersionV1, SandboxID: sb.SandboxID, TenantID: "tenant-2",
			TargetPort: 8080, LogicalName: "web",
		}); !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatalf("cross-tenant binding not denied: %v", err)
		}
		// Same-tenant and omitted-tenant requests still work.
		if _, err := s.mgr.StartExecution(api.StartExecutionRequest{
			Version: api.SchemaVersionV1, SandboxID: sb.SandboxID, TenantID: "tenant-1",
			PrincipalID: "principal-1", IdempotencyKey: d.NewKey(),
			Operation: domain.Operation{Command: "true"},
		}); err != nil {
			t.Fatalf("owner-tenant exec denied: %v", err)
		}
		if _, err := s.mgr.StartExecution(api.StartExecutionRequest{
			Version: api.SchemaVersionV1, SandboxID: sb.SandboxID,
			PrincipalID: "principal-1", IdempotencyKey: d.NewKey(),
			Operation: domain.Operation{Command: "true"},
		}); err != nil {
			t.Fatalf("omitted-tenant exec denied: %v", err)
		}
	})
}
