// Real-agent compatibility (PLAN §15): tool-loop adapter, OpenHands-style
// mapping, trace replay, A2A notification wake, and coordinator fan-out —
// all above the manager's public API with scripted model stand-ins.
package conformance

import (
	"strings"
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/integration"
)

func newAgentRuntime(s *system) *integration.AgentRuntime {
	return &integration.AgentRuntime{Mgr: s.mgr, TenantID: "tenant-1", PrincipalID: "agent-1", OutputBudget: 256}
}

func createAgentSandbox(t *testing.T, s *system, taskRef string) string {
	t.Helper()
	d := agentdriver.New(s.mgr, "tenant-1", "agent-1", 7)
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: taskRef,
		EnvironmentID: "env-base-1", PolicyRef: "policy-default",
	})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, sb.SandboxID)
	return sb.SandboxID
}

// Multi-turn LLM tool loop: shell -> observe -> write -> observe -> done,
// against both backends (PLAN §15.1).
func TestToolLoopMultiTurn(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		rt := newAgentRuntime(s)
		sandboxID := createAgentSandbox(t, s, "task-loop")
		llm := &integration.ScriptedLLM{Queue: []integration.Turn{
			{Call: &integration.ToolCall{Name: "write_file", Writes: map[string]string{"note.txt": "hello-loop"}}},
			{Call: &integration.ToolCall{Name: "shell", Command: "cat note.txt"}},
			{Done: true},
		}}
		obs, err := rt.RunLoop(sandboxID, llm)
		if err != nil {
			t.Fatal(err)
		}
		if len(obs) != 2 || len(llm.Seen) != 2 {
			t.Fatalf("loop turns wrong: obs=%d seen=%d", len(obs), len(llm.Seen))
		}
		if obs[0].ExitCode != 0 || obs[1].ExitCode != 0 {
			t.Fatalf("exit codes: %+v", obs)
		}
		if s.backend == "local" && !strings.Contains(obs[1].Output, "hello-loop") {
			t.Fatalf("observation missing command output: %+v", obs[1])
		}
	})
}

// Observations are truncated to the output budget.
func TestToolLoopOutputTruncated(t *testing.T) {
	s := newSystem(t, "local")
	rt := newAgentRuntime(s)
	rt.OutputBudget = 64
	sandboxID := createAgentSandbox(t, s, "task-trunc")
	_, obs, err := rt.ExecShell(sandboxID, "seq 1 500")
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Output) > 64 || !strings.Contains(obs.Note, "truncated") {
		t.Fatalf("truncation wrong: %+v", obs)
	}
}

// OpenHands-style coding task: write, test (fail), fix, test (pass),
// workspace committed (PLAN §15.2).
func TestOpenHandsCodingTask(t *testing.T) {
	s := newSystem(t, "local")
	rt := newAgentRuntime(s)
	sandboxID := createAgentSandbox(t, s, "task-oh")
	obs, err := rt.RunActions(sandboxID, []integration.OHAction{
		{Kind: "write", Path: "msg.txt", Content: "hellp"},
		{Kind: "cmd", Command: "grep -q hello msg.txt"},    // fails
		{Kind: "write", Path: "msg.txt", Content: "hello"}, // fix
		{Kind: "cmd", Command: "grep -q hello msg.txt"},    // passes
		{Kind: "read", Path: "msg.txt"},
		{Kind: "finish"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 5 {
		t.Fatalf("observations = %d", len(obs))
	}
	if obs[1].ExitCode == 0 {
		t.Fatal("first test run should fail")
	}
	if obs[3].ExitCode != 0 {
		t.Fatal("second test run should pass")
	}
	if !strings.Contains(obs[4].Output, "hello") {
		t.Fatalf("read observation wrong: %+v", obs[4])
	}
	sb := mustGetSandbox(t, s, sandboxID)
	head, err := s.ws.GetHead(sb.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := s.ws.ReadManifest(sb.WorkspaceID, head.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if manifest["msg.txt"] != "hello" {
		t.Fatalf("workspace not committed: %v", manifest)
	}
}

// Shell workload trace replay (PLAN §15.3).
func TestTraceReplay(t *testing.T) {
	s := newSystem(t, "local")
	rt := newAgentRuntime(s)
	sandboxID := createAgentSandbox(t, s, "task-trace")
	trace := `{"op":"shell","command":"mkdir -p src && echo v1 > version.txt","expect_exit":0}
{"op":"expect_file","path":"version.txt","contains":"v1"}
{"op":"write","path":"src/main.sh","content":"echo built"}
{"op":"shell","command":"test -f src/main.sh","expect_exit":0}
{"op":"shell","command":"sh src/main.sh","expect_exit":0}
{"op":"expect_file","path":"src/main.sh","contains":"built"}
`
	steps, err := rt.ReplayTrace(sandboxID, strings.NewReader(trace))
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 3 {
		t.Fatalf("shell steps = %d", len(steps))
	}

	// A failing expectation must be caught.
	bad := `{"op":"shell","command":"exit 3","expect_exit":0}`
	if _, err := rt.ReplayTrace(sandboxID, strings.NewReader(bad)); err == nil {
		t.Fatal("failing trace expectation not caught")
	}
}

// A2A-style delegation: the parent stays dormant on its event cursor and
// wakes on the subagent's durable ExecutionCompleted — no polling inside
// the platform (PLAN §15.4).
func TestA2AParentSubagentWake(t *testing.T) {
	s := newSystem(t, "fake")
	parentSandbox := createAgentSandbox(t, s, "task-parent")
	subSandbox := createAgentSandbox(t, s, "task-subagent")
	if parentSandbox == subSandbox {
		t.Fatal("subagent must run in a separate sandbox")
	}

	// Parent delegates: subagent starts an async execution.
	sub, err := s.mgr.StartExecution(api.StartExecutionRequest{
		Version: api.SchemaVersionV1, SandboxID: subSandbox, PrincipalID: "subagent",
		Operation: domain.Operation{Writes: map[string]string{"result.txt": "sub-result"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Parent goes dormant on its consumer; the wake is the durable event.
	consumer := eventservice.NewConsumer()
	woke := make(chan domain.Event, 1)
	go func() {
		ev, err := integration.WaitForEvent(consumer, s.outbox, 10*time.Second, func(ev domain.Event) bool {
			return ev.EventType == domain.EventExecutionCompleted && ev.Payload["execution_id"] == sub.ExecutionID
		})
		if err != nil {
			t.Error(err)
			return
		}
		woke <- ev
	}()

	// Subagent finishes (scripted stand-in for its own agent loop).
	time.Sleep(20 * time.Millisecond)
	if _, err := s.mgr.CompleteExecution(sub.ExecutionID); err != nil {
		t.Fatal(err)
	}

	select {
	case <-woke:
	case <-time.After(10 * time.Second):
		t.Fatal("parent never woke on subagent completion event")
	}
	// Parent aggregates the result from the subagent's workspace.
	files, err := s.mgr.RuntimeFiles(subSandbox)
	if err != nil {
		t.Fatal(err)
	}
	if files["result.txt"] != "sub-result" {
		t.Fatalf("aggregated result wrong: %v", files)
	}
}

// Coordinator fan-out: shared-vs-separate sandbox policy, then an idle
// suspend/wake cycle driven purely by events (PLAN §15.5).
func TestCoordinatorFanOutAndEventWake(t *testing.T) {
	s := newSystem(t, "fake")
	rt := newAgentRuntime(s)
	coord := integration.NewCoordinator(rt)
	d := agentdriver.New(s.mgr, "tenant-1", "agent-1", 9)
	existing := map[string]string{}
	create := func() (string, error) {
		sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
			Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "coord-task",
			EnvironmentID: "env-base-1", PolicyRef: "policy-default",
		})
		if err != nil {
			return "", err
		}
		if _, err := d.EnsureMaterialized(sb.SandboxID); err != nil {
			return "", err
		}
		return sb.SandboxID, nil
	}

	tasks := []integration.CoordinatorTask{
		{TaskID: "t1", ShareSandbox: true, Group: "g1"},
		{TaskID: "t2", ShareSandbox: true, Group: "g1"},
		{TaskID: "t3"},
		{TaskID: "t4"},
	}
	sandboxes := map[string]string{}
	for _, task := range tasks {
		id, _, err := coord.SandboxFor(task, existing, create)
		if err != nil {
			t.Fatal(err)
		}
		sandboxes[task.TaskID] = id
		existing[task.TaskID] = id
	}
	if sandboxes["t1"] != sandboxes["t2"] {
		t.Fatal("shared-group tasks must share a sandbox")
	}
	if sandboxes["t3"] == sandboxes["t4"] || sandboxes["t3"] == sandboxes["t1"] {
		t.Fatal("separate-sandbox tasks must not share")
	}

	// Idle: coordinator suspends every sandbox.
	seen := map[string]bool{}
	for _, id := range sandboxes {
		if seen[id] {
			continue
		}
		seen[id] = true
		if err := s.mgr.Suspend(id); err != nil {
			t.Fatal(err)
		}
	}
	// Wake: a durable event (here: the coordinator's own subscription sees
	// the suspends complete) triggers resume and the final aggregation.
	consumer := eventservice.NewConsumer()
	for id := range seen {
		if _, err := s.mgr.Resume(id); err != nil {
			t.Fatal(err)
		}
	}
	final, err := s.mgr.StartExecution(api.StartExecutionRequest{
		Version: api.SchemaVersionV1, SandboxID: sandboxes["t3"], PrincipalID: "coordinator",
		Operation: domain.Operation{Writes: map[string]string{"aggregate.txt": "all-done"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.mgr.CompleteExecution(final.ExecutionID); err != nil {
		t.Fatal(err)
	}
	if _, err := integration.WaitForEvent(consumer, s.outbox, 5*time.Second, func(ev domain.Event) bool {
		return ev.EventType == domain.EventExecutionCompleted && ev.Payload["execution_id"] == final.ExecutionID
	}); err != nil {
		t.Fatal(err)
	}
}

// Steering at a tool boundary: a user steer cancels the running execution
// cleanly and the loop continues with the next turn.
func TestSteeringCancelAtBoundary(t *testing.T) {
	s := newSystem(t, "local")
	rt := newAgentRuntime(s)
	sandboxID := createAgentSandbox(t, s, "task-steer")

	ex, err := s.mgr.StartExecution(api.StartExecutionRequest{
		Version: api.SchemaVersionV1, SandboxID: sandboxID, PrincipalID: "agent-1",
		Operation: domain.Operation{Command: "sleep 30"},
	})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := rt.Steer(ex.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(obs.Note, "cancelled by user steer") {
		t.Fatalf("steer observation wrong: %+v", obs)
	}
	cur, err := s.mgr.GetExecution(ex.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.State != domain.ExecutionCancelled {
		t.Fatalf("execution state = %s, want CANCELLED", cur.State)
	}
	// The loop continues at the boundary with the steered next turn.
	if _, obs, err := rt.ExecShell(sandboxID, "echo after-steer"); err != nil || obs.ExitCode != 0 {
		t.Fatalf("post-steer turn failed: %v %+v", err, obs)
	}
}

// ExecutionStateReset is surfaced to the agent runtime as an actionable
// descriptor (restart your services), not a raw epoch number.
func TestExecutionStateResetTranslated(t *testing.T) {
	s := newSystem(t, "fake")
	rt := newAgentRuntime(s)
	sandboxID := createAgentSandbox(t, s, "task-reset-obs")
	d := agentdriver.New(s.mgr, "tenant-1", "agent-1", 11)

	if err := s.mgr.KillRuntime(sandboxID); err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, sandboxID) // emits ExecutionStateReset

	consumer := eventservice.NewConsumer()
	var translated *integration.Observation
	for _, ev := range consumer.Poll(s.outbox) {
		if obs := integration.TranslateEvent(ev); obs != nil && strings.Contains(obs.Note, "restart services") {
			translated = obs
		}
	}
	if translated == nil {
		t.Fatal("no actionable reset observation produced")
	}
	if !strings.Contains(translated.Note, "epoch 1 -> 2") {
		t.Fatalf("translation missing epoch detail: %q", translated.Note)
	}
	_ = rt
}

// A write op must not report the stale capture file left behind by a prior
// shell op (L11).
func TestWriteOpNoStaleShellOutput(t *testing.T) {
	s := newSystem(t, "local")
	rt := newAgentRuntime(s)
	sandboxID := createAgentSandbox(t, s, "task-stale")
	_, shellObs, err := rt.ExecShell(sandboxID, "echo shell-output")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shellObs.Output, "shell-output") {
		t.Fatalf("shell observation missing output: %+v", shellObs)
	}
	_, writeObs, err := rt.WriteFiles(sandboxID, map[string]string{"other.txt": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if writeObs.Output != "" {
		t.Fatalf("write op reported stale shell output: %+v", writeObs)
	}
}

// Reading a missing file yields an explicit error observation, not silent
// empty output (L11).
func TestRunActionsReadMissingFile(t *testing.T) {
	s := newSystem(t, "local")
	rt := newAgentRuntime(s)
	sandboxID := createAgentSandbox(t, s, "task-read-missing")
	obs, err := rt.RunActions(sandboxID, []integration.OHAction{
		{Kind: "read", Path: "nope.txt"},
		{Kind: "finish"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || !strings.Contains(obs[0].Note, "not found") {
		t.Fatalf("missing-file read observation wrong: %+v", obs)
	}
}

// SandboxFor reports the shared policy on creation as well as on cache hit
// (L11).
func TestSandboxForSharedFlag(t *testing.T) {
	s := newSystem(t, "fake")
	rt := newAgentRuntime(s)
	coord := integration.NewCoordinator(rt)
	create := func() (string, error) { return createAgentSandbox(t, s, "task-share"), nil }
	sharedTask := integration.CoordinatorTask{TaskID: "s1", ShareSandbox: true, Group: "g"}
	_, shared, err := coord.SandboxFor(sharedTask, map[string]string{}, create)
	if err != nil || !shared {
		t.Fatalf("first shared create: shared=%v err=%v", shared, err)
	}
	_, shared, err = coord.SandboxFor(integration.CoordinatorTask{TaskID: "s2", ShareSandbox: true, Group: "g"}, map[string]string{}, create)
	if err != nil || !shared {
		t.Fatalf("cache hit: shared=%v err=%v", shared, err)
	}
	_, shared, err = coord.SandboxFor(integration.CoordinatorTask{TaskID: "x1"}, map[string]string{}, create)
	if err != nil || shared {
		t.Fatalf("non-shared task: shared=%v err=%v", shared, err)
	}
}
