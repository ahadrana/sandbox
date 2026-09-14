// Suspend/resume and execution-checkpoint conformance (PLAN §11):
// workspace-only suspend is an explicit 10-step flow; STOP/CONT checkpoint
// suspend retains the epoch only when continuity is proven (FR-SR-005), and
// any break in continuity falls back to workspace-only reset (INV-009).
package conformance

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	"github.com/agent-sandbox/platform/domain"
)

// incarnationPids lists live PIDs carrying the incarnation marker.
func incarnationPids(incID string) []int {
	marker := "AGENT_SANDBOX_INCARNATION=" + incID
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		environ, err := os.ReadFile("/proc/" + e.Name() + "/environ")
		if err != nil || len(environ) == 0 {
			continue
		}
		for _, entry := range strings.Split(string(environ), "\x00") {
			if entry == marker {
				out = append(out, pid)
				break
			}
		}
	}
	return out
}

func procState(pid int) string {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	str := string(stat)
	i := strings.LastIndex(str, ")")
	if i < 0 {
		return ""
	}
	fields := strings.Fields(str[i+1:])
	if len(fields) < 1 {
		return ""
	}
	return fields[0]
}

func samePIDs(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[int]bool{}
	for _, p := range a {
		set[p] = true
	}
	for _, p := range b {
		if !set[p] {
			return false
		}
	}
	return true
}

// A suspended sandbox rejects new executions with an explicit state error;
// Resume is a separate call (documented admission policy: no auto-resume).
func TestSuspendRejectsNewExec(t *testing.T) {
	s := newSystem(t, "fake")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 71)
	sb, _ := d.CreateSandbox("task-suspend-admit")
	mustMaterialize(t, d, sb.SandboxID)

	if err := s.mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxSuspended {
		t.Fatalf("state = %s, want SUSPENDED", got)
	}
	if _, err := d.Exec(sb.SandboxID, domain.Operation{Command: "x"}); !errors.Is(err, domain.ErrIllegalState) {
		t.Fatalf("exec on SUSPENDED: err = %v, want ErrIllegalState", err)
	}
}

// Workspace-only suspend (backend without checkpoint capability): committed
// workspace and the lost-on-resume process inventory are recorded; resume
// rematerializes with epoch increment, startup rerun, and reset event.
func TestWorkspaceOnlySuspendResume(t *testing.T) {
	s := newIsolatedSystem(t)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 72)
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version:         api.SchemaVersionV1,
		TenantID:        "tenant-1",
		TaskRef:         "task-wsonly",
		EnvironmentID:   "env-base-1",
		PolicyRef:       "policy-default",
		StartupCommands: []string{"echo run >> startup.log"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, sb.SandboxID)

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command:         "true",
		Writes:          map[string]string{"committed.txt": "data"},
		SpawnBackground: []domain.BackgroundSpec{{Name: "sleeper", Ticks: 200}},
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	consumer := eventservice.NewConsumer()
	suspended := eventsOfType(consumer.Poll(s.outbox), domain.EventSandboxSuspended)
	if len(suspended) != 1 || suspended[0].Payload["mode"] != "workspace_only" {
		t.Fatalf("want workspace_only suspend event: %v", suspended)
	}
	lost, _ := suspended[0].Payload["lost_processes"].([]string)
	if len(lost) == 0 {
		t.Fatal("lost-on-resume process inventory not recorded")
	}

	report, err := s.mgr.Resume(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.PriorEpoch != 1 || report.NewEpoch != 2 {
		t.Fatalf("epoch %d -> %d, want 1 -> 2", report.PriorEpoch, report.NewEpoch)
	}
	fresh := consumer.Poll(s.outbox)
	if got := eventsOfType(fresh, domain.EventExecutionStateReset); len(got) != 1 {
		t.Fatalf("want one ExecutionStateReset: %v", got)
	}
	resumed := eventsOfType(fresh, domain.EventSandboxResumed)
	if len(resumed) != 1 || resumed[0].Payload["continuity"] != "workspace_only" {
		t.Fatalf("want workspace_only resume event: %v", resumed)
	}
	files, err := s.mgr.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if files["committed.txt"] != "data" {
		t.Fatalf("committed workspace not restored: %v", files)
	}
	if got := strings.Count(files["startup.log"], "run"); got != 2 {
		t.Fatalf("startup reruns = %d, want 2 (log %q)", got, files["startup.log"])
	}
}

// Checkpoint suspend SIGSTOPs every owned process; resume with proven
// continuity RETAINS the epoch, emits no ExecutionStateReset, and the same
// PID set keeps running (FR-SR-005).
func TestCheckpointSuspendResumeRetainsEpoch(t *testing.T) {
	s := newSystem(t, "local")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 73)
	sb, _ := d.CreateSandbox("task-checkpoint")
	mustMaterialize(t, d, sb.SandboxID)

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "sleep 60 & echo bg-started",
	}); err != nil {
		t.Fatal(err)
	}
	incID := *mustGetSandbox(t, s, sb.SandboxID).RuntimeIncarnationID
	pids := incarnationPids(incID)
	if len(pids) == 0 {
		t.Fatal("no background processes to checkpoint")
	}
	ramBefore, err := s.mgr.Usage(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	consumer := eventservice.NewConsumer()
	suspended := eventsOfType(consumer.Poll(s.outbox), domain.EventSandboxSuspended)
	if len(suspended) != 1 || suspended[0].Payload["mode"] != "execution_state" {
		t.Fatalf("want execution_state suspend event: %v", suspended)
	}
	if suspended[0].Payload["ram_reclaimed_bytes"] != int64(0) {
		t.Fatalf("STOP/CONT must honestly report 0 RAM reclaimed: %v", suspended[0].Payload)
	}
	for _, pid := range pids {
		if st := procState(pid); st != "T" {
			t.Fatalf("pid %d state = %q, want T (stopped)", pid, st)
		}
	}
	// STOP/CONT reclaims CPU, not RAM: the stopped processes are still
	// resident and still metered.
	ramDuring, err := s.mgr.Usage(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if ramDuring.MemoryBytes != ramBefore.MemoryBytes {
		t.Fatalf("RAM reclaimed during STOP/CONT suspend: before=%d during=%d", ramBefore.MemoryBytes, ramDuring.MemoryBytes)
	}

	report, err := s.mgr.Resume(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.NewEpoch != report.PriorEpoch {
		t.Fatalf("continuity resume changed epoch %d -> %d", report.PriorEpoch, report.NewEpoch)
	}
	if got := eventsOfType(consumer.Poll(s.outbox), domain.EventExecutionStateReset); len(got) != 0 {
		t.Fatalf("ExecutionStateReset emitted on continuity resume: %v", got)
	}
	if got := incarnationPids(incID); !samePIDs(got, pids) {
		t.Fatalf("PID set changed across checkpoint resume: %v -> %v", pids, got)
	}
	for _, pid := range pids {
		if st := procState(pid); st == "T" || st == "" {
			t.Fatalf("pid %d not running after resume (state %q)", pid, st)
		}
	}
	if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
}

// A checkpointed process dying while suspended breaks continuity: resume
// falls back to workspace-only recovery with epoch increment and reset.
func TestCheckpointDeadProcessFallback(t *testing.T) {
	s := newSystem(t, "local")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 74)
	sb, _ := d.CreateSandbox("task-deadcp")
	mustMaterialize(t, d, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "sleep 60 & echo bg-started",
		Writes:  map[string]string{"committed.txt": "data"},
	}); err != nil {
		t.Fatal(err)
	}
	incID := *mustGetSandbox(t, s, sb.SandboxID).RuntimeIncarnationID
	pids := incarnationPids(incID)
	if len(pids) == 0 {
		t.Fatal("no background processes")
	}

	if err := s.mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	for _, pid := range pids {
		syscall.Kill(pid, syscall.SIGKILL)
	}
	pollUntil(t, 5*time.Second, "checkpointed processes gone", func() bool {
		return len(incarnationPids(incID)) == 0
	})

	report, err := s.mgr.Resume(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.NewEpoch != report.PriorEpoch+1 {
		t.Fatalf("fallback must increment epoch %d -> %d", report.PriorEpoch, report.NewEpoch)
	}
	consumer := eventservice.NewConsumer()
	if got := eventsOfType(consumer.Poll(s.outbox), domain.EventExecutionStateReset); len(got) != 1 {
		t.Fatalf("want one ExecutionStateReset on fallback: %v", got)
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxRunning {
		t.Fatalf("state = %s, want RUNNING after fallback", got)
	}
	files, err := s.mgr.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if files["committed.txt"] != "data" {
		t.Fatalf("committed workspace not restored on fallback: %v", files)
	}
}

// Corrupt/incompatible checkpoint metadata (fault hook) must also fall back
// to workspace-only recovery — never false continuity (INV-009).
func TestCheckpointCorruptMetadataFallback(t *testing.T) {
	s := newSystem(t, "local")
	lb := s.localBackend(t)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 75)
	sb, _ := d.CreateSandbox("task-corruptcp")
	mustMaterialize(t, d, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "sleep 60 & echo bg"}); err != nil {
		t.Fatal(err)
	}
	if err := s.mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	lb.CorruptCheckpoint = true

	report, err := s.mgr.Resume(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.NewEpoch != report.PriorEpoch+1 {
		t.Fatalf("corrupt checkpoint must fall back with epoch increment: %d -> %d", report.PriorEpoch, report.NewEpoch)
	}
	consumer := eventservice.NewConsumer()
	if got := eventsOfType(consumer.Poll(s.outbox), domain.EventExecutionStateReset); len(got) != 1 {
		t.Fatalf("want one ExecutionStateReset: %v", got)
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxRunning {
		t.Fatalf("state = %s, want RUNNING", got)
	}
}

// Suspend/resume latency benchmark plus the RAM-reclaimed honesty report
// (expected 0 for STOP/CONT — asserted, not just logged).
func TestSuspendResumeBenchmark(t *testing.T) {
	s := newSystem(t, "local")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 76)
	sb, _ := d.CreateSandbox("task-bench")
	mustMaterialize(t, d, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "sleep 60 & echo bg"}); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if err := s.mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	suspendLatency := time.Since(start)
	start = time.Now()
	if _, err := s.mgr.Resume(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	resumeLatency := time.Since(start)

	consumer := eventservice.NewConsumer()
	suspended := eventsOfType(consumer.Poll(s.outbox), domain.EventSandboxSuspended)
	if len(suspended) != 1 {
		t.Fatalf("missing suspend event: %v", suspended)
	}
	ramReclaimed, ok := suspended[0].Payload["ram_reclaimed_bytes"].(int64)
	if !ok || ramReclaimed != 0 {
		t.Fatalf("RAM reclaimed report must be present and honestly 0 for STOP/CONT: %v", suspended[0].Payload)
	}
	t.Logf("suspend latency: %v; resume latency: %v; RAM reclaimed: %d bytes (STOP/CONT expected 0)", suspendLatency, resumeLatency, ramReclaimed)
	if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
}
