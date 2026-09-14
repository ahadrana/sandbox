// Policy/lease conformance: resource accounting from host counters
// (INV-016), lease enforcement thresholds and actions (FR-BG-004, INV-015),
// baseline services that never block quiescence (PLAN §10), and the
// background-wall deadline.
package conformance

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/domain"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
)

func permissivePolicy() sandboxmanager.PolicyConfig {
	return sandboxmanager.PolicyConfig{
		ProcessLimit:      256,
		MemoryLimitBytes:  1 << 30,
		WallDeadline:      24 * time.Hour,
		MaxBackgroundWall: time.Hour,
	}
}

func handleOf(t *testing.T, s *system, sandboxID string) backendinterface.Handle {
	t.Helper()
	sb := mustGetSandbox(t, s, sandboxID)
	if sb.RuntimeIncarnationID == nil {
		t.Fatal("no live incarnation")
	}
	return backendinterface.Handle{IncarnationID: *sb.RuntimeIncarnationID}
}

// CPU burned by a foreground command is metered from host counters; a
// background CPU burner left behind by the command is metered too.
func TestCPUBurnerMetered(t *testing.T) {
	s := newSystem(t, "local")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 61)
	sb, _ := d.CreateSandbox("task-cpu")
	mustMaterialize(t, d, sb.SandboxID)

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "dd if=/dev/zero bs=1M count=30 | sha256sum",
	}); err != nil {
		t.Fatal(err)
	}
	u, err := s.mgr.Usage(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if u.CPUSeconds <= 0 {
		t.Fatalf("foreground CPU not metered: %+v", u)
	}

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "yes > /dev/null & echo bg-started",
	}); err != nil {
		t.Fatal(err)
	}
	before, err := s.mgr.Usage(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	pollUntil(t, 10*time.Second, "background CPU accrual", func() bool {
		u, err := s.mgr.Usage(sb.SandboxID)
		return err == nil && u.CPUSeconds > before.CPUSeconds+0.15
	})
	if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
}

// A baseline service (declared at create time, e.g. an abandoned dev
// server) is metered but never blocks quiescence (PLAN §10).
func TestAbandonedDevServerBaseline(t *testing.T) {
	s := newSystem(t, "local")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 62)
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version:          api.SchemaVersionV1,
		TenantID:         "tenant-1",
		TaskRef:          "task-baseline",
		EnvironmentID:    "env-base-1",
		PolicyRef:        "policy-default",
		BaselineCommands: []string{"sleep 30 &"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, sb.SandboxID)

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "true"}); err != nil {
		t.Fatal(err)
	}
	waitSandboxState(t, s, sb.SandboxID, domain.SandboxQuiescent)

	u, err := s.mgr.Usage(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if u.ProcessCount < 1 {
		t.Fatalf("baseline service not metered: %+v", u)
	}
	if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
}

// Continuous BACKGROUND_ACTIVE wall time past MaxBackgroundWall raises
// ResourceLimitExceeded{background_wall} and kills the background
// descendants; the sandbox then drains to QUIESCENT.
func TestBackgroundDeadlineKills(t *testing.T) {
	s := newSystem(t, "fake")
	p := permissivePolicy()
	p.MaxBackgroundWall = 2 * time.Second
	s.mgr.SetPolicy(p)

	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 63)
	sb, _ := d.CreateSandbox("task-bgwall")
	mustMaterialize(t, d, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		SpawnBackground: []domain.BackgroundSpec{{Name: "sleeper", Ticks: 100}},
	}); err != nil {
		t.Fatal(err)
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxBackgroundActive {
		t.Fatalf("sandbox state = %s, want BACKGROUND_ACTIVE", got)
	}

	for i := 0; i < 4; i++ {
		if err := s.mgr.Tick(time.Second); err != nil {
			t.Fatal(err)
		}
	}
	consumer := eventservice.NewConsumer()
	exceeded := eventsOfType(consumer.Poll(s.outbox), domain.EventResourceLimitExceeded)
	if len(exceeded) == 0 || exceeded[0].Payload["resource"] != "background_wall" {
		t.Fatalf("missing background_wall exceeded event: %v", exceeded)
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxQuiescent {
		t.Fatalf("sandbox state = %s, want QUIESCENT after background kill", got)
	}
	if u, err := s.mgr.Usage(sb.SandboxID); err != nil || u.ProcessCount != 0 {
		t.Fatalf("background descendants survived enforcement: %+v, %v", u, err)
	}
}

// A fork-bomb equivalent (bounded process flood — a real `:|:&` bomb is
// unsafe on this shared host) trips the process limit; enforcement kills
// the flood and the sandbox survives.
func TestForkBombBoundedByProcessLimit(t *testing.T) {
	s := newSystem(t, "local")
	p := permissivePolicy()
	p.ProcessLimit = 32
	s.mgr.SetPolicy(p)

	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 64)
	sb, _ := d.CreateSandbox("task-forkbomb")
	mustMaterialize(t, d, sb.SandboxID)

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "for i in $(seq 40); do sleep 300 & done; echo spawned",
	}); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, 10*time.Second, "process-limit enforcement", func() bool {
		if err := s.mgr.Tick(100 * time.Millisecond); err != nil {
			t.Fatalf("tick: %v", err)
		}
		u, err := s.mgr.Usage(sb.SandboxID)
		return err == nil && u.ProcessCount == 0
	})

	consumer := eventservice.NewConsumer()
	exceeded := eventsOfType(consumer.Poll(s.outbox), domain.EventResourceLimitExceeded)
	if len(exceeded) == 0 || exceeded[0].Payload["resource"] != "process_count" {
		t.Fatalf("missing process_count exceeded event: %v", exceeded)
	}
	if exceeded[0].Payload["action"] != "terminate_background" {
		t.Fatalf("unexpected enforcement action: %v", exceeded[0].Payload)
	}
	waitSandboxState(t, s, sb.SandboxID, domain.SandboxQuiescent)
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got == domain.SandboxFailed {
		t.Fatal("sandbox must survive process-limit enforcement")
	}
}

// A memory hog crosses the memory limit; enforcement kills it. Requires
// python3 for a reliably-sized allocation.
func TestMemoryBombExceeded(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	s := newSystem(t, "local")
	p := permissivePolicy()
	p.MemoryLimitBytes = 64 << 20
	s.mgr.SetPolicy(p)

	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 65)
	sb, _ := d.CreateSandbox("task-membomb")
	mustMaterialize(t, d, sb.SandboxID)

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "python3 -c 'import time; x=bytearray(200*1024*1024); time.sleep(60)' & echo bg-started",
	}); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, 15*time.Second, "memory-limit enforcement", func() bool {
		if err := s.mgr.Tick(100 * time.Millisecond); err != nil {
			t.Fatalf("tick: %v", err)
		}
		u, err := s.mgr.Usage(sb.SandboxID)
		return err == nil && u.ProcessCount == 0
	})

	consumer := eventservice.NewConsumer()
	exceeded := eventsOfType(consumer.Poll(s.outbox), domain.EventResourceLimitExceeded)
	if len(exceeded) == 0 || exceeded[0].Payload["resource"] != "memory_bytes" {
		t.Fatalf("missing memory_bytes exceeded event: %v", exceeded)
	}
	waitSandboxState(t, s, sb.SandboxID, domain.SandboxQuiescent)
}

// Ten idle watchers under the process limit trip the 80% approaching
// warning but nothing is killed; pushing past 100% kills them all.
// ProcessCount accounting is asserted at each step.
func TestManyIdleWatchers(t *testing.T) {
	s := newSystem(t, "fake")
	p := permissivePolicy()
	p.ProcessLimit = 12
	s.mgr.SetPolicy(p)

	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 66)
	sb, _ := d.CreateSandbox("task-watchers")
	mustMaterialize(t, d, sb.SandboxID)

	watchers := make([]domain.BackgroundSpec, 0, 15)
	for i := 0; i < 10; i++ {
		watchers = append(watchers, domain.BackgroundSpec{Name: "watcher-" + strconv.Itoa(i), Ticks: 100})
	}
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{SpawnBackground: watchers}); err != nil {
		t.Fatal(err)
	}
	if err := s.mgr.Tick(100 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if u, err := s.mgr.Usage(sb.SandboxID); err != nil || u.ProcessCount != 10 {
		t.Fatalf("process accounting wrong: %+v, %v", u, err)
	}

	consumer := eventservice.NewConsumer()
	approaching := eventsOfType(consumer.Poll(s.outbox), domain.EventResourceLimitApproaching)
	if len(approaching) != 1 || approaching[0].Payload["resource"] != "process_count" {
		t.Fatalf("want exactly one process_count approaching event: %v", approaching)
	}
	if got := eventsOfType(consumer.Poll(s.outbox), domain.EventResourceLimitExceeded); len(got) != 0 {
		t.Fatalf("no exceeded event expected at 80%%: %v", got)
	}

	more := make([]domain.BackgroundSpec, 0, 5)
	for i := 10; i < 15; i++ {
		more = append(more, domain.BackgroundSpec{Name: "watcher-" + strconv.Itoa(i), Ticks: 100})
	}
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{SpawnBackground: more}); err != nil {
		t.Fatal(err)
	}
	if u, err := s.mgr.Usage(sb.SandboxID); err != nil || u.ProcessCount != 15 {
		t.Fatalf("process accounting wrong: %+v, %v", u, err)
	}
	if err := s.mgr.Tick(100 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	exceeded := eventsOfType(consumer.Poll(s.outbox), domain.EventResourceLimitExceeded)
	if len(exceeded) == 0 || exceeded[0].Payload["resource"] != "process_count" {
		t.Fatalf("missing process_count exceeded event: %v", exceeded)
	}
	if u, err := s.mgr.Usage(sb.SandboxID); err != nil || u.ProcessCount != 0 {
		t.Fatalf("watchers survived enforcement: %+v, %v", u, err)
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxQuiescent {
		t.Fatalf("sandbox state = %s, want QUIESCENT", got)
	}
}

// Reported usage matches the test's own read of host counters for the same
// processes (INV-016: accounting is host-side, not guest self-report).
func TestUsageMatchesHostCounters(t *testing.T) {
	s := newSystem(t, "local")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 67)
	sb, _ := d.CreateSandbox("task-counters")
	mustMaterialize(t, d, sb.SandboxID)

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "yes > /dev/null & echo bg-started",
	}); err != nil {
		t.Fatal(err)
	}
	defer s.mgr.KillRuntime(sb.SandboxID)

	incID := *mustGetSandbox(t, s, sb.SandboxID).RuntimeIncarnationID
	marker := "AGENT_SANDBOX_INCARNATION=" + incID
	pollUntil(t, 10*time.Second, "host counter match", func() bool {
		u, err := s.mgr.Usage(sb.SandboxID)
		if err != nil || u.ProcessCount != 1 {
			return false
		}
		cpu, rss, ok := readHostCounters(marker)
		if !ok {
			return false
		}
		cpuOK := u.CPUSeconds >= cpu-0.05 && u.CPUSeconds <= cpu+0.5
		rssOK := u.MemoryBytes >= rss && u.MemoryBytes <= rss+(4<<20)
		return cpuOK && rssOK && u.CPUSeconds > 0.05
	})
}

// readHostCounters sums utime+stime seconds and VmRSS bytes for the single
// process carrying the marker, directly from /proc.
func readHostCounters(marker string) (cpuSeconds float64, rssBytes int64, ok bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, 0, false
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		environ, err := os.ReadFile("/proc/" + e.Name() + "/environ")
		if err != nil || len(environ) == 0 {
			continue
		}
		found := false
		for _, entry := range strings.Split(string(environ), "\x00") {
			if entry == marker {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		stat, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		str := string(stat)
		i := strings.LastIndex(str, ")")
		if i < 0 {
			continue
		}
		fields := strings.Fields(str[i+1:])
		if len(fields) >= 13 {
			utime, _ := strconv.Atoi(fields[11])
			stime, _ := strconv.Atoi(fields[12])
			cpuSeconds += float64(utime+stime) / 100.0
		}
		status, err := os.ReadFile("/proc/" + e.Name() + "/status")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				var kb int64
				if _, err := fmtSscanfKB(line, &kb); err == nil {
					rssBytes += kb * 1024
				}
			}
		}
		_ = pid
		return cpuSeconds, rssBytes, true
	}
	return 0, 0, false
}

func fmtSscanfKB(line string, out *int64) (int, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, os.ErrInvalid
	}
	v, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, err
	}
	*out = v
	return 1, nil
}

// Scripted stats drive deterministic enforcement: exceeded fires once per
// excursion, re-arms below 80%, and fires again on the next excursion.
func TestLeaseEnforcementScripted(t *testing.T) {
	s := newSystem(t, "fake")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 68)
	sb, _ := d.CreateSandbox("task-scripted")
	mustMaterialize(t, d, sb.SandboxID)
	fb := s.fakeBackend(t)
	h := handleOf(t, s, sb.SandboxID)

	fb.ScriptStats(h, backendinterface.Stats{ProcessCount: 300, MemoryBytes: 2 << 30})
	if err := s.mgr.Tick(100 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	consumer := eventservice.NewConsumer()
	exceeded := eventsOfType(consumer.Poll(s.outbox), domain.EventResourceLimitExceeded)
	if len(exceeded) != 2 {
		t.Fatalf("want process_count+memory_bytes exceeded events, got %v", exceeded)
	}

	// Same excursion: no duplicate events.
	if err := s.mgr.Tick(100 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if got := eventsOfType(consumer.Poll(s.outbox), domain.EventResourceLimitExceeded); len(got) != 0 {
		t.Fatalf("duplicate exceeded events: %v", got)
	}

	// Drop below 80% to re-arm, then exceed again.
	fb.ScriptStats(h, backendinterface.Stats{ProcessCount: 1, MemoryBytes: 1 << 20})
	if err := s.mgr.Tick(100 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	fb.ScriptStats(h, backendinterface.Stats{ProcessCount: 300, MemoryBytes: 1 << 20})
	if err := s.mgr.Tick(100 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	exceeded = eventsOfType(consumer.Poll(s.outbox), domain.EventResourceLimitExceeded)
	if len(exceeded) != 1 || exceeded[0].Payload["resource"] != "process_count" {
		t.Fatalf("re-armed enforcement did not fire exactly once: %v", exceeded)
	}
}

// A sandbox past its wall deadline is committed, terminated, and suspended
// with an explicit reason; it can be rematerialized afterwards.
func TestWallDeadlineSuspend(t *testing.T) {
	s := newSystem(t, "fake")
	p := permissivePolicy()
	p.WallDeadline = 2 * time.Second
	s.mgr.SetPolicy(p)

	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 69)
	sb, _ := d.CreateSandbox("task-wall")
	mustMaterialize(t, d, sb.SandboxID)

	for i := 0; i < 3; i++ {
		if err := s.mgr.Tick(time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxSuspended {
		t.Fatalf("sandbox state = %s, want SUSPENDED", got)
	}
	consumer := eventservice.NewConsumer()
	suspended := eventsOfType(consumer.Poll(s.outbox), domain.EventSandboxSuspended)
	if len(suspended) != 1 || suspended[0].Payload["reason"] != "wall_deadline" {
		t.Fatalf("missing wall_deadline suspend event: %v", suspended)
	}

	report := mustMaterialize(t, d, sb.SandboxID)
	// Wall-deadline enforcement reclaims resources (M7): the suspend is
	// workspace-only, so rematerialization is an epoch-incrementing reset.
	if report.NewEpoch != 2 {
		t.Fatalf("rematerialize epoch = %d, want 2", report.NewEpoch)
	}
	// Enforcement is idempotent across further ticks (no repeated
	// transitions or errors).
	for i := 0; i < 2; i++ {
		if err := s.mgr.Tick(time.Second); err != nil {
			t.Fatal(err)
		}
	}
}

// H4 regression: a quota-denied materialize leaves the sandbox FAILED (not
// wedged in STARTING), and retry succeeds once the quota is raised.
func TestQuotaDeniedMaterializeRetryable(t *testing.T) {
	runBoth(t, func(t *testing.T, s *system) {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 5)
		s.mgr.SetQuota(domain.Quota{TenantID: "tenant-1", MaxLiveSandboxes: 1})
		first, err := d.CreateSandbox("task-first")
		if err != nil {
			t.Fatal(err)
		}
		mustMaterialize(t, d, first.SandboxID)
		second, err := d.CreateSandbox("task-second")
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.mgr.Materialize(second.SandboxID)
		var qerr *domain.QuotaExceededError
		if !errors.As(err, &qerr) {
			t.Fatalf("expected QuotaExceededError, got %v", err)
		}
		got := mustGetSandbox(t, s, second.SandboxID)
		if got.ObservedState != domain.SandboxFailed {
			t.Fatalf("state after quota denial = %s, want FAILED", got.ObservedState)
		}
		s.mgr.SetQuota(domain.Quota{TenantID: "tenant-1", MaxLiveSandboxes: 2})
		if _, err := s.mgr.Materialize(second.SandboxID); err != nil {
			t.Fatalf("retry after quota raised: %v", err)
		}
		if got := mustGetSandbox(t, s, second.SandboxID); got.ObservedState != domain.SandboxRunning {
			t.Fatalf("state after retry = %s, want RUNNING", got.ObservedState)
		}
	})
}

// H4 regression: an rt.Create failure leaves the sandbox FAILED and a later
// Materialize retry succeeds.
func TestCreateFailureMaterializeRetryable(t *testing.T) {
	s := newSystem(t, "fake")
	fb := s.fakeBackend(t)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 6)
	sb, err := d.CreateSandbox("task-flaky-create")
	if err != nil {
		t.Fatal(err)
	}
	fb.Faults.FailCreate = true
	if _, err := s.mgr.Materialize(sb.SandboxID); err == nil {
		t.Fatal("expected materialize failure")
	}
	if got := mustGetSandbox(t, s, sb.SandboxID); got.ObservedState != domain.SandboxFailed {
		t.Fatalf("state after create failure = %s, want FAILED", got.ObservedState)
	}
	fb.Faults.FailCreate = false
	if _, err := s.mgr.Materialize(sb.SandboxID); err != nil {
		t.Fatalf("retry after fault cleared: %v", err)
	}
	if got := mustGetSandbox(t, s, sb.SandboxID); got.ObservedState != domain.SandboxRunning {
		t.Fatalf("state after retry = %s, want RUNNING", got.ObservedState)
	}
}
