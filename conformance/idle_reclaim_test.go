package conformance

import (
	"errors"
	"strings"
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/domain"
)

// idlePolicy: short idle-reclaim threshold on top of the permissive base.
func idlePolicy(after time.Duration) sandboxmanager.PolicyConfig {
	p := permissivePolicy()
	p.IdleReclaimAfter = after
	return p
}

// (a) A sandbox with live background work is NEVER auto-reclaimed, however
// far past the idle threshold the clock advances.
func TestIdleReclaimNeverReclaimsActiveSandbox(t *testing.T) {
	s := newSystem(t, "fake")
	s.mgr.SetPolicy(idlePolicy(time.Minute))
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 31)
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-active",
	})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command:         "true",
		SpawnBackground: []domain.BackgroundSpec{{Name: "worker", Ticks: 1 << 20}},
	}); err != nil {
		t.Fatal(err)
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxBackgroundActive {
		t.Fatalf("state = %s, want BACKGROUND_ACTIVE", got)
	}
	// Fast-forward 10x past the threshold: still alive, still active.
	for i := 0; i < 10; i++ {
		if err := s.mgr.Tick(time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	cur := mustGetSandbox(t, s, sb.SandboxID)
	if cur.ObservedState != domain.SandboxBackgroundActive {
		t.Fatalf("active sandbox reclaimed: state = %s", cur.ObservedState)
	}
	if events, _ := s.outbox.Replay(0); len(eventsOfType(events, domain.EventSandboxSuspended)) != 0 {
		t.Fatal("active sandbox was suspended")
	}
	if got := s.mgr.Metrics().IdleReclaims; got != 0 {
		t.Fatalf("idle reclaims = %d, want 0", got)
	}
	if got := s.mgr.Metrics().IdleReclaimSkipsActive; got == 0 {
		t.Fatal("active skips not counted in metrics")
	}
}

// (b) A quiescent sandbox IS reclaimed once idle past the threshold: a
// checkpoint is taken and the sandbox suspends with reason idle_reclaim.
func TestIdleReclaimReclaimsQuiescentSandbox(t *testing.T) {
	s := newSystem(t, "fake")
	s.mgr.SetPolicy(idlePolicy(5 * time.Minute))
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 32)
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-idle",
	})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, sb.SandboxID)

	// First tick observes idleness and starts the idle clock; nothing below
	// the threshold may reclaim.
	if err := s.mgr.Tick(time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.mgr.Tick(3 * time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got == domain.SandboxSuspended {
		t.Fatal("reclaimed before the idle threshold")
	}
	if err := s.mgr.Tick(2 * time.Minute); err != nil {
		t.Fatal(err)
	}
	cur := mustGetSandbox(t, s, sb.SandboxID)
	if cur.ObservedState != domain.SandboxSuspended {
		t.Fatalf("state = %s, want SUSPENDED", cur.ObservedState)
	}
	if cur.CheckpointRef == nil {
		t.Fatal("idle reclaim did not take a checkpoint")
	}
	events, _ := s.outbox.Replay(0)
	suspended := eventsOfType(events, domain.EventSandboxSuspended)
	if len(suspended) != 1 || suspended[0].Payload["reason"] != "idle_reclaim" {
		t.Fatalf("missing idle_reclaim suspend event: %v", suspended)
	}
	if got := s.mgr.Metrics().IdleReclaims; got != 1 {
		t.Fatalf("idle reclaims = %d, want 1", got)
	}
	// Enforcement is idempotent: further ticks do not re-suspend.
	for i := 0; i < 2; i++ {
		if err := s.mgr.Tick(10 * time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.mgr.Metrics().IdleReclaims; got != 1 {
		t.Fatalf("idle reclaims after extra ticks = %d, want 1", got)
	}
}

// (c) INV-015 background deadlines bound how long "active" can persist:
// once the deadline kills the background work, the sandbox quiesces and
// reclaim becomes legal.
func TestIdleReclaimAfterBackgroundDeadlineQuiesce(t *testing.T) {
	s := newSystem(t, "fake")
	p := idlePolicy(2 * time.Minute)
	p.MaxBackgroundWall = 2 * time.Minute
	s.mgr.SetPolicy(p)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 33)
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-runaway",
	})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command:         "true",
		SpawnBackground: []domain.BackgroundSpec{{Name: "runaway", Ticks: 1 << 20}},
	}); err != nil {
		t.Fatal(err)
	}
	// t=1m,2m: active and inside the background wall — no reclaim.
	for i := 0; i < 2; i++ {
		if err := s.mgr.Tick(time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxBackgroundActive {
		t.Fatalf("state = %s, want BACKGROUND_ACTIVE", got)
	}
	// t=3m: background wall exceeded -> work killed -> quiesce; idle clock
	// starts. t=5m: idle for 2m >= threshold -> reclaim.
	for i := 0; i < 4; i++ {
		if err := s.mgr.Tick(time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	events, _ := s.outbox.Replay(0)
	exceeded := eventsOfType(events, domain.EventResourceLimitExceeded)
	if len(exceeded) == 0 || exceeded[0].Payload["resource"] != "background_wall" {
		t.Fatalf("background deadline never fired: %v", events)
	}
	cur := mustGetSandbox(t, s, sb.SandboxID)
	if cur.ObservedState != domain.SandboxSuspended {
		t.Fatalf("state = %s, want SUSPENDED (reclaim after deadline-quiesce)", cur.ObservedState)
	}
	suspended := eventsOfType(events, domain.EventSandboxSuspended)
	if len(suspended) != 1 || suspended[0].Payload["reason"] != "idle_reclaim" {
		t.Fatalf("missing idle_reclaim suspend: %v", suspended)
	}
}

// (d) Capacity pressure with all-active sandboxes: the new create fails
// honestly and no active sandbox is reclaimed or preempted.
func TestCapacityPressureShedsNewPlacementNotActiveWork(t *testing.T) {
	s := newSystem(t, "fake")
	s.mgr.SetPolicy(idlePolicy(time.Minute))
	s.mgr.SetQuota(domain.Quota{TenantID: "tenant-1", MaxLiveSandboxes: 1})
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 34)
	sb1, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-busy",
	})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, sb1.SandboxID)
	if _, err := d.ExecSync(sb1.SandboxID, domain.Operation{
		Command:         "true",
		SpawnBackground: []domain.BackgroundSpec{{Name: "worker", Ticks: 1 << 20}},
	}); err != nil {
		t.Fatal(err)
	}

	sb2, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-newcomer",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.mgr.Materialize(sb2.SandboxID)
	var qerr *domain.QuotaExceededError
	if !errors.As(err, &qerr) {
		t.Fatalf("new placement err = %v, want QuotaExceededError", err)
	}
	events, _ := s.outbox.Replay(0)
	if got := eventsOfType(events, domain.EventQuotaExceeded); len(got) != 1 {
		t.Fatalf("missing honest quota-denial event: %v", events)
	}
	// The active sandbox is untouched — even after ticks past the idle
	// threshold, pressure never reclaims work.
	if err := s.mgr.Tick(5 * time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := mustGetSandbox(t, s, sb1.SandboxID).ObservedState; got != domain.SandboxBackgroundActive {
		t.Fatalf("active sandbox disturbed: state = %s", got)
	}
	if got := s.mgr.Metrics().IdleReclaims; got != 0 {
		t.Fatalf("idle reclaims = %d, want 0", got)
	}
}

// (e) Step-2 integration: an idle-reclaimed sandbox (workspace-only path,
// checkpoint capability masked) resumes epoch-creating and the restart
// recipe reconstructs its service — no agent-driven execution.
func TestIdleReclaimedSandboxResumesViaHooks(t *testing.T) {
	const port = "18442"
	f := newEnvFixture(t)
	f.repos.AddVersion("base-go", "", map[string]string{"bin/go": "binary"})
	f.repos.AddVersion("app", "sha-app-1", map[string]string{"main.go": "v1"})
	spec := baseSpec()
	spec.Start = []string{"echo booted >> hooks.log"}
	spec.Terminals = []string{"python3 -m http.server " + port + " --bind 127.0.0.1"}
	env := mustBuild(t, f, "coding", spec)

	s := newSystem(t, "local")
	// Mask checkpoint: idle reclaim takes the workspace-only path, so the
	// resume is epoch-creating and hooks re-run.
	s.rt = noCheckpointRuntime{s.rt}
	s.mgr = sandboxmanager.New(s.clock, s.ids, s.ws, s.rt, s.outbox, s.store, "host-1")
	s.mgr.SetEnvironmentSource(f.builder)
	s.mgr.SetPolicy(idlePolicy(2 * time.Minute))

	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 35)
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-idle-hooks",
		EnvironmentID: env.EnvironmentID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.mgr.Materialize(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.mgr.KillRuntime(sb.SandboxID) })
	get := func() (string, bool) {
		return httpGet("http://127.0.0.1:" + port + "/hooks.log")
	}
	pollUntil(t, 10*time.Second, "hook-launched HTTP service", func() bool {
		body, ok := get()
		return ok && strings.TrimSpace(body) == "booted"
	})

	// The terminal-hook server counts as live work: while it runs, the
	// sandbox is NOT idle. Stop it so the sandbox can quiesce (the service
	// ended on its own — reclaim of genuinely idle sandboxes only). The
	// scripted write marks the workspace dirty so the suspend commits the
	// hook log along with it.
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "pkill -f 'http.server " + port + "'",
		Writes:  map[string]string{"committed.txt": "x"},
	}); err != nil {
		t.Fatal(err)
	}

	// Idle clock: first tick observes quiescence, then past the threshold.
	if err := s.mgr.Tick(time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got == domain.SandboxSuspended {
		t.Fatal("reclaimed before threshold")
	}
	if err := s.mgr.Tick(2 * time.Minute); err != nil {
		t.Fatal(err)
	}
	cur := mustGetSandbox(t, s, sb.SandboxID)
	if cur.ObservedState != domain.SandboxSuspended {
		t.Fatalf("state = %s, want SUSPENDED", cur.ObservedState)
	}
	consumer := eventservice.NewConsumer()
	suspended := eventsOfType(consumer.Poll(s.outbox), domain.EventSandboxSuspended)
	if len(suspended) != 1 || suspended[0].Payload["reason"] != "idle_reclaim" || suspended[0].Payload["mode"] != "workspace_only" {
		t.Fatalf("want workspace_only idle_reclaim suspend: %v", suspended)
	}

	report, err := s.mgr.Resume(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.PriorEpoch != 1 || report.NewEpoch != 2 {
		t.Fatalf("epoch %d -> %d, want 1 -> 2", report.PriorEpoch, report.NewEpoch)
	}
	fresh := consumer.Poll(s.outbox)
	if got := eventsOfType(fresh, domain.EventEnvironmentHooksStarted); len(got) != 1 {
		t.Fatalf("hooks did not re-run on idle-reclaim resume: %v", got)
	}
	// The restart recipe reconstructed the service.
	pollUntil(t, 10*time.Second, "service reconstructed after idle-reclaim resume", func() bool {
		body, ok := get()
		return ok && strings.Count(body, "booted") == 2
	})
	files, err := s.mgr.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(files["hooks.log"], "booted"); got != 2 {
		t.Fatalf("start hook ran %d times, want 2 (log %q)", got, files["hooks.log"])
	}
}
