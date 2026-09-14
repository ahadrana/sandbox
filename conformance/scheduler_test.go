// Scheduler/fairness/autoscaling conformance (PLAN §13): tenant quota
// admission, priority/class preemption, locality scoring, autoscaling
// signals, cache eviction pinning, packing density, and dormant scale.
package conformance

import (
	"errors"
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/control-plane/scheduler"
	"github.com/agent-sandbox/platform/domain"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
	localbackend "github.com/agent-sandbox/platform/runtime/local-backend"
	"github.com/agent-sandbox/platform/workspace"
)

type stubEnvSource map[string]map[string]string

func (s stubEnvSource) ArtifactManifest(id string) (map[string]string, error) {
	m, ok := s[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return m, nil
}

// Tenant quota admission: the limited tenant gets an explicit
// QuotaExceeded error + event while other tenants still place.
func TestTenantQuotaAdmission(t *testing.T) {
	s := newSystem(t, "fake")
	s.mgr.SetQuota(domain.Quota{TenantID: "tenant-a", MaxLiveSandboxes: 1})

	dA := agentdriver.New(s.mgr, "tenant-a", "principal-1", 91)
	sb1, _ := dA.CreateSandbox("task-a1")
	mustMaterialize(t, dA, sb1.SandboxID)

	sb2, _ := dA.CreateSandbox("task-a2")
	_, err := dA.EnsureMaterialized(sb2.SandboxID)
	var quotaErr *domain.QuotaExceededError
	if !errors.As(err, &quotaErr) {
		t.Fatalf("second sandbox: err = %v, want QuotaExceededError", err)
	}
	if quotaErr.TenantID != "tenant-a" || quotaErr.Resource != "live_sandboxes" {
		t.Fatalf("quota error wrong: %+v", quotaErr)
	}
	consumer := eventservice.NewConsumer()
	if got := eventsOfType(consumer.Poll(s.outbox), domain.EventQuotaExceeded); len(got) != 1 {
		t.Fatalf("missing QuotaExceeded event: %v", got)
	}

	// A different tenant is unaffected.
	dB := agentdriver.New(s.mgr, "tenant-b", "principal-1", 91)
	sbB, _ := dB.CreateSandbox("task-b1")
	mustMaterialize(t, dB, sbB.SandboxID)
}

// Full fleet: an INTERACTIVE requester preempts (suspends) a
// strictly-lower-priority BACKGROUND sandbox; the victim is resumable once
// capacity frees up.
func TestPreemption(t *testing.T) {
	fs := newFleetSystem(t, 1, 1)
	d := agentdriver.New(fs.mgr, "tenant-1", "principal-1", 92)

	bg, err := fs.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-bg",
		EnvironmentID: "env-base-1", PolicyRef: "policy-default",
		Priority: 10, Class: domain.ClassBackground,
	})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, bg.SandboxID)

	iv, err := fs.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-iv",
		EnvironmentID: "env-base-1", PolicyRef: "policy-default",
		Priority: 50, Class: domain.ClassInteractive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.EnsureMaterialized(iv.SandboxID); err != nil {
		t.Fatalf("interactive materialize should preempt: %v", err)
	}

	if got := mustGetSandbox(t, &system{mgr: fs.mgr}, iv.SandboxID).ObservedState; got != domain.SandboxRunning {
		t.Fatalf("interactive state = %s", got)
	}
	if got := mustGetSandbox(t, &system{mgr: fs.mgr}, bg.SandboxID).ObservedState; got != domain.SandboxSuspended {
		t.Fatalf("victim state = %s, want SUSPENDED", got)
	}
	consumer := eventservice.NewConsumer()
	preempted := eventsOfType(consumer.Poll(fs.outbox), domain.EventSandboxPreempted)
	if len(preempted) != 1 || preempted[0].Payload["preempted_by"] != iv.SandboxID {
		t.Fatalf("missing preemption event: %v", preempted)
	}

	// Victim resumes once capacity exists.
	fs.addHost(t, "host-2")
	report, err := fs.mgr.Resume(bg.SandboxID)
	if err != nil {
		t.Fatalf("victim resume: %v", err)
	}
	if report.NewEpoch != report.PriorEpoch+1 {
		t.Fatalf("victim resume epochs = %d -> %d (fleet restore unsupported, workspace-only expected)", report.PriorEpoch, report.NewEpoch)
	}
}

// Equal priority never preempts: placement fails with a capacity error.
func TestEqualPriorityNoPreemption(t *testing.T) {
	fs := newFleetSystem(t, 1, 1)
	d := agentdriver.New(fs.mgr, "tenant-1", "principal-1", 93)

	bg, err := fs.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-bg",
		EnvironmentID: "env-base-1", PolicyRef: "policy-default",
		Priority: 50, Class: domain.ClassBackground,
	})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, bg.SandboxID)

	iv, err := fs.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-iv",
		EnvironmentID: "env-base-1", PolicyRef: "policy-default",
		Priority: 50, Class: domain.ClassInteractive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.EnsureMaterialized(iv.SandboxID); !errors.Is(err, scheduler.ErrNoCapacity) {
		t.Fatalf("equal priority: err = %v, want ErrNoCapacity", err)
	}
	if got := eventsOfType(eventservice.NewConsumer().Poll(fs.outbox), domain.EventSandboxPreempted); len(got) != 0 {
		t.Fatalf("equal priority must not preempt: %v", got)
	}
}

// Packing density: sandboxes sharing an environment cluster onto the fewest
// hosts via the env-cache locality bonus.
func TestPackingDensity(t *testing.T) {
	clock := domain.NewManualClock(time.Now())
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	outbox := eventservice.NewOutbox()
	envs := stubEnvSource{"env-pack": {"base.txt": "base"}}
	fleet := hostagent.NewFleet(clock, envs, ws)
	for _, id := range []string{"host-1", "host-2", "host-3"} {
		backend, err := localbackend.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		fleet.RegisterHost(hostagent.New(id, backend, envs, ws, 1<<20, 4, 16))
	}
	mgr := sandboxmanager.New(clock, ids, ws, fleet, outbox, sandboxmanager.NewMemoryStore(), "fleet")
	d := agentdriver.New(mgr, "tenant-1", "principal-1", 94)

	hostsUsed := map[string]bool{}
	for i := 0; i < 6; i++ {
		sb, err := mgr.CreateSandbox(api.CreateSandboxRequest{
			Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-pack",
			EnvironmentID: "env-pack", PolicyRef: "policy-default",
		})
		if err != nil {
			t.Fatal(err)
		}
		mustMaterialize(t, d, sb.SandboxID)
		cur := mustGetSandbox(t, &system{mgr: mgr}, sb.SandboxID)
		hostID, _, ok := fleet.PlacementOf(*cur.RuntimeIncarnationID)
		if !ok {
			t.Fatal("no placement")
		}
		hostsUsed[hostID] = true
	}
	// 6 sandboxes, 4 slots/host: locality must pack them onto at most 2
	// hosts (naive spreading would use all 3).
	if len(hostsUsed) > 2 {
		t.Fatalf("packing used %d hosts, want <= 2: %v", len(hostsUsed), hostsUsed)
	}
}

// Dormant scale gate (INV-029): 2000 logical sandboxes with only ~10
// materialized; the control plane handles it and live capacity matches
// active work.
func TestDormantScale(t *testing.T) {
	s := newSystem(t, "fake")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 95)

	const total, live = 2000, 10
	ids := make([]string, 0, total)
	for i := 0; i < total; i++ {
		sb, err := d.CreateSandbox("task-dormant")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, sb.SandboxID)
	}
	for _, id := range ids[:live] {
		mustMaterialize(t, d, id)
		if _, err := d.ExecSync(id, domain.Operation{Writes: map[string]string{"f": "x"}}); err != nil {
			t.Fatal(err)
		}
	}
	running, unmaterialized := 0, 0
	for _, id := range ids {
		switch mustGetSandbox(t, s, id).ObservedState {
		case domain.SandboxRunning, domain.SandboxQuiescent:
			running++
		case domain.SandboxUnmaterialized:
			unmaterialized++
		default:
			t.Fatalf("unexpected state for %s", id)
		}
	}
	if running != live || unmaterialized != total-live {
		t.Fatalf("live=%d dormant=%d, want %d/%d", running, unmaterialized, live, total-live)
	}
}

// Autoscaling signals: sustained capacity placement failures recommend
// adding hosts; sustained low utilization recommends removing hosts.
func TestScaleRecommendation(t *testing.T) {
	// Scale-out: 1 host, 1 slot, three failed placements in a row.
	fs := newFleetSystem(t, 1, 1)
	d := agentdriver.New(fs.mgr, "tenant-1", "principal-1", 96)
	sb1, _ := d.CreateSandbox("task-scale-1")
	mustMaterialize(t, d, sb1.SandboxID)
	for i := 0; i < 3; i++ {
		sb, err := fs.mgr.CreateSandbox(api.CreateSandboxRequest{
			Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-scale-x",
			EnvironmentID: "env-base-1", PolicyRef: "policy-default",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fs.mgr.Materialize(sb.SandboxID); !errors.Is(err, scheduler.ErrNoCapacity) {
			t.Fatalf("placement %d: err = %v, want ErrNoCapacity", i, err)
		}
	}
	rec := fs.fleet.Recommendation()
	if rec.AddHosts < 1 {
		t.Fatalf("no scale-out recommendation after sustained failures: %+v", rec)
	}

	// Scale-in: 2 idle hosts for enough ticks.
	fs2 := newFleetSystem(t, 2, 4)
	fs2.tick(6)
	rec = fs2.fleet.Recommendation()
	if rec.RemoveHosts != 1 {
		t.Fatalf("scale-in recommendation = %+v, want RemoveHosts 1", rec)
	}
}

// Cache eviction pinning: an environment artifact used by a live
// incarnation is never evicted, even past the size bound.
func TestCachePinProtection(t *testing.T) {
	clock := domain.NewManualClock(time.Now())
	ids := domain.NewIDGen()
	wsStore := workspace.NewMemory(clock, ids)
	ws, err := wsStore.Create("tenant-1", "envA")
	if err != nil {
		t.Fatal(err)
	}
	backend, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	envs := stubEnvSource{"envA": {"a.txt": "a"}, "envB": {"b.txt": "b"}, "envC": {"c.txt": "c"}, "envD": {"d.txt": "d"}}
	agent := hostagent.New("h1", backend, envs, wsStore, 1<<20, 4, 1) // cache size 1

	create := func(sandboxID, incID, envID string, fence int64) {
		t.Helper()
		_, err := agent.Create(hostagent.CreateRequest{
			SandboxID: sandboxID, IncarnationID: incID, Fence: fence, Epoch: 1,
			EnvironmentID: envID, WorkspaceID: ws.WorkspaceID,
			WorkspaceGeneration: ws.HeadGeneration, MemoryBytes: 64,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	create("s1", "i1", "envA", 1) // fetches envA + ws, pins envA
	create("s2", "i2", "envB", 1) // fetches envB (+ws churn); envA pinned
	create("s3", "i3", "envA", 1) // envA still cached (pin held by live i1)
	// 4 fetches: envA, ws, envB, ws churn. Without pinning envA would have
	// been evicted and refetched (6).
	if got := agent.Cache().Fetches(); got != 4 {
		t.Fatalf("fetches = %d, want 4 (pinned envA survived eviction pressure)", got)
	}
	// After terminating all incarnations the pins are released and cached
	// artifacts become evictable.
	for _, h := range []string{"i1", "i2", "i3"} {
		if err := agent.Terminate(backendinterface.Handle{IncarnationID: h}); err != nil {
			t.Fatal(err)
		}
	}
	create("s4", "i4", "envC", 1) // fetch 5; evicts oldest unpinned
	create("s5", "i5", "envD", 1) // fetch 6; evicts envA
	create("s6", "i6", "envA", 1) // fetch: envA was evicted after unpin
	// 8 total: phase 1's 4 + envC + envD + envA refetch + ws churn. The key
	// invariant is above: envA needed no refetch while pinned.
	if got := agent.Cache().Fetches(); got != 8 {
		t.Fatalf("fetches after unpin = %d, want 8 (envA evicted then refetched)", got)
	}
}

// Locality scoring: checkpoint-holding and lower-pressure hosts win.
func TestSchedulerLocalityScoring(t *testing.T) {
	sched := scheduler.New()
	hosts := []scheduler.HostView{
		{HostID: "a", Healthy: true, CapacitySlots: 4, CapacityMemory: 100,
			CachedEnvironments: map[string]bool{}, CachedWorkspaces: map[string]bool{},
			CachedCheckpoints: map[string]bool{"sb1": true}},
		{HostID: "b", Healthy: true, CapacitySlots: 4, CapacityMemory: 100,
			CachedEnvironments: map[string]bool{}, CachedWorkspaces: map[string]bool{},
			CachedCheckpoints: map[string]bool{}},
	}
	p, err := sched.Place(scheduler.Request{SandboxID: "sb1", MemoryRequired: 10}, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if p.HostID != "a" {
		t.Fatalf("checkpoint locality lost: placed on %s", p.HostID)
	}

	// Memory pressure penalty: equal hosts, one under pressure.
	hosts[0].CachedCheckpoints = map[string]bool{}
	hosts[1].Pressure = 0.9
	p, err = sched.Place(scheduler.Request{SandboxID: "sb2", MemoryRequired: 10}, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if p.HostID != "a" {
		t.Fatalf("high-pressure host won placement: %s", p.HostID)
	}
}

// L9 regression: CreateSandbox validates Priority (0-100) and Class
// (INTERACTIVE|BACKGROUND); empty Class defaults to INTERACTIVE.
func TestCreateSandboxValidation(t *testing.T) {
	s := newSystem(t, "fake")
	for _, req := range []api.CreateSandboxRequest{
		{Version: api.SchemaVersionV1, TenantID: "t", TaskRef: "x", Priority: -1},
		{Version: api.SchemaVersionV1, TenantID: "t", TaskRef: "x", Priority: 101},
		{Version: api.SchemaVersionV1, TenantID: "t", TaskRef: "x", Class: "Interactive"}, // case typo
		{Version: api.SchemaVersionV1, TenantID: "t", TaskRef: "x", Class: "BATCH"},
	} {
		if _, err := s.mgr.CreateSandbox(req); !errors.Is(err, domain.ErrInvalidRequest) {
			t.Fatalf("request %+v: err = %v, want ErrInvalidRequest", req, err)
		}
	}
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "t", TaskRef: "x", Priority: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sb.WorkloadClass != domain.ClassInteractive {
		t.Fatalf("default class = %q, want INTERACTIVE", sb.WorkloadClass)
	}
	if sb.Priority != 50 {
		t.Fatalf("priority = %d, want 50", sb.Priority)
	}
}
