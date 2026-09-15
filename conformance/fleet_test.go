package conformance

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/domain"
	environmentbuilder "github.com/agent-sandbox/platform/environment-builder"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	fakebackend "github.com/agent-sandbox/platform/runtime/fake-backend"
	supervisor "github.com/agent-sandbox/platform/runtime/guest-supervisor"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
	"github.com/agent-sandbox/platform/runtime/hostfacts"
	localbackend "github.com/agent-sandbox/platform/runtime/local-backend"
	"github.com/agent-sandbox/platform/workspace"
)

type fleetSystem struct {
	mgr      *sandboxmanager.Manager
	fleet    *hostagent.Fleet
	clock    *domain.ManualClock
	ids      *domain.IDGen
	ws       *workspace.Memory
	outbox   *eventservice.Outbox
	hosts    map[string]*hostagent.HostAgent
	backends map[string]*localbackend.Backend
	slots    int
}

func newFleetSystem(t *testing.T, hostCount, slots int) *fleetSystem {
	t.Helper()
	clock := domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	outbox := eventservice.NewOutbox()
	fleet := hostagent.NewFleet(clock, nil, ws)
	fs := &fleetSystem{
		clock: clock, ids: ids, ws: ws, outbox: outbox, fleet: fleet,
		hosts: map[string]*hostagent.HostAgent{}, backends: map[string]*localbackend.Backend{},
		slots: slots,
	}
	for i := 0; i < hostCount; i++ {
		fs.addHost(t, fmt.Sprintf("host-%d", i+1))
	}
	fs.mgr = sandboxmanager.New(clock, ids, ws, fleet, outbox, sandboxmanager.NewMemoryStore(), "fleet")
	return fs
}

func (fs *fleetSystem) addHost(t *testing.T, hostID string) {
	t.Helper()
	backend, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	agent := hostagent.New(hostID, backend, nil, fs.ws, 1<<20, fs.slots, 16)
	fs.hosts[hostID] = agent
	fs.backends[hostID] = backend
	fs.fleet.RegisterHost(agent)
}

func (fs *fleetSystem) placementHost(t *testing.T, sandboxID string) string {
	t.Helper()
	sb, err := fs.mgr.GetSandbox(sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	hostID, _, ok := fs.fleet.PlacementOf(*sb.RuntimeIncarnationID)
	if !ok {
		t.Fatal("no placement recorded")
	}
	return hostID
}

func (fs *fleetSystem) tick(n int) {
	for i := 0; i < n; i++ {
		fs.mgr.Tick(time.Second)
	}
}

// Host restart: agent restarts with the same host ID and an intact local
// cache/backend; incarnations keep working and new placements succeed.
func TestRuntimeHostRestart(t *testing.T) {
	fs := newFleetSystem(t, 2, 4)
	d := agentdriver.New(fs.mgr, "tenant-1", "principal-1", 109)
	sb, _ := d.CreateSandbox("task-restart")
	mustMaterialize(t, d, sb.SandboxID)
	hostID := fs.placementHost(t, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{Writes: map[string]string{"a": "1"}}); err != nil {
		t.Fatal(err)
	}

	// Host agent restart: new instance, same host ID, same backend (cache intact).
	restarted := hostagent.New(hostID, fs.backends[hostID], nil, fs.ws, 1<<20, fs.slots, 16)
	fs.fleet.RegisterHost(restarted)

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{Writes: map[string]string{"b": "2"}}); err != nil {
		t.Fatalf("incarnation unusable after host restart: %v", err)
	}
	files, err := fs.mgr.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if files["a"] != "1" || files["b"] != "2" {
		t.Fatalf("incarnation state lost across host restart: %v", files)
	}
	sb2, _ := d.CreateSandbox("task-restart-2")
	mustMaterialize(t, d, sb2.SandboxID)
	if got := fs.placementHost(t, sb2.SandboxID); got == "" {
		t.Fatal("no new placement after host restart")
	}
}

// M5 gate: node loss -> explicit FAILED; rematerialization on ANOTHER host
// with unchanged sandbox_id, epoch increment, ExecutionStateReset, intact
// workspace generation (INV-001, INV-005, INV-007).
func TestNodeLossRematerializeElsewhere(t *testing.T) {
	fs := newFleetSystem(t, 3, 4)
	d := agentdriver.New(fs.mgr, "tenant-1", "principal-1", 113)
	sb, _ := d.CreateSandbox("task-nodeloss")
	mustMaterialize(t, d, sb.SandboxID)
	lostHost := fs.placementHost(t, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Writes: map[string]string{"work.txt": "committed-on-lost-host"},
	}); err != nil {
		t.Fatal(err)
	}

	fs.fleet.SimulateHostLoss(lostHost)
	fs.tick(3)
	cur := mustGetSandbox2(t, fs.mgr, sb.SandboxID)
	if cur.ObservedState != domain.SandboxFailed {
		t.Fatalf("sandbox state = %s after host loss, want FAILED", cur.ObservedState)
	}
	if cur.RuntimeIncarnationID != nil {
		t.Fatal("dead incarnation still referenced")
	}

	report, err := fs.mgr.Materialize(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	newHost := fs.placementHost(t, sb.SandboxID)
	if newHost == lostHost {
		t.Fatalf("rematerialized on the lost host %s", newHost)
	}
	if report.PriorEpoch != 1 || report.NewEpoch != 2 {
		t.Fatalf("epoch = %d -> %d", report.PriorEpoch, report.NewEpoch)
	}
	cur = mustGetSandbox2(t, fs.mgr, sb.SandboxID)
	if cur.SandboxID != sb.SandboxID || cur.WorkspaceGeneration != 2 {
		t.Fatalf("identity/generation wrong after recovery: %+v", cur)
	}
	files, err := fs.mgr.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if files["work.txt"] != "committed-on-lost-host" {
		t.Fatalf("workspace generation not intact on new host: %v", files)
	}
	consumer := eventservice.NewConsumer()
	resets := eventsOfType(consumer.Poll(fs.outbox), domain.EventExecutionStateReset)
	if len(resets) != 1 {
		t.Fatal("missing ExecutionStateReset after host-loss recovery")
	}
}

func mustGetSandbox2(t *testing.T, mgr *sandboxmanager.Manager, id string) *domain.Sandbox {
	t.Helper()
	sb, err := mgr.GetSandbox(id)
	if err != nil {
		t.Fatal(err)
	}
	return sb
}

// Host-agent pod restart (ADR 005): the agent process comes back with the
// same host ID but an empty backend (its state dir is pod-local). The fleet
// must declare the previously placed incarnation lost at re-registration —
// liveness heartbeats alone resume too fast for the down-tick path.
func TestHostReregisterDeclaresMissingIncarnationLost(t *testing.T) {
	fs := newFleetSystem(t, 2, 4)
	d := agentdriver.New(fs.mgr, "tenant-1", "principal-1", 117)
	sb, _ := d.CreateSandbox("task-podrestart")
	mustMaterialize(t, d, sb.SandboxID)
	hostID := fs.placementHost(t, sb.SandboxID)

	// Fresh agent process, fresh backend: nothing of the old pod survives.
	freshBackend, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	restarted := hostagent.New(hostID, freshBackend, nil, fs.ws, 1<<20, fs.slots, 16)
	fs.fleet.RegisterHost(restarted)

	fs.tick(1)
	cur := mustGetSandbox2(t, fs.mgr, sb.SandboxID)
	if cur.ObservedState != domain.SandboxFailed {
		t.Fatalf("sandbox state = %s after agent re-register, want FAILED", cur.ObservedState)
	}
	if cur.RuntimeIncarnationID != nil {
		t.Fatal("dead incarnation still referenced")
	}
}

// Cold node: a host with an empty cache materializes correctly, populating
// its cache on demand from the durable store (INV-023).
func TestColdNodePlacement(t *testing.T) {
	fs := newFleetSystem(t, 1, 4)
	d := agentdriver.New(fs.mgr, "tenant-1", "principal-1", 127)
	sb, _ := d.CreateSandbox("task-cold-node")
	mustMaterialize(t, d, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{Writes: map[string]string{"x": "y"}}); err != nil {
		t.Fatal(err)
	}

	// Simulate node loss, then register a brand-new cold host (empty cache).
	fs.fleet.SimulateHostLoss("host-1")
	fs.tick(3)
	fs.addHost(t, "host-cold")
	if got := fs.hosts["host-cold"].Cache().Fetches(); got != 0 {
		t.Fatalf("cold host cache not empty: %d fetches", got)
	}
	if _, err := fs.mgr.Materialize(sb.SandboxID); err != nil {
		t.Fatalf("cold rematerialization failed: %v", err)
	}
	if got := fs.placementHost(t, sb.SandboxID); got != "host-cold" {
		t.Fatalf("placed on %s, want the cold host", got)
	}
	files, err := fs.mgr.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if files["x"] != "y" {
		t.Fatalf("cold node lost committed bytes: %v", files)
	}
	if fs.hosts["host-cold"].Cache().Fetches() == 0 {
		t.Fatal("cold host did not fetch from the durable store")
	}
}

// Duplicate fenced create: replay with the current fence yields the same
// incarnation; an older fence is rejected (PLAN §8).
func TestDuplicateFencedCreate(t *testing.T) {
	fs := newFleetSystem(t, 1, 4)
	agent := fs.hosts["host-1"]
	req := hostagent.CreateRequest{
		SandboxID: "sb-fence", IncarnationID: "inc-fence-1", Fence: 5, Epoch: 1,
		WorkspaceID: createWSForTest(t, fs), WorkspaceGeneration: 1, MemoryBytes: 64,
	}
	h1, err := agent.Create(req)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := agent.Create(req)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("replayed fence created a second incarnation: %v vs %v", h1, h2)
	}
	stale := req
	stale.Fence = 4
	stale.IncarnationID = "inc-fence-stale"
	if _, err := agent.Create(stale); err != hostagent.ErrStaleFence {
		t.Fatalf("stale fence not rejected: %v", err)
	}
	fresh := req
	fresh.Fence = 6
	fresh.IncarnationID = "inc-fence-2"
	if _, err := agent.Create(fresh); err != nil {
		t.Fatalf("next fence rejected: %v", err)
	}
}

func createWSForTest(t *testing.T, fs *fleetSystem) string {
	t.Helper()
	ws, err := fs.ws.Create("tenant-1", "env-1")
	if err != nil {
		t.Fatal(err)
	}
	return ws.WorkspaceID
}

// Cache behavior: second materialization of the same environment on one host
// hits the artifact cache; after eviction it misses and refetches, staying
// correct. Fetches from durable stores are counted.
func TestCacheHitMiss(t *testing.T) {
	f := newEnvFixture(t)
	f.repos.AddVersion("base-go", "", map[string]string{"bin/go": "binary"})
	f.repos.AddVersion("app", "sha-app-1", map[string]string{"main.go": "v1"})
	env := mustBuild(t, f, "coding", environmentbuilderSpecForTest())

	clock := domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	outbox := eventservice.NewOutbox()
	fleet := hostagent.NewFleet(clock, f.builder, ws)
	backend, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	agent := hostagent.New("host-1", backend, f.builder, ws, 1<<20, 8, 8)
	fleet.RegisterHost(agent)
	mgr := sandboxmanager.New(clock, ids, ws, fleet, outbox, sandboxmanager.NewMemoryStore(), "fleet")

	materializeWithEnv := func(taskRef string) string {
		sb, err := mgr.CreateSandbox(api.CreateSandboxRequest{
			Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: taskRef,
			EnvironmentID: env.EnvironmentID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mgr.Materialize(sb.SandboxID); err != nil {
			t.Fatal(err)
		}
		return sb.SandboxID
	}
	materializeWithEnv("task-c1")
	first := agent.Cache().Fetches()
	if first != 2 { // env artifact + workspace generation
		t.Fatalf("first materialization fetched %d, want 2", first)
	}
	materializeWithEnv("task-c2")
	if got := agent.Cache().Fetches(); got != first+1 {
		t.Fatalf("second materialization fetched %d, want %d (env cache hit)", got, first+1)
	}
	agent.Cache().Flush()
	materializeWithEnv("task-c3")
	if got := agent.Cache().Fetches(); got != first+3 {
		t.Fatalf("post-eviction materialization fetched %d, want %d (miss + refetch)", got, first+3)
	}
}

func environmentbuilderSpecForTest() environmentbuilder.EnvironmentSpec {
	return environmentbuilder.EnvironmentSpec{
		BaseRuntimeRef: "base-go",
		RepoInputs:     []domain.RepoInput{{RepoURL: "app", SHA: "sha-app-1"}},
	}
}

// High density: 50 sandboxes across 3 hosts; capacity respected, placement
// distributed.
func TestHighDensityStarts(t *testing.T) {
	fs := newFleetSystem(t, 3, 20)
	d := agentdriver.New(fs.mgr, "tenant-1", "principal-1", 131)
	const n = 50
	perHost := map[string]int{}
	for i := 0; i < n; i++ {
		sb, err := d.CreateSandbox(fmt.Sprintf("task-hd-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fs.mgr.Materialize(sb.SandboxID); err != nil {
			t.Fatalf("materialize %d: %v", i, err)
		}
		perHost[fs.placementHost(t, sb.SandboxID)]++
	}
	if len(perHost) != 3 {
		t.Fatalf("placement not distributed: %v", perHost)
	}
	for hostID, count := range perHost {
		if count > 20 {
			t.Fatalf("host %s over capacity: %d", hostID, count)
		}
		agent := fs.hosts[hostID]
		if v := agent.View(); v.UsedSlots > v.CapacitySlots {
			t.Fatalf("host %s slots %d/%d", hostID, v.UsedSlots, v.CapacitySlots)
		}
	}
	t.Logf("distribution: %v", perHost)
}

// Scheduler never exceeds host capacity (PLAN §8).
func TestPlacementRespectsCapacity(t *testing.T) {
	fs := newFleetSystem(t, 2, 1)
	d := agentdriver.New(fs.mgr, "tenant-1", "principal-1", 137)
	for i := 0; i < 2; i++ {
		sb, _ := d.CreateSandbox(fmt.Sprintf("task-cap-%d", i))
		if _, err := fs.mgr.Materialize(sb.SandboxID); err != nil {
			t.Fatalf("materialize %d: %v", i, err)
		}
	}
	sb, _ := d.CreateSandbox("task-cap-overflow")
	if _, err := fs.mgr.Materialize(sb.SandboxID); err == nil {
		t.Fatal("placement succeeded beyond total fleet capacity")
	}
	if got := mustGetSandbox2(t, fs.mgr, sb.SandboxID).ObservedState; got == domain.SandboxRunning {
		t.Fatal("sandbox running without capacity")
	}
}

// H8 regression: N concurrent duplicate Creates for the same sandbox+fence
// yield exactly one incarnation and charge capacity exactly once.
func TestConcurrentDuplicateCreateAtomic(t *testing.T) {
	fs := newFleetSystem(t, 1, 4)
	agent := fs.hosts["host-1"]
	req := hostagent.CreateRequest{
		SandboxID: "sb-race", IncarnationID: "inc-race-1", Fence: 3, Epoch: 1,
		WorkspaceID: createWSForTest(t, fs), WorkspaceGeneration: 1, MemoryBytes: 64,
	}
	const n = 16
	var wg sync.WaitGroup
	handles := make([]backendinterface.Handle, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			handles[i], errs[i] = agent.Create(req)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
		if handles[i] != handles[0] {
			t.Fatalf("goroutine %d got a different incarnation: %v vs %v", i, handles[i], handles[0])
		}
	}
	v := agent.View()
	if v.UsedSlots != 1 {
		t.Fatalf("slots charged %d times, want 1", v.UsedSlots)
	}
	if v.UsedMemory != 64 {
		t.Fatalf("memory charged %d, want 64", v.UsedMemory)
	}
}

// M10 regression: fleet capabilities are the honest intersection — an empty
// fleet declares zero-value capabilities, and a feature is declared only
// when every host supports it. Restore is declared when the hosts support
// it: Fleet.Restore routes to the checkpoint's origin host (ADR-008).
func TestFleetCapabilitiesHonest(t *testing.T) {
	clock := domain.NewManualClock(time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC))
	ws := workspace.NewMemory(clock, domain.NewIDGen())
	empty := hostagent.NewFleet(clock, nil, ws)
	caps := empty.Capabilities()
	if caps != (backendinterface.Capabilities{}) {
		t.Fatalf("empty fleet capabilities = %+v, want zero value", caps)
	}

	fs := newFleetSystem(t, 2, 4)
	caps = fs.fleet.Capabilities()
	if caps.IsolationClass != backendinterface.IsolationProcess {
		t.Fatalf("fleet isolation class = %s, want PROCESS (weakest host)", caps.IsolationClass)
	}
	// Every host here is a local backend with STOP/CONT restore; the
	// intersection may — and must — declare it. The fleet-level scoping
	// (origin-host-only, ADR-008) is a routing semantic, not a capability.
	if !caps.SupportsRestore {
		t.Fatal("SupportsRestore under-declared: every host supports restore and Fleet.Restore routes it")
	}
}

// M14 regression: View reads cache state under the cache lock — concurrent
// View during creates must not race ("concurrent map iteration and map
// write").
func TestViewConcurrentWithCreate(t *testing.T) {
	fs := newFleetSystem(t, 1, 8)
	agent := fs.hosts["host-1"]
	wsID := createWSForTest(t, fs)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = agent.View()
			}
		}
	}()
	for i := 0; i < 8; i++ {
		_, err := agent.Create(hostagent.CreateRequest{
			SandboxID: fmt.Sprintf("sb-view-%d", i), IncarnationID: fmt.Sprintf("inc-view-%d", i),
			Fence: 1, Epoch: 1, WorkspaceID: wsID, WorkspaceGeneration: 1, MemoryBytes: 16,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
}

// M15 regression: an incarnation terminated via the fleet while its host is
// lost is scrubbed when the host re-registers — the orphaned compute is
// owned and accounted again, not left running unroutable.
func TestOrphanScrubbedOnHostReregister(t *testing.T) {
	fs := newFleetSystem(t, 1, 4)
	req := hostagent.CreateRequest{
		SandboxID: "sb-orphan", IncarnationID: "inc-orphan-1", Fence: 1, Epoch: 1,
		WorkspaceID: createWSForTest(t, fs), WorkspaceGeneration: 1, MemoryBytes: 32,
	}
	handle, err := fs.fleet.Create(backendinterface.Spec{
		SandboxID: req.SandboxID, IncarnationID: req.IncarnationID, Epoch: 1,
		WorkspaceID: req.WorkspaceID, WorkspaceGeneration: 1, MemoryBytes: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	fs.fleet.SimulateHostLoss("host-1")
	// Terminate via the fleet while the host is down: the fleet forgets the
	// incarnation, but the host (unreachable) keeps running it.
	if err := fs.fleet.Terminate(handle); err != nil {
		t.Fatal(err)
	}
	// Host restarts with an intact backend: it adopts the still-live
	// incarnation the fleet no longer tracks.
	restarted := hostagent.New("host-1", fs.backends["host-1"], nil, fs.ws, 1<<20, fs.slots, 16)
	if len(restarted.IncarnationIDs()) != 1 {
		t.Fatalf("restarted host incarnations = %v", restarted.IncarnationIDs())
	}
	fs.fleet.RegisterHost(restarted)
	if got := fs.fleet.OrphansScrubbed(); got != 1 {
		t.Fatalf("orphans scrubbed = %d, want 1", got)
	}
	if got := restarted.IncarnationIDs(); len(got) != 0 {
		t.Fatalf("orphan still running on host after scrub: %v", got)
	}
}

// L7 regression: a restarted host agent rebuilds ownership and fence state
// from adopted spec metadata, so a replayed pre-restart Create is idempotent
// — same incarnation, capacity charged once.
func TestAdoptedIncarnationFenceIdempotent(t *testing.T) {
	fs := newFleetSystem(t, 1, 4)
	req := hostagent.CreateRequest{
		SandboxID: "sb-adopt", IncarnationID: "inc-adopt-1", Fence: 7, Epoch: 1,
		WorkspaceID: createWSForTest(t, fs), WorkspaceGeneration: 1, MemoryBytes: 48,
	}
	agent := fs.hosts["host-1"]
	h1, err := agent.Create(req)
	if err != nil {
		t.Fatal(err)
	}
	// Host agent restart: new instance over the same backend (adoption).
	restarted := hostagent.New("host-1", fs.backends["host-1"], nil, fs.ws, 1<<20, fs.slots, 16)
	h2, err := restarted.Create(req)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("replayed pre-restart create duplicated incarnation: %v vs %v", h1, h2)
	}
	if got := restarted.IncarnationIDs(); len(got) != 1 {
		t.Fatalf("incarnations after replay = %v, want exactly 1", got)
	}
	if v := restarted.View(); v.UsedSlots != 1 || v.UsedMemory != 48 {
		t.Fatalf("capacity after adoption+replay = %d slots/%d mem, want 1/48", v.UsedSlots, v.UsedMemory)
	}
}

// FC gate (review follow-up 3): a fleet host backed by the Firecracker
// backend runs real microVM incarnations through the same placement,
// capacity, execution, and adoption path as the local backend — the
// prerequisite for the real K8s fleet. Skips without FC_TEST=1/KVM.
func TestFirecrackerHostAgent(t *testing.T) {
	if reason := firecrackerUnavailable(); reason != "" {
		t.Skip(reason)
	}
	backend := firecrackerRuntime(t)
	clock := domain.NewManualClock(time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	outbox := eventservice.NewOutbox()
	store := sandboxmanager.NewMemoryStore()
	fleet := hostagent.NewFleet(clock, nil, ws)
	const mem = int64(256 << 20)
	fleet.DefaultMemory = mem
	agent := hostagent.New("fc-host-1", backend, nil, ws, 1<<30, 4, 16)
	fleet.RegisterHost(agent)
	mgr := sandboxmanager.New(clock, ids, ws, fleet, outbox, store, "fc-host-1")
	d := agentdriver.New(mgr, "tenant-1", "principal-1", 7)

	// The capability intersection of an FC-backed fleet declares VM class.
	if got := fleet.Capabilities().IsolationClass; got != backendinterface.IsolationVM {
		t.Fatalf("fleet isolation class = %v, want VM", got)
	}

	sb, err := d.CreateSandbox("task-fc-fleet")
	if err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, sb.SandboxID)

	// Capacity charges the VM's real memory (Spec.MemoryBytes sizes the
	// microVM via memMiB), not a placeholder.
	v := agent.View()
	if v.UsedSlots != 1 || v.UsedMemory != mem {
		t.Fatalf("host capacity = %d slots/%d bytes, want 1/%d", v.UsedSlots, v.UsedMemory, mem)
	}

	// Exec inside the microVM through the fleet -> host -> vsock path.
	ex, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "echo fc-fleet-ok"})
	if err != nil {
		t.Fatal(err)
	}
	if ex.State != domain.ExecutionCompleted || *ex.ExitCode != 0 {
		t.Fatalf("exec in microVM: %+v", ex)
	}

	// Workspace commit round-trips the live guest workspace.
	content := d.RandomContent(32)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{Writes: map[string]string{"fleet.txt": content}}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.CommitWorkspace(api.CommitWorkspaceRequest{Version: api.SchemaVersionV1, SandboxID: sb.SandboxID}); err != nil {
		t.Fatal(err)
	}

	// Host-agent restart over the same backend adopts the still-live VM
	// incarnation: ownership, fence, and capacity rebuilt from retained spec.
	restarted := hostagent.New("fc-host-1", backend, nil, ws, 1<<30, 4, 16)
	if got := restarted.IncarnationIDs(); len(got) != 1 {
		t.Fatalf("adopted incarnations = %v, want 1", got)
	}
	if v := restarted.View(); v.UsedSlots != 1 || v.UsedMemory != mem {
		t.Fatalf("capacity after adoption = %d slots/%d mem, want 1/%d", v.UsedSlots, v.UsedMemory, mem)
	}

	// Terminate through the manager frees the host's capacity (the fleet
	// still routes to the originally registered agent).
	if err := mgr.Terminate(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	if v := agent.View(); v.UsedSlots != 0 || v.UsedMemory != 0 {
		t.Fatalf("capacity after terminate = %d slots/%d mem, want 0/0", v.UsedSlots, v.UsedMemory)
	}
}

// P1.7 plumbing: a create materializing a checkpoint restore carries the
// checkpoint's host facts (Spec.CheckpointFacts ← CheckpointData.Metadata
// via the manager); the fleet grants the checkpoint-locality bonus only on
// an exact fact match.
func TestRestorePlacementGuard(t *testing.T) {
	fs := newFleetSystem(t, 2, 4)
	wsID := createWSForTest(t, fs)
	spec := func(incID string, facts map[string]string) backendinterface.Spec {
		return backendinterface.Spec{
			SandboxID: "sb-guard", IncarnationID: incID, Epoch: 1,
			WorkspaceID: wsID, WorkspaceGeneration: 1, MemoryBytes: 64,
			CheckpointFacts: facts,
		}
	}
	// Boot an incarnation and pause it: its host then holds the only
	// "cached checkpoint" for sb-guard.
	h1, err := fs.fleet.Create(spec("inc-g1", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.fleet.Start(h1); err != nil {
		t.Fatal(err)
	}
	if err := fs.fleet.Pause(h1); err != nil {
		t.Fatal(err)
	}
	cpHost, _, ok := fs.fleet.PlacementOf("inc-g1")
	if !ok {
		t.Fatal("no placement for inc-g1")
	}
	facts := hostfacts.Current()
	matching := map[string]string{"arch": facts.Arch, "kernel_release": facts.KernelRelease, "cpu_part": facts.CPUPart}
	mismatching := map[string]string{"arch": facts.Arch, "kernel_release": "0.0.0-nonexistent", "cpu_part": facts.CPUPart}
	create := func(incID string, facts map[string]string) string {
		t.Helper()
		if _, err := fs.fleet.Create(spec(incID, facts)); err != nil {
			t.Fatal(err)
		}
		host, _, _ := fs.fleet.PlacementOf(incID)
		return host
	}
	// Matching guard: the checkpoint-holding host wins on the bonus.
	if got := create("inc-g2", matching); got != cpHost {
		t.Fatalf("matching guard placed on %q, want checkpoint host %q", got, cpHost)
	}
	// Nil guard (no restore in play): the bonus still applies (legacy
	// semantics) — the checkpoint host wins again.
	if got := create("inc-g3", nil); got != cpHost {
		t.Fatalf("nil guard placed on %q, want checkpoint host %q (bonus unconditional)", got, cpHost)
	}
	// Mismatching guard: NO bonus — the fuller host wins instead.
	if got := create("inc-g4", mismatching); got == cpHost {
		t.Fatalf("mismatching guard still earned the checkpoint-locality bonus (host %q)", got)
	}
}

// The host agent refuses to publish its own RPC port to a guest: the DNAT
// would hijack heartbeats/RPC into the guest (observed on k3s: host
// declared lost, teardown suppressed, VMM + rules leaked).
func TestPublishProtectsRPCPort(t *testing.T) {
	fs := newFleetSystem(t, 1, 2)
	agent := fs.hosts["host-1"]
	agent.ProtectPorts(8080)
	err := agent.PublishPort(backendinterface.Handle{IncarnationID: "inc-x"}, 9000, 8080)
	if err == nil || !errors.Is(err, backendinterface.ErrPortConflict) {
		t.Fatalf("err = %v, want ErrPortConflict", err)
	}
}

// Routed restore placement (ADR-008): a checkpoint boots only on its ORIGIN
// host — the bits are host-local and the RPC carries them by reference.
// Fleet.Restore re-places a reclaimed incarnation on the origin host under
// a fresh fence, enforces the host-facts guard, and fails honestly (unknown,
// down, or mismatched origin) so the manager can fall back to
// workspace-only recovery.
func TestFleetRestoreOriginHost(t *testing.T) {
	clock := domain.NewManualClock(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
	ws := workspace.NewMemory(clock, domain.NewIDGen())
	fleet := hostagent.NewFleet(clock, nil, ws)
	agents := map[string]*hostagent.HostAgent{}
	for _, id := range []string{"host-1", "host-2"} {
		agent := hostagent.New(id, fakebackend.New(), nil, ws, 1<<20, 4, 16)
		agents[id] = agent
		fleet.RegisterHost(agent)
	}
	wsID, wsGen := commitEmptyWS(t, ws)
	spec := backendinterface.Spec{SandboxID: "sb-1", IncarnationID: "inc-1", Epoch: 1, MemoryBytes: 64, WorkspaceID: wsID, WorkspaceGeneration: wsGen}
	h, err := fleet.Create(spec)
	if err != nil {
		t.Fatal(err)
	}
	origin, _, ok := fleet.PlacementOf(h.IncarnationID)
	if !ok {
		t.Fatal("no placement after create")
	}
	if err := fleet.Start(h); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Pause(h); err != nil {
		t.Fatal(err)
	}
	cp, err := fleet.Snapshot(h)
	if err != nil {
		t.Fatal(err)
	}
	// The host enriched the checkpoint with its accounting facts.
	if cp.Metadata["sandbox_id"] != "sb-1" || cp.Metadata["memory_bytes"] != "64" || cp.Metadata["fence"] == "" {
		t.Fatalf("checkpoint not self-describing: %v", cp.Metadata)
	}

	// Reclaim the incarnation (snapshot-class suspend): placement erased.
	if err := fleet.Terminate(h); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := fleet.PlacementOf(h.IncarnationID); ok {
		t.Fatal("placement retained after terminate")
	}
	if got := agents[origin].View().UsedSlots; got != 0 {
		t.Fatalf("origin host slot not reclaimed: %d", got)
	}

	// Restore with no origin recorded: honest failure, no guessing.
	if _, err := fleet.Restore(cp); !errors.Is(err, backendinterface.ErrNotFound) {
		t.Fatalf("restore without origin host: err = %v", err)
	}
	cp.Metadata["origin_host"] = origin

	// Unknown origin host: honest failure.
	bad := cp
	bad.Metadata = copyMD(cp.Metadata)
	bad.Metadata["origin_host"] = "host-nope"
	if _, err := fleet.Restore(bad); !errors.Is(err, backendinterface.ErrNotFound) {
		t.Fatalf("restore to unknown host: err = %v", err)
	}

	// Guard mismatch: the recorded facts must match the origin host.
	bad2 := cp
	bad2.Metadata = copyMD(cp.Metadata)
	bad2.Metadata["kernel_release"] = "bogus-0.0.0"
	if _, err := fleet.Restore(bad2); !errors.Is(err, supervisor.ErrUnsupported) {
		t.Fatalf("restore with mismatched guard: err = %v", err)
	}

	// The happy path lands on the origin host — never the better-scored
	// peer — under a fresh fence, with capacity re-charged exactly once.
	h2, err := fleet.Restore(cp)
	if err != nil {
		t.Fatal(err)
	}
	if h2 != h {
		t.Fatalf("restored handle = %v, want %v", h2, h)
	}
	gotHost, fence, ok := fleet.PlacementOf(h2.IncarnationID)
	if !ok || gotHost != origin {
		t.Fatalf("restored placement = %q, %v; want origin %q", gotHost, ok, origin)
	}
	if fence != 2 {
		t.Fatalf("restore fence = %d, want 2 (fresh placement)", fence)
	}
	if got := agents[origin].View().UsedSlots; got != 1 {
		t.Fatalf("origin host slots after restore = %d, want 1", got)
	}

	// A down origin host fails the restore honestly.
	if err := fleet.Terminate(h2); err != nil {
		t.Fatal(err)
	}
	fleet.SimulateHostLoss(origin)
	if _, err := fleet.Restore(cp); !errors.Is(err, backendinterface.ErrRuntimeGone) {
		t.Fatalf("restore with origin host down: err = %v", err)
	}
}

// A checkpoint whose incarnation is still LIVE (STOP/CONT class — never
// terminated) restores in place: no re-placement, no new fence, no extra
// capacity charge.
func TestFleetRestoreLiveIncarnationInPlace(t *testing.T) {
	clock := domain.NewManualClock(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
	ws := workspace.NewMemory(clock, domain.NewIDGen())
	fleet := hostagent.NewFleet(clock, nil, ws)
	agent := hostagent.New("host-1", fakebackend.New(), nil, ws, 1<<20, 4, 16)
	fleet.RegisterHost(agent)
	wsID, wsGen := commitEmptyWS(t, ws)
	spec := backendinterface.Spec{SandboxID: "sb-1", IncarnationID: "inc-1", Epoch: 1, MemoryBytes: 64, WorkspaceID: wsID, WorkspaceGeneration: wsGen}
	h, err := fleet.Create(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := fleet.Start(h); err != nil {
		t.Fatal(err)
	}
	if err := fleet.Pause(h); err != nil {
		t.Fatal(err)
	}
	cp, err := fleet.Snapshot(h)
	if err != nil {
		t.Fatal(err)
	}
	// No origin_host in the metadata: the live placement routes the restore.
	h2, err := fleet.Restore(cp)
	if err != nil {
		t.Fatal(err)
	}
	if h2 != h {
		t.Fatalf("restored handle = %v, want %v", h2, h)
	}
	_, fence, ok := fleet.PlacementOf(h2.IncarnationID)
	if !ok || fence != 1 {
		t.Fatalf("live restore re-placed: fence = %d, ok = %v", fence, ok)
	}
	if got := agent.View().UsedSlots; got != 1 {
		t.Fatalf("slots after in-place restore = %d, want 1", got)
	}
}

func copyMD(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func commitEmptyWS(t *testing.T, ws *workspace.Memory) (string, int64) {
	t.Helper()
	w, err := ws.Create("tenant-1", "")
	if err != nil {
		t.Fatal(err)
	}
	head, err := ws.GetHead(w.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	gen, err := ws.Commit(w.WorkspaceID, head.Generation, map[string]string{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return w.WorkspaceID, gen.Generation
}
