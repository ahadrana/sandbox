// Package chaos is the deterministic fault-injection qualification runner
// (PLAN §14). It drives the agent driver through seeded randomized mixed
// workloads across many sandboxes and tenants while injecting the fault
// menu the architecture supports, then asserts contract properties (not
// exact sequences): no cross-tenant leakage, no silent state loss, exactly
// one logical execution per idempotency key, epoch resets iff continuity
// was lost, committed workspace integrity, and valid end states.
package chaos

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/control-plane/scheduler"
	"github.com/agent-sandbox/platform/domain"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	fakebackend "github.com/agent-sandbox/platform/runtime/fake-backend"
	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
	localbackend "github.com/agent-sandbox/platform/runtime/local-backend"
	"github.com/agent-sandbox/platform/workspace"
)

// Config parameterizes one chaos run.
type Config struct {
	Seed      int64
	Ops       int
	Fleet     bool // false: fake backend; true: 2-host fleet of local backends
	Sandboxes int  // sandbox pool size
}

// Report summarizes a finished run.
type Report struct {
	FaultsInjected map[string]int
	OpsFailed      map[string]int // tolerated failures by kind
}

// flakyWS fails the next failNext workspace-store operations, then
// recovers: operations must fail cleanly and retries succeed.
type flakyWS struct {
	inner    workspace.Store
	failNext int
	injected int
}

func (f *flakyWS) fail() error {
	if f.failNext > 0 {
		f.failNext--
		f.injected++
		return errors.New("chaos: transient workspace-store failure")
	}
	return nil
}

func (f *flakyWS) Create(tenantID, base string) (domain.Workspace, error) {
	if err := f.fail(); err != nil {
		return domain.Workspace{}, err
	}
	return f.inner.Create(tenantID, base)
}
func (f *flakyWS) Materialize(id string, gen int64) (map[string]string, error) {
	if err := f.fail(); err != nil {
		return nil, err
	}
	return f.inner.Materialize(id, gen)
}
func (f *flakyWS) Commit(id string, parent int64, manifest map[string]string, cause *string) (domain.WorkspaceGeneration, error) {
	if err := f.fail(); err != nil {
		return domain.WorkspaceGeneration{}, err
	}
	return f.inner.Commit(id, parent, manifest, cause)
}
func (f *flakyWS) GetHead(id string) (domain.WorkspaceGeneration, error) {
	if err := f.fail(); err != nil {
		return domain.WorkspaceGeneration{}, err
	}
	return f.inner.GetHead(id)
}
func (f *flakyWS) ReadManifest(id string, gen int64) (map[string]string, error) {
	if err := f.fail(); err != nil {
		return nil, err
	}
	return f.inner.ReadManifest(id, gen)
}
func (f *flakyWS) Pin(id string, gen int64) error {
	if err := f.fail(); err != nil {
		return err
	}
	return f.inner.Pin(id, gen)
}
func (f *flakyWS) Unpin(id string, gen int64) error {
	if err := f.fail(); err != nil {
		return err
	}
	return f.inner.Unpin(id, gen)
}
func (f *flakyWS) GC(id string) (int, error) {
	if err := f.fail(); err != nil {
		return 0, err
	}
	return f.inner.GC(id)
}

type runState struct {
	t      *testing.T
	cfg    Config
	rng    *rand.Rand
	clock  *domain.ManualClock
	ids    *domain.IDGen
	ws     *flakyWS
	outbox *eventservice.Outbox
	store  *sandboxmanager.MemoryStore
	mgr    *sandboxmanager.Manager
	fleet  *hostagent.Fleet
	fake   *fakebackend.Backend
	hosts  map[string]*hostagent.HostAgent

	drivers map[string]*agentdriver.Driver
	pool    []string // sandbox IDs
	tenant  map[string]string
	class   map[string]string // sandbox workload class ("")

	committed    map[string]map[string]string // sandboxID -> file -> content
	terminated   map[string]bool
	materialized map[string]bool
	killed       map[string]bool // runtime loss since last successful materialize
	idemKeys     map[string]string
	faults       map[string]int
	failures     map[string]int
	suspendMode  map[string]string // sandboxID -> last suspend event mode
	lossySeen    map[string]int
	lossy        *eventservice.Consumer
	restarts     int
}

var tenants = []string{"tenant-a", "tenant-b"}

// Run executes one seeded chaos run and asserts all contract properties.
func Run(t *testing.T, cfg Config) Report {
	t.Helper()
	if cfg.Sandboxes == 0 {
		cfg.Sandboxes = 8
	}
	r := &runState{
		t: t, cfg: cfg, rng: rand.New(rand.NewSource(cfg.Seed)),
		clock: domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)), ids: domain.NewIDGen(),
		outbox: eventservice.NewOutbox(), store: sandboxmanager.NewMemoryStore(),
		hosts:   map[string]*hostagent.HostAgent{},
		drivers: map[string]*agentdriver.Driver{}, tenant: map[string]string{},
		class: map[string]string{}, committed: map[string]map[string]string{},
		terminated: map[string]bool{}, materialized: map[string]bool{}, killed: map[string]bool{},
		idemKeys: map[string]string{}, faults: map[string]int{}, failures: map[string]int{},
		suspendMode: map[string]string{}, lossySeen: map[string]int{},
	}
	r.ws = &flakyWS{inner: workspace.NewMemory(r.clock, r.ids)}
	var rt sandboxmanager.Runtime
	if cfg.Fleet {
		r.fleet = hostagent.NewFleet(r.clock, nil, r.ws)
		for i := 0; i < 2; i++ {
			backend, err := localbackend.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			agent := hostagent.New(fmt.Sprintf("host-%d", i+1), backend, nil, r.ws, 1<<20, 8, 16)
			r.hosts[fmt.Sprintf("host-%d", i+1)] = agent
			r.fleet.RegisterHost(agent)
		}
		rt = r.fleet
	} else {
		r.fake = fakebackend.New()
		rt = r.fake
	}
	r.mgr = sandboxmanager.New(r.clock, r.ids, r.ws, rt, r.outbox, r.store, "host-1")
	for _, tenant := range tenants {
		r.drivers[tenant] = agentdriver.New(r.mgr, tenant, "principal-"+tenant, cfg.Seed)
	}

	// Consumer-outage simulation: this consumer polls only rarely during
	// the run, then must catch up with every event exactly once.
	r.lossy = eventservice.NewConsumer()
	for i := 0; i < cfg.Ops; i++ {
		r.step()
		if r.rng.Intn(100) < 10 {
			r.pollLossy()
		}
		if err := r.mgr.Tick(50); err != nil {
			t.Fatalf("tick: %v", err)
		}
	}
	r.ws.failNext = 0 // drain any armed fault before final assertions
	r.assertProperties()
	return Report{FaultsInjected: r.faults, OpsFailed: r.failures}
}

func (r *runState) step() {
	op := r.rng.Intn(14)
	switch {
	case op <= 2 && len(r.pool) < r.cfg.Sandboxes:
		r.opCreate()
	case op <= 5:
		r.opExec()
	case op == 6:
		r.opSuspendResume()
	case op == 7:
		r.opTerminate()
	case op == 8:
		r.opKillRuntime()
	case op == 9:
		r.opManagerRestart()
	case op == 10:
		r.opSupervisorKill()
	case op == 11:
		r.opIdempotentRetry()
	case op == 12:
		r.opCacheLoss()
	default:
		r.opWorkspaceFault()
	}
}

func (r *runState) driver(tenant string) *agentdriver.Driver {
	return r.drivers[tenant]
}

// tolerate records an expected chaos failure; anything else is fatal.
func (r *runState) tolerate(kind string, err error) bool {
	if err == nil {
		return true
	}
	var epochErr *domain.EpochConflictError
	var quotaErr *domain.QuotaExceededError
	switch {
	case errors.Is(err, domain.ErrIllegalState), errors.Is(err, domain.ErrNotFound),
		errors.Is(err, domain.ErrIllegalTransition),
		errors.Is(err, scheduler.ErrNoCapacity), errors.Is(err, domain.ErrEgressDenied),
		errors.As(err, &epochErr), errors.As(err, &quotaErr),
		errors.Is(err, backendinterface.ErrRuntimeGone),
		errors.Is(err, supervisor.ErrNotFound):
		r.failures[kind]++
		return false
	}
	if strings.Contains(err.Error(), "transient workspace-store failure") ||
		strings.Contains(err.Error(), "supervisor") {
		r.failures[kind]++
		return false
	}
	r.t.Fatalf("op %s: unexpected error: %v", kind, err)
	return false
}

func (r *runState) opCreate() {
	tenant := tenants[r.rng.Intn(len(tenants))]
	sb, err := r.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: tenant, TaskRef: "chaos-task",
		EnvironmentID: "env-base-1", PolicyRef: "policy-default",
	})
	if err != nil {
		r.tolerate("create", err) // transient ws-store failure: clean failure
		return
	}
	r.pool = append(r.pool, sb.SandboxID)
	r.tenant[sb.SandboxID] = tenant
	r.committed[sb.SandboxID] = map[string]string{}
	if r.rng.Intn(100) < 70 {
		r.materialize(sb.SandboxID)
	}
}

func (r *runState) live() []string {
	var out []string
	for _, id := range r.pool {
		if !r.terminated[id] {
			out = append(out, id)
		}
	}
	return out
}

func (r *runState) pickLive() string {
	live := r.live()
	if len(live) == 0 {
		return ""
	}
	return live[r.rng.Intn(len(live))]
}

func (r *runState) materialize(id string) {
	d := r.driver(r.tenant[id])
	report, err := d.EnsureMaterialized(id)
	if !r.tolerate("materialize", err) {
		return
	}
	if report == nil {
		return
	}
	// No silent state loss: a runtime kill since the last successful
	// materialize must be reported.
	if r.killed[id] && report.PriorEpoch > 0 && report.NewEpoch > report.PriorEpoch && !report.UncommittedStateLost {
		r.t.Fatalf("sandbox %s: uncommitted loss after kill not reported (epoch %d -> %d)", id, report.PriorEpoch, report.NewEpoch)
	}
	r.killed[id] = false
	r.materialized[id] = true
}

func (r *runState) opExec() {
	id := r.pickLive()
	if id == "" {
		return
	}
	d := r.driver(r.tenant[id])
	file := fmt.Sprintf("chaos-%d.txt", r.rng.Intn(1000))
	content := fmt.Sprintf("data-%d", r.rng.Intn(1<<30))
	if _, err := d.ExecSync(id, domain.Operation{Writes: map[string]string{file: content}}); !r.tolerate("exec", err) {
		return
	}
	r.committed[id][file] = content
}

func (r *runState) opSuspendResume() {
	id := r.pickLive()
	if id == "" {
		return
	}
	if err := r.mgr.Suspend(id); err != nil {
		r.tolerate("suspend", err)
		return
	}
	r.faults["suspend"]++
	mode := ""
	events, _ := r.outbox.Replay(0)
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].EventType == domain.EventSandboxSuspended && events[i].Payload["sandbox_id"] == id {
			mode, _ = events[i].Payload["mode"].(string)
			break
		}
	}
	r.suspendMode[id] = mode
	corrupt := !r.cfg.Fleet && mode == "execution_state" && r.rng.Intn(100) < 30
	if corrupt {
		r.fake.Faults.CorruptCheckpoint = true
	}
	before := mustResetCount(r, id)
	report, err := r.mgr.Resume(id)
	if corrupt {
		r.fake.Faults.CorruptCheckpoint = false
		r.faults["checkpoint_corrupt"]++
	}
	if !r.tolerate("resume", err) {
		return
	}
	// Epoch reset iff volatile continuity was lost: a continuity resume
	// retains the epoch and must not emit ExecutionStateReset.
	after := mustResetCount(r, id)
	if mode == "execution_state" && report.NewEpoch == report.PriorEpoch && after != before {
		r.t.Fatalf("sandbox %s: ExecutionStateReset emitted despite continuity resume", id)
	}
	if report.NewEpoch > report.PriorEpoch && after == before {
		r.t.Fatalf("sandbox %s: epoch incremented without ExecutionStateReset", id)
	}
	r.killed[id] = false
}

func mustResetCount(r *runState, sandboxID string) int {
	events, _ := r.outbox.Replay(0)
	n := 0
	for _, ev := range events {
		if ev.EventType == domain.EventExecutionStateReset && ev.Payload["sandbox_id"] == sandboxID {
			n++
		}
	}
	return n
}

func (r *runState) opTerminate() {
	id := r.pickLive()
	if id == "" {
		return
	}
	if err := r.mgr.Terminate(id); err != nil {
		r.tolerate("terminate", err)
		return
	}
	r.terminated[id] = true
}

func (r *runState) opKillRuntime() {
	id := r.pickLive()
	if id == "" {
		return
	}
	if err := r.mgr.KillRuntime(id); err != nil {
		r.tolerate("kill_runtime", err)
		return
	}
	r.faults["kill_runtime"]++
	if r.materialized[id] {
		r.killed[id] = true
	}
}

func (r *runState) opManagerRestart() {
	mgr, err := sandboxmanager.NewFromStore(r.clock, r.ids, r.store, r.ws, r.currentRuntime(), r.outbox, "host-1")
	if err != nil {
		r.tolerate("manager_restart", err)
		return
	}
	r.mgr = mgr
	r.restarts++
	// Fresh idempotency-key stream: reusing pre-restart keys would
	// idempotently replay old executions (that is the contract working —
	// the client must not reuse keys across incarnations of itself).
	for tenant := range r.drivers {
		// Unique principal per control-plane incarnation: idempotency keys
		// embed it, and a client must never reuse keys across its own
		// restarts (that replay protection is the contract working).
		principal := fmt.Sprintf("principal-%s-r%d", tenant, r.restarts)
		r.drivers[tenant] = agentdriver.New(mgr, tenant, principal, r.cfg.Seed)
	}
	r.faults["manager_restart"]++
}

func (r *runState) currentRuntime() sandboxmanager.Runtime {
	if r.cfg.Fleet {
		return r.fleet
	}
	return r.fake
}

func (r *runState) opSupervisorKill() {
	if r.cfg.Fleet {
		// Fleet mode: declare a host lost; the manager must reconcile and
		// rematerialize elsewhere.
		for hostID := range r.hosts {
			r.fleet.SimulateHostLoss(hostID)
			for i := 0; i < 4; i++ {
				if err := r.mgr.Tick(50); err != nil {
					r.t.Fatalf("tick: %v", err)
				}
			}
			r.fleet.RegisterHost(r.hosts[hostID]) // heal for later ops
			r.faults["host_loss"]++
			for _, id := range r.live() {
				if r.materialized[id] {
					r.killed[id] = true
				}
			}
			return
		}
		return
	}
	// Fake mode: transient supervisor death on the next exec.
	r.fake.Faults.SupervisorDead = true
	id := r.pickLive()
	if id != "" {
		r.opExec()
	}
	r.fake.Faults.SupervisorDead = false
	r.faults["supervisor_dead"]++
}

func (r *runState) opIdempotentRetry() {
	id := r.pickLive()
	if id == "" {
		return
	}
	key := fmt.Sprintf("chaos-key-%d", r.rng.Int63())
	req := api.StartExecutionRequest{
		Version: api.SchemaVersionV1, SandboxID: id, PrincipalID: "chaos",
		IdempotencyKey: key, Operation: domain.Operation{Writes: map[string]string{"idem": key}},
	}
	first, err := r.mgr.StartExecution(req)
	if !r.tolerate("idem_first", err) {
		return
	}
	// Simulated lost ACK: the client retries the identical request.
	second, err := r.mgr.StartExecution(req)
	if !r.tolerate("idem_retry", err) {
		return
	}
	if first.ExecutionID != second.ExecutionID {
		r.t.Fatalf("idempotency key %s produced two executions: %s, %s", key, first.ExecutionID, second.ExecutionID)
	}
	if prev, ok := r.idemKeys[key]; ok && prev != first.ExecutionID {
		r.t.Fatalf("idempotency key %s rebound: %s -> %s", key, prev, first.ExecutionID)
	}
	r.idemKeys[key] = first.ExecutionID
	r.faults["lost_ack_retry"]++
}

func (r *runState) opCacheLoss() {
	if !r.cfg.Fleet {
		return
	}
	for _, agent := range r.hosts {
		agent.Cache().Flush()
	}
	r.faults["cache_flush"]++
	// Refetch path: rematerialize any lost sandbox.
	for _, id := range r.live() {
		r.materialize(id)
		return
	}
}

func (r *runState) opWorkspaceFault() {
	r.ws.failNext = 1 + r.rng.Intn(2)
	r.faults["ws_transient"]++
	// Whatever operation runs next fails cleanly; retry succeeds.
	id := r.pickLive()
	if id != "" {
		r.materialize(id)
	}
}

func (r *runState) pollLossy() {
	for _, ev := range r.lossy.Poll(r.outbox) {
		r.lossySeen[ev.EventID]++
	}
}

// assertProperties checks the contract invariants over the whole run.
func (r *runState) assertProperties() {
	t := r.t
	events, _ := r.outbox.Replay(0)

	// Consumer outage + duplicate delivery: the starved consumer catches
	// up with every event exactly once; a re-poll yields nothing.
	r.pollLossy()
	if len(r.lossySeen) != len(events) {
		t.Fatalf("consumer lost events: saw %d of %d", len(r.lossySeen), len(events))
	}
	for id, n := range r.lossySeen {
		if n != 1 {
			t.Fatalf("duplicate delivery of event %s (%d times)", id, n)
		}
	}
	if again := r.lossy.Poll(r.outbox); len(again) != 0 {
		t.Fatalf("re-poll delivered %d duplicate events", len(again))
	}

	// Cross-tenant isolation + valid end states + reset consistency.
	for _, ev := range events {
		sbID, _ := ev.Payload["sandbox_id"].(string)
		if sbID == "" {
			sbID = ev.AggregateID
		}
		if tenant, ok := r.tenant[sbID]; ok && ev.TenantID != tenant {
			t.Fatalf("cross-tenant leakage: event %s tenant %s, sandbox %s tenant %s", ev.EventType, ev.TenantID, sbID, tenant)
		}
		if ev.EventType == domain.EventExecutionStateReset {
			prior, _ := ev.Payload["prior_epoch"].(int64)
			next, _ := ev.Payload["new_epoch"].(int64)
			if next != prior+1 {
				t.Fatalf("reset epochs incoherent: %d -> %d", prior, next)
			}
		}
	}
	valid := map[domain.SandboxState]bool{
		domain.SandboxUnmaterialized: true, domain.SandboxRunning: true,
		// Transient states are reconcilable: a run may end mid-flight.
		domain.SandboxStarting: true, domain.SandboxSuspending: true, domain.SandboxResuming: true,
		domain.SandboxBackgroundActive: true, domain.SandboxQuiescent: true,
		domain.SandboxSuspended: true, domain.SandboxTerminated: true,
		domain.SandboxFailed: true,
	}
	for _, id := range r.pool {
		sb, err := r.mgr.GetSandbox(id)
		if err != nil {
			t.Fatalf("get sandbox %s: %v", id, err)
		}
		if !valid[sb.ObservedState] {
			t.Fatalf("sandbox %s in invalid end state %s", id, sb.ObservedState)
		}
		if r.terminated[id] && sb.ObservedState != domain.SandboxTerminated {
			t.Fatalf("sandbox %s terminated but state %s", id, sb.ObservedState)
		}
		for _, ex := range r.mgr.Executions(id) {
			if ex.TenantID != r.tenant[id] {
				t.Fatalf("cross-tenant execution %s on sandbox %s", ex.ExecutionID, id)
			}
		}
	}

	// Committed workspace integrity: head digest present and every
	// committed write observable at head.
	for id, files := range r.committed {
		sb, err := r.mgr.GetSandbox(id)
		if err != nil {
			t.Fatal(err)
		}
		head, err := r.ws.GetHead(sb.WorkspaceID)
		if err != nil {
			t.Fatal(err)
		}
		if len(files) > 0 && head.IntegrityDigest == "" {
			t.Fatalf("sandbox %s: committed head missing integrity digest", id)
		}
		manifest, err := r.ws.ReadManifest(sb.WorkspaceID, head.Generation)
		if err != nil {
			t.Fatal(err)
		}
		for file, content := range files {
			if manifest[file] != content {
				t.Fatalf("sandbox %s: committed file %s lost or corrupt (want %q, got %q)", id, file, content, manifest[file])
			}
		}
	}
}
