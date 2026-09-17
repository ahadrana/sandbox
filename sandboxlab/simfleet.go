package sandboxlab

import (
	"fmt"
	"time"

	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/domain"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
	"github.com/agent-sandbox/platform/runtime/hostfacts"
	"github.com/agent-sandbox/platform/workspace"
)

// HostSpec describes one simulated host at fleet-build time.
type HostSpec struct {
	ID          string // empty: auto-named host-N
	MemCapacity int64
	Slots       int
	Facts       hostfacts.Facts
	Latencies   Latencies
	// Pools, when VCPU > 0, enables the phase-6 resource-contention model
	// (fluid fair-sharing of vCPU / I/O / network among in-flight ops).
	Pools Pools
}

// Config describes a simulated world.
type Config struct {
	Seed  int64
	Start time.Time
	Hosts []HostSpec
	// TickCadence is the virtual heartbeat/tick interval: a recurring event
	// drives Manager.Tick(0) (which drives Fleet.Tick) at this cadence. The
	// kernel owns the clock; Tick's duration argument would double-advance
	// it, so the cadence lives in the event schedule instead.
	TickCadence time.Duration
}

// SimFleet composes the real control plane (manager + fleet + scheduler +
// outbox + workspace store) over a set of SimHosts, all on one kernel.
type SimFleet struct {
	Kernel *Kernel
	Mgr    *sandboxmanager.Manager
	Fleet  *hostagent.Fleet
	Outbox *eventservice.Outbox
	WS     *workspace.Memory
	Hosts  map[string]*SimHost // hostID -> host, keyed map; never iterated for decisions
	Engine *Engine             // invariant engine, observing after every kernel event

	tickCadence time.Duration
}

// New builds the simulated world and registers every host with the fleet.
func New(cfg Config) *SimFleet {
	start := cfg.Start
	if start.IsZero() {
		start = time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	}
	k := NewKernel(cfg.Seed, start)
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(k.Clock(), ids)
	outbox := eventservice.NewOutbox()
	fleet := hostagent.NewFleet(k.Clock(), nil, ws)
	sf := &SimFleet{
		Kernel: k, Fleet: fleet, Outbox: outbox, WS: ws,
		Hosts:       map[string]*SimHost{},
		tickCadence: cfg.TickCadence,
	}
	for i, spec := range cfg.Hosts {
		hostID := spec.ID
		if hostID == "" {
			hostID = fmt.Sprintf("host-%d", i+1)
		}
		h := NewSimHost(k, hostID, ws, spec.MemCapacity, spec.Slots, spec.Facts, spec.Latencies)
		h.SetPools(spec.Pools)
		sf.Hosts[hostID] = h
		fleet.RegisterHost(h)
	}
	sf.Mgr = sandboxmanager.New(k.Clock(), ids, ws, fleet, outbox, sandboxmanager.NewMemoryStore(), "cp-sim")
	sf.Engine = NewEngine(sf)
	if cfg.TickCadence > 0 {
		sf.scheduleTick()
	}
	return sf
}

// InvariantReport finalizes the invariant engine over the completed run.
// Scenario tests call this and assert zero violations.
func (sf *SimFleet) InvariantReport() Report { return sf.Engine.Report() }

// JoinOps advances the kernel until every host's contention model is idle
// (ADR-010 phase 6): op completions are kernel wake events, so the scenario
// driver joins here after each top-level step. Flat-mode fleets have no
// queued wakes, making this a no-op. Never call from inside a manager
// operation — wake processing must not re-enter the control plane.
func (sf *SimFleet) JoinOps() {
	sf.Kernel.RunUntilCond(func() bool {
		for _, h := range sf.Hosts {
			if !h.OpsIdle() {
				return false
			}
		}
		return true
	})
}

// scheduleTick installs the recurring virtual-heartbeat event.
func (sf *SimFleet) scheduleTick() {
	sf.Kernel.After(sf.tickCadence, "tick", func() {
		// Manager.Tick(0): the kernel already advanced the clock to this
		// event's time; a nonzero argument would double-advance it.
		_ = sf.Mgr.Tick(0)
		sf.scheduleTick()
	})
}

// KillHost schedules (or performs, when called from an event) host loss:
// the fleet marks it unreachable and heartbeat-miss accounting declares it
// lost after the threshold, feeding the manager's lost-incarnation
// reconciliation — the same path the conformance suite drives by hand.
func (sf *SimFleet) KillHost(hostID string) {
	sf.Fleet.SimulateHostLoss(hostID)
	sf.Kernel.Note("kill " + hostID)
}

// KillHostAt schedules a host kill at a virtual offset.
func (sf *SimFleet) KillHostAt(at time.Duration, hostID string) {
	sf.Kernel.At(at, "kill "+hostID, func() { sf.KillHost(hostID) })
}

// StallHeartbeatsAt schedules a heartbeat stall — in an in-process sim a
// partition IS a stall; the control plane cannot distinguish them
// (ADR-010 §6). ReviveHostAt ends it.
func (sf *SimFleet) StallHeartbeatsAt(at time.Duration, hostID string) {
	sf.KillHostAt(at, hostID)
}

// ReviveHostAt schedules host recovery (fleet.HostSeen clears the down
// latch, per the heartbeat-revival fix).
func (sf *SimFleet) ReviveHostAt(at time.Duration, hostID string) {
	sf.Kernel.At(at, "revive "+hostID, func() {
		sf.Fleet.HostSeen(hostID)
		sf.Kernel.Note("revive " + hostID)
	})
}

// CreateMaterialized schedules a sandbox create+materialize at a virtual
// offset, recording the outcome (and the placed host) in the trace. The
// returned channel-like accessor is unnecessary in a single-threaded sim:
// read Results after Kernel.Run.
func (sf *SimFleet) CreateMaterialized(at time.Duration, tenant, taskRef string) {
	sf.Kernel.At(at, "create "+taskRef, func() {
		sb, err := sf.Mgr.CreateSandbox(api.CreateSandboxRequest{
			Version: api.SchemaVersionV1, TenantID: tenant, TaskRef: taskRef,
		})
		if err != nil {
			sf.Kernel.Note(fmt.Sprintf("create %s err %v", taskRef, err))
			return
		}
		if _, err := sf.Mgr.Materialize(sb.SandboxID); err != nil {
			sf.Kernel.Note(fmt.Sprintf("materialize %s err %v", taskRef, err))
			return
		}
		host, _ := sf.Mgr.HostOf(sb.SandboxID)
		sf.Kernel.Note(fmt.Sprintf("live %s %s host=%s", taskRef, sb.SandboxID, host))
	})
}
