package hostagent

import (
	"sync"
	"time"

	"github.com/agent-sandbox/platform/control-plane/scheduler"
	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/runtime/backend-interface"
	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

// heartbeatMissThreshold is how many consecutive fleet ticks a host may miss
// before it is declared lost.
const heartbeatMissThreshold = 3

// Fleet is the simulated execution fleet: it routes every manager operation
// through placement and the owning host agent, tracks heartbeats, and
// declares hosts lost after missed heartbeats. It satisfies the
// sandboxmanager.Runtime contract.
type Fleet struct {
	mu    sync.Mutex
	clock domain.Clock
	sched *scheduler.Scheduler
	envs  EnvironmentSource
	ws    WorkspaceStore

	hosts        map[string]*HostAgent
	down         map[string]bool
	missed       map[string]int
	lostDeclared map[string]bool
	lastSeen     map[string]time.Time

	byIncarnation   map[string]string // incarnationID -> hostID
	fenceOf         map[string]int64  // incarnationID -> fence
	pendingLost     []string          // incarnation IDs awaiting manager reconciliation
	orphansScrubbed int               // host incarnations scrubbed at re-registration
	DefaultMemory   int64

	capacityFailures int // consecutive capacity-caused placement failures
	lowUtilTicks     int // consecutive ticks with utilization below threshold
}

// ScaleRecommendation is the fleet's deterministic autoscaling signal
// (PLAN §13): add hosts after sustained capacity placement failures,
// remove hosts after sustained low utilization. Emitted, never enacted.
type ScaleRecommendation struct {
	AddHosts    int
	RemoveHosts int
	Reason      string
}

const (
	scaleOutFailureThreshold = 3
	scaleInUtilThreshold     = 0.2
	scaleInTickThreshold     = 5
)

// Recommendation returns the current autoscaling signal (zero value: hold).
func (f *Fleet) Recommendation() ScaleRecommendation {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.capacityFailures >= scaleOutFailureThreshold {
		return ScaleRecommendation{AddHosts: f.capacityFailures / scaleOutFailureThreshold, Reason: "sustained capacity placement failures"}
	}
	if f.lowUtilTicks >= scaleInTickThreshold {
		healthy := 0
		for id := range f.hosts {
			if !f.down[id] {
				healthy++
			}
		}
		if healthy > 1 {
			return ScaleRecommendation{RemoveHosts: healthy - 1, Reason: "sustained low utilization"}
		}
	}
	return ScaleRecommendation{}
}

func NewFleet(clock domain.Clock, envs EnvironmentSource, ws WorkspaceStore) *Fleet {
	return &Fleet{
		clock: clock, sched: scheduler.New(), envs: envs, ws: ws,
		hosts: map[string]*HostAgent{}, down: map[string]bool{},
		missed: map[string]int{}, lostDeclared: map[string]bool{},
		lastSeen:      map[string]time.Time{},
		byIncarnation: map[string]string{}, fenceOf: map[string]int64{},
		DefaultMemory: 128,
	}
}

// RegisterHost registers (or re-registers, e.g. after a host restart) a
// host. On re-registration, any incarnation the host still runs that the
// fleet no longer tracks — for example terminated via the fleet while the
// host was lost — is an orphan: it is scrubbed (terminated) and counted so
// the compute is owned and accounted again (INV-016).
func (f *Fleet) RegisterHost(h *HostAgent) {
	for _, incID := range h.IncarnationIDs() {
		f.mu.Lock()
		_, known := f.byIncarnation[incID]
		f.mu.Unlock()
		if !known {
			h.Terminate(backendinterface.Handle{IncarnationID: incID})
			f.mu.Lock()
			f.orphansScrubbed++
			f.mu.Unlock()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts[h.HostID()] = h
	f.down[h.HostID()] = false
	f.missed[h.HostID()] = 0
	f.lostDeclared[h.HostID()] = false
	f.lastSeen[h.HostID()] = f.clock.Now()
}

// OrphansScrubbed reports how many orphaned host incarnations the fleet has
// terminated at host (re-)registration.
func (f *Fleet) OrphansScrubbed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.orphansScrubbed
}

// SimulateHostLoss cuts heartbeats and reachability for a host.
func (f *Fleet) SimulateHostLoss(hostID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down[hostID] = true
	f.missed[hostID] = 0
}

func (f *Fleet) hostOf(handle backendinterface.Handle) (*HostAgent, bool, error) {
	hostID, ok := f.byIncarnation[handle.IncarnationID]
	if !ok {
		return nil, false, backendinterface.ErrNotFound
	}
	h := f.hosts[hostID]
	return h, f.down[hostID], nil
}

// PlacementOf exposes the placement (host, fence) of an incarnation.
func (f *Fleet) PlacementOf(incarnationID string) (string, int64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	hostID, ok := f.byIncarnation[incarnationID]
	return hostID, f.fenceOf[incarnationID], ok
}

// LostIncarnations consumes the list of incarnations whose hosts were
// declared lost since the last call.
func (f *Fleet) LostIncarnations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.pendingLost
	f.pendingLost = nil
	return out
}

// Create places the incarnation and forwards a fenced create to the host.
func (f *Fleet) Create(spec backendinterface.Spec) (backendinterface.Handle, error) {
	f.mu.Lock()
	views := make([]scheduler.HostView, 0, len(f.hosts))
	for id, h := range f.hosts {
		if f.down[id] {
			continue
		}
		views = append(views, h.View())
	}
	mem := spec.MemoryBytes
	if mem == 0 {
		mem = f.DefaultMemory
	}
	placement, err := f.sched.Place(scheduler.Request{
		SandboxID:      spec.SandboxID,
		EnvironmentID:  spec.EnvironmentID,
		WorkspaceID:    spec.WorkspaceID,
		MemoryRequired: mem,
		Priority:       spec.Priority,
	}, views)
	if err != nil {
		f.capacityFailures++
		f.mu.Unlock()
		return backendinterface.Handle{}, err
	}
	f.capacityFailures = 0
	host := f.hosts[placement.HostID]
	f.mu.Unlock()

	handle, err := host.Create(CreateRequest{
		SandboxID:           spec.SandboxID,
		IncarnationID:       spec.IncarnationID,
		Fence:               placement.Fence,
		Epoch:               spec.Epoch,
		EnvironmentID:       spec.EnvironmentID,
		WorkspaceID:         spec.WorkspaceID,
		WorkspaceGeneration: spec.WorkspaceGeneration,
		MemoryBytes:         mem,
	})
	if err != nil {
		return backendinterface.Handle{}, err
	}
	f.mu.Lock()
	f.byIncarnation[handle.IncarnationID] = placement.HostID
	f.fenceOf[handle.IncarnationID] = placement.Fence
	f.mu.Unlock()
	return handle, nil
}

func (f *Fleet) Start(h backendinterface.Handle) error {
	host, down, err := f.hostOf(h)
	if err != nil {
		return err
	}
	if down {
		return backendinterface.ErrRuntimeGone
	}
	return host.Start(h)
}

func (f *Fleet) Pause(h backendinterface.Handle) error {
	host, _, err := f.hostOf(h)
	if err != nil {
		return err
	}
	return host.Pause(h)
}

func (f *Fleet) Resume(h backendinterface.Handle) error {
	host, _, err := f.hostOf(h)
	if err != nil {
		return err
	}
	return host.Resume(h)
}

func (f *Fleet) Snapshot(h backendinterface.Handle) (backendinterface.CheckpointData, error) {
	host, _, err := f.hostOf(h)
	if err != nil {
		return backendinterface.CheckpointData{}, err
	}
	return host.Snapshot(h)
}

func (f *Fleet) Restore(cp backendinterface.CheckpointData) (backendinterface.Handle, error) {
	return backendinterface.Handle{}, supervisor.ErrUnsupported
}

// Terminate scrubs the incarnation on its host; a lost host is cleaned up
// locally without error.
func (f *Fleet) Terminate(h backendinterface.Handle) error {
	f.mu.Lock()
	host, down, err := f.hostOf(h)
	delete(f.byIncarnation, h.IncarnationID)
	delete(f.fenceOf, h.IncarnationID)
	f.mu.Unlock()
	if err != nil {
		return nil
	}
	if down {
		return nil
	}
	return host.Terminate(h)
}

func (f *Fleet) Stats(h backendinterface.Handle) (backendinterface.Stats, error) {
	host, down, err := f.hostOf(h)
	if err != nil {
		return backendinterface.Stats{}, err
	}
	if down {
		return backendinterface.Stats{}, backendinterface.ErrRuntimeGone
	}
	return host.Stats(h)
}

// Exec forwards through the owning host to the incarnation's supervisor —
// the seam a real transport proxy replaces later (PLAN §8).
func (f *Fleet) Exec(h backendinterface.Handle, executionID string, op domain.Operation) error {
	host, down, err := f.hostOf(h)
	if err != nil {
		return err
	}
	if down {
		return backendinterface.ErrRuntimeGone
	}
	return host.Exec(h, executionID, op)
}

func (f *Fleet) WaitExecution(h backendinterface.Handle, executionID string) (supervisor.Result, error) {
	host, down, err := f.hostOf(h)
	if err != nil {
		return supervisor.Result{}, err
	}
	if down {
		return supervisor.Result{}, backendinterface.ErrRuntimeGone
	}
	return host.WaitExecution(h, executionID)
}

func (f *Fleet) LiveNonBaselineDescendants(h backendinterface.Handle) int {
	host, down, err := f.hostOf(h)
	if err != nil || down {
		return 0
	}
	return host.LiveNonBaselineDescendants(h)
}

// ProcessInventory routes to the host owning the incarnation.
func (f *Fleet) ProcessInventory(h backendinterface.Handle) ([]supervisor.ProcessInfo, error) {
	host, down, err := f.hostOf(h)
	if err != nil {
		return nil, err
	}
	if down {
		return nil, nil
	}
	return host.ProcessInventory(h)
}

func (f *Fleet) TerminateBackground(h backendinterface.Handle) error {
	host, down, err := f.hostOf(h)
	if err != nil {
		return err
	}
	if down {
		return nil
	}
	return host.TerminateBackground(h)
}

func (f *Fleet) LiveDescendants(h backendinterface.Handle) int {
	host, down, err := f.hostOf(h)
	if err != nil || down {
		return 0
	}
	return host.LiveDescendants(h)
}

func (f *Fleet) WorkspaceFiles(h backendinterface.Handle) (map[string]string, error) {
	host, down, err := f.hostOf(h)
	if err != nil {
		return nil, err
	}
	if down {
		return nil, backendinterface.ErrRuntimeGone
	}
	return host.WorkspaceFiles(h)
}

func (f *Fleet) Dirty(h backendinterface.Handle) bool {
	host, down, err := f.hostOf(h)
	if err != nil || down {
		return false
	}
	return host.Dirty(h)
}

func (f *Fleet) MarkCommitted(h backendinterface.Handle) {
	host, down, err := f.hostOf(h)
	if err != nil || down {
		return
	}
	host.MarkCommitted(h)
}

func (f *Fleet) KillRuntime(h backendinterface.Handle) {
	f.mu.Lock()
	host, down, err := f.hostOf(h)
	delete(f.byIncarnation, h.IncarnationID)
	delete(f.fenceOf, h.IncarnationID)
	f.mu.Unlock()
	if err != nil || down {
		return
	}
	host.KillRuntime(h)
}

// Alive reports host-reachable incarnation liveness.
func (f *Fleet) Alive(h backendinterface.Handle) bool {
	f.mu.Lock()
	host, down, err := f.hostOf(h)
	f.mu.Unlock()
	if err != nil || down {
		return false
	}
	return host.Alive(h)
}

// Capabilities returns the honest intersection of the fleet's declared
// surfaces: the weakest isolation class and only the features every host
// supports. An empty fleet has zero-value capabilities (declaring VM-class
// with no hosts would be a lie). Restore is declared unsupported because
// Fleet.Restore has no placement routing and returns ErrUnsupported.
func (f *Fleet) Capabilities() backendinterface.Capabilities {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hosts) == 0 {
		return backendinterface.Capabilities{}
	}
	classRank := map[backendinterface.IsolationClass]int{
		backendinterface.IsolationProcess:   0,
		backendinterface.IsolationNamespace: 1,
		backendinterface.IsolationVM:        2,
	}
	var caps backendinterface.Capabilities
	first := true
	for _, h := range f.hosts {
		c := h.Capabilities()
		if first {
			caps = c
			first = false
			continue
		}
		caps.SupportsPause = caps.SupportsPause && c.SupportsPause
		caps.SupportsSnapshot = caps.SupportsSnapshot && c.SupportsSnapshot
		caps.SupportsRestore = caps.SupportsRestore && c.SupportsRestore
		caps.SupportsCheckpoint = caps.SupportsCheckpoint && c.SupportsCheckpoint
		caps.NetworkIsolated = caps.NetworkIsolated && c.NetworkIsolated
		caps.HostCredentialFree = caps.HostCredentialFree && c.HostCredentialFree
		if classRank[c.IsolationClass] < classRank[caps.IsolationClass] {
			caps.IsolationClass = c.IsolationClass
		}
	}
	caps.SupportsRestore = false
	return caps
}

// Tick receives heartbeats from healthy hosts and declares hosts lost after
// heartbeatMissThreshold consecutive misses.
func (f *Fleet) Tick() {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.clock.Now()
	for id, h := range f.hosts {
		if f.down[id] {
			if f.lostDeclared[id] {
				continue
			}
			f.missed[id]++
			if f.missed[id] >= heartbeatMissThreshold {
				f.lostDeclared[id] = true
				for incID, hostID := range f.byIncarnation {
					if hostID == id {
						f.pendingLost = append(f.pendingLost, incID)
					}
				}
			}
			continue
		}
		h.Tick()
		f.lastSeen[id] = now
	}
	// Utilization for the scale-in signal: worst healthy-host slot usage.
	healthy, maxUtil := 0, 0.0
	for id, h := range f.hosts {
		if f.down[id] {
			continue
		}
		healthy++
		v := h.View()
		if v.CapacitySlots > 0 {
			if u := float64(v.UsedSlots) / float64(v.CapacitySlots); u > maxUtil {
				maxUtil = u
			}
		}
	}
	if healthy > 1 && maxUtil < scaleInUtilThreshold {
		f.lowUtilTicks++
	} else {
		f.lowUtilTicks = 0
	}
}
