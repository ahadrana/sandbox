package hostagent

import (
	"fmt"
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

// Host is the fleet's view of one runtime host: the full supervision surface
// the fleet routes through. *HostAgent satisfies it in-process; the control
// plane daemon substitutes an HTTP client (runtime/host-agent/rpc) for
// hosts reached across the network — placement, fencing, and loss semantics
// are identical either way.
type Host interface {
	HostID() string
	IncarnationIDs() []string
	Create(req CreateRequest) (backendinterface.Handle, error)
	Terminate(handle backendinterface.Handle) error
	View() scheduler.HostView
	Tick()
	Capabilities() backendinterface.Capabilities
	Start(handle backendinterface.Handle) error
	Pause(handle backendinterface.Handle) error
	Resume(handle backendinterface.Handle) error
	Snapshot(handle backendinterface.Handle) (backendinterface.CheckpointData, error)
	Restore(cp backendinterface.CheckpointData) (backendinterface.Handle, error)
	Stats(handle backendinterface.Handle) (backendinterface.Stats, error)
	Exec(handle backendinterface.Handle, executionID string, op domain.Operation) error
	WaitExecution(handle backendinterface.Handle, executionID string) (supervisor.Result, error)
	LiveNonBaselineDescendants(handle backendinterface.Handle) int
	ProcessInventory(handle backendinterface.Handle) ([]supervisor.ProcessInfo, error)
	TerminateBackground(handle backendinterface.Handle) error
	LiveDescendants(handle backendinterface.Handle) int
	WorkspaceFiles(handle backendinterface.Handle) (map[string]string, error)
	Dirty(handle backendinterface.Handle) bool
	MarkCommitted(handle backendinterface.Handle)
	KillRuntime(handle backendinterface.Handle)
	Alive(handle backendinterface.Handle) bool
	PublishPort(handle backendinterface.Handle, guestPort, hostPort int, fence int64) error
	UnpublishPort(handle backendinterface.Handle, hostPort int, fence int64) error
}

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

	hosts        map[string]Host
	down         map[string]bool
	missed       map[string]int
	lostDeclared map[string]bool
	lastSeen     map[string]time.Time

	byIncarnation map[string]string // incarnationID -> hostID
	fenceOf       map[string]int64  // incarnationID -> fence
	// pendingRestore marks incarnations whose restore RPC is in flight:
	// placement is registered only after the RPC returns (review H4), and a
	// host re-registration in that window must treat the incarnation as
	// owned, never as an orphan to scrub.
	pendingRestore  map[string]bool
	pendingLost     []string // incarnation IDs awaiting manager reconciliation
	orphansScrubbed int      // host incarnations scrubbed at re-registration
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
		hosts: map[string]Host{}, down: map[string]bool{},
		missed: map[string]int{}, lostDeclared: map[string]bool{},
		lastSeen:      map[string]time.Time{},
		byIncarnation: map[string]string{}, fenceOf: map[string]int64{},
		pendingRestore: map[string]bool{},
		DefaultMemory:  128,
	}
}

// RegisterHost registers (or re-registers, e.g. after a host restart) a
// host. On re-registration, any incarnation the host still runs that the
// fleet no longer tracks — for example terminated via the fleet while the
// host was lost — is an orphan: it is scrubbed (terminated) and counted so
// the compute is owned and accounted again (INV-016). Symmetrically, any
// incarnation the fleet tracked on this host that the re-registering host
// no longer runs (agent process restarted empty) is declared lost so the
// manager reconciles it (INV-016: loss is observed, never assumed silent).
func (f *Fleet) RegisterHost(h Host) {
	running := map[string]bool{}
	for _, incID := range h.IncarnationIDs() {
		running[incID] = true
		f.mu.Lock()
		_, known := f.byIncarnation[incID]
		pending := f.pendingRestore[incID]
		f.mu.Unlock()
		// An incarnation with a restore RPC in flight is owned (review H4):
		// its placement registers when the RPC returns, so a host
		// re-registration in that window must not scrub it as an orphan.
		if !known && !pending {
			h.Terminate(backendinterface.Handle{IncarnationID: incID})
			f.mu.Lock()
			f.orphansScrubbed++
			f.mu.Unlock()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for incID, hostID := range f.byIncarnation {
		if hostID == h.HostID() && !running[incID] {
			delete(f.byIncarnation, incID)
			delete(f.fenceOf, incID)
			f.pendingLost = append(f.pendingLost, incID)
		}
	}
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

func (f *Fleet) hostOf(handle backendinterface.Handle) (Host, bool, error) {
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
	req := scheduler.Request{
		SandboxID:      spec.SandboxID,
		EnvironmentID:  spec.EnvironmentID,
		WorkspaceID:    spec.WorkspaceID,
		MemoryRequired: mem,
		Priority:       spec.Priority,
	}
	// P1.7: a create materializing a checkpoint restore carries the
	// checkpoint's host facts — the locality bonus only counts on hosts
	// whose facts match exactly (a mismatched host could not restore it
	// anyway, ADR-001 P0.4 validation).
	if len(spec.CheckpointFacts) > 0 {
		g := scheduler.Guard{
			Arch:          spec.CheckpointFacts["arch"],
			KernelRelease: spec.CheckpointFacts["kernel_release"],
			CPUPart:       spec.CheckpointFacts["cpu_part"],
		}
		// Review L8: an all-empty guard is meaningless (every host would
		// "match") — treat it as no guard, defense in depth even though the
		// manager already filters empty facts out of CheckpointFacts.
		if g != (scheduler.Guard{}) {
			req.CheckpointGuard = &g
		}
	}
	placement, err := f.sched.Place(req, views)
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

// PublishPort routes an endpoint publish to the incarnation's host
// (ADR-007 data plane), carrying the placement fence the host validates
// (review H2).
func (f *Fleet) PublishPort(h backendinterface.Handle, guestPort, hostPort int) error {
	f.mu.Lock()
	host, _, err := f.hostOf(h)
	fence := f.fenceOf[h.IncarnationID]
	f.mu.Unlock()
	if err != nil {
		return err
	}
	return host.PublishPort(h, guestPort, hostPort, fence)
}

// UnpublishPort routes an endpoint unpublish to the incarnation's host; a
// lost host is cleaned locally (its reboot scrubs the rules) and is not an
// error.
func (f *Fleet) UnpublishPort(h backendinterface.Handle, hostPort int) error {
	f.mu.Lock()
	host, down, err := f.hostOf(h)
	fence := f.fenceOf[h.IncarnationID]
	f.mu.Unlock()
	if err != nil || down {
		return nil
	}
	return host.UnpublishPort(h, hostPort, fence)
}

// Restore routes a checkpoint restore to the ORIGIN host (ADR-008):
// checkpoint bits are host-local artifacts and the RPC carries them by
// reference, so only the host that wrote the checkpoint can boot from it.
// An incarnation that is still live (STOP/CONT class, never terminated)
// resumes in place with no re-placement; a reclaimed incarnation is
// re-placed on the origin host under a fresh fence — capacity and the
// checkpoint's host-facts guard (kernel release, CPU part) are enforced,
// so a mismatched or exhausted origin host fails the restore honestly and
// the caller falls back to workspace-only recovery.
func (f *Fleet) Restore(cp backendinterface.CheckpointData) (backendinterface.Handle, error) {
	f.mu.Lock()
	if hostID, ok := f.byIncarnation[cp.IncarnationID]; ok {
		// Live incarnation: it never left its host — resume in place.
		host := f.hosts[hostID]
		down := f.down[hostID]
		f.mu.Unlock()
		if down {
			return backendinterface.Handle{}, backendinterface.ErrRuntimeGone
		}
		return host.Restore(cp)
	}
	origin := cp.Metadata["origin_host"]
	if origin == "" {
		f.mu.Unlock()
		return backendinterface.Handle{}, fmt.Errorf("checkpoint %s records no origin host: %w", cp.IncarnationID, backendinterface.ErrNotFound)
	}
	host, ok := f.hosts[origin]
	if !ok {
		f.mu.Unlock()
		return backendinterface.Handle{}, fmt.Errorf("checkpoint origin host %q not in fleet: %w", origin, backendinterface.ErrNotFound)
	}
	if f.down[origin] {
		f.mu.Unlock()
		return backendinterface.Handle{}, fmt.Errorf("checkpoint origin host %q unavailable: %w", origin, backendinterface.ErrRuntimeGone)
	}
	view := host.View()
	f.mu.Unlock()
	// The checkpoint's recorded host facts must match the origin host
	// exactly — a mismatched host could never boot it (ADR-001 P0.4), and
	// this fleet has no cross-host transfer to route around it.
	if kr := cp.Metadata["kernel_release"]; kr != "" && kr != view.KernelRelease {
		return backendinterface.Handle{}, fmt.Errorf("checkpoint kernel_release %q does not match origin host %q: %w", kr, view.KernelRelease, supervisor.ErrUnsupported)
	}
	if part := cp.Metadata["cpu_part"]; part != "" && part != view.CPUPart {
		return backendinterface.Handle{}, fmt.Errorf("checkpoint cpu_part %q does not match origin host %q: %w", part, view.CPUPart, supervisor.ErrUnsupported)
	}
	var mem int64
	fmt.Sscanf(cp.Metadata["memory_bytes"], "%d", &mem)
	if mem == 0 {
		mem = f.DefaultMemory
	}
	// Placement on the single admissible host: capacity is re-validated and
	// a fresh placement fence issued. A failure here does NOT feed the
	// fleet-wide scale-out counter (review M9): the restore is pinned to
	// the origin host, so a full origin says nothing about fleet capacity —
	// counting it would ratchet a false scale-out signal permanently.
	placement, err := f.sched.Place(scheduler.Request{
		SandboxID:      cp.Metadata["sandbox_id"],
		MemoryRequired: mem,
	}, []scheduler.HostView{view})
	if err != nil {
		return backendinterface.Handle{}, err
	}
	// Review H4: register a PENDING placement before the RPC so a host
	// re-registration mid-restore treats the incarnation as owned (never an
	// orphan to scrub); promote on success, roll back on failure.
	f.mu.Lock()
	f.pendingRestore[cp.IncarnationID] = true
	f.mu.Unlock()
	// Refresh the fence in a COPY of the metadata — the caller's checkpoint
	// record is shared state.
	md := make(map[string]string, len(cp.Metadata)+1)
	for k, v := range cp.Metadata {
		md[k] = v
	}
	md["fence"] = fmt.Sprintf("%d", placement.Fence)
	handle, err := host.Restore(backendinterface.CheckpointData{
		IncarnationID: cp.IncarnationID,
		Files:         cp.Files,
		Metadata:      md,
	})
	f.mu.Lock()
	delete(f.pendingRestore, cp.IncarnationID)
	if err == nil {
		f.byIncarnation[handle.IncarnationID] = placement.HostID
		f.fenceOf[handle.IncarnationID] = placement.Fence
		// A successful restore proves placement capacity exists — reset the
		// scale-out failure streak exactly like Create does (review M9).
		f.capacityFailures = 0
	}
	f.mu.Unlock()
	if err != nil {
		// Rollback (review H4/H5): the error may be a lost ACK with the
		// incarnation actually booted on the host — terminate best-effort so
		// nothing runs fleet-invisible before the caller falls back.
		_ = host.Terminate(backendinterface.Handle{IncarnationID: cp.IncarnationID})
		return backendinterface.Handle{}, err
	}
	return handle, nil
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
// with no hosts would be a lie). SupportsRestore means routed restore works
// — with the ADR-008 scoping that a checkpoint boots only on its origin
// host (checkpoint bits are host-local; there is no cross-host transfer).
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
		caps.SupportsPortPublish = caps.SupportsPortPublish && c.SupportsPortPublish
		if classRank[c.IsolationClass] < classRank[caps.IsolationClass] {
			caps.IsolationClass = c.IsolationClass
		}
	}
	return caps
}

// ReleaseSandbox drops per-sandbox scheduling state (the placement fence
// counter) when a sandbox terminates, so the fences map does not grow
// unboundedly.
func (f *Fleet) ReleaseSandbox(sandboxID string) {
	f.sched.ReleaseFence(sandboxID)
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
