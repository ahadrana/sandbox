// Package sandboxmanager is the in-memory authoritative logical lifecycle
// controller: sandbox state machine, execution service, epoch fencing,
// workspace commit coordination, and transactional outbox emission.
package sandboxmanager

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/agent-sandbox/platform/api"
	"github.com/agent-sandbox/platform/control-plane/event-service"
	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/network"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
	"github.com/agent-sandbox/platform/workspace"
)

// Runtime is the data/control surface the manager needs from a backend.
type Runtime interface {
	backendinterface.Backend
	Exec(h backendinterface.Handle, executionID string, op domain.Operation) error
	WaitExecution(h backendinterface.Handle, executionID string) (supervisor.Result, error)
	LiveDescendants(h backendinterface.Handle) int
	LiveNonBaselineDescendants(h backendinterface.Handle) int
	ProcessInventory(h backendinterface.Handle) ([]supervisor.ProcessInfo, error)
	TerminateBackground(h backendinterface.Handle) error
	WorkspaceFiles(h backendinterface.Handle) (map[string]string, error)
	Dirty(h backendinterface.Handle) bool
	MarkCommitted(h backendinterface.Handle)
	KillRuntime(h backendinterface.Handle)
	Alive(h backendinterface.Handle) bool
	Tick()
}

// PlacementTracker is implemented by fleet runtimes that place incarnations
// on hosts under placement fences.
type PlacementTracker interface {
	PlacementOf(incarnationID string) (hostID string, fence int64, ok bool)
}

// LostIncarnationTracker is implemented by fleet runtimes that detect host
// loss; the manager reconciles the listed incarnations.
type LostIncarnationTracker interface {
	LostIncarnations() []string
}

// EnvironmentSource resolves prepared-environment artifacts (PLAN §7).
type EnvironmentSource interface {
	ArtifactManifest(environmentID string) (map[string]string, error)
}

type Manager struct {
	mu     sync.Mutex
	clock  *domain.ManualClock
	ids    *domain.IDGen
	ws     workspace.Store
	rt     Runtime
	outbox *eventservice.Outbox
	store  Store
	hostID string
	envs   EnvironmentSource

	sandboxes    map[string]*domain.Sandbox
	executions   map[string]*domain.Execution
	incarnations map[string]*domain.RuntimeIncarnation
	handles      map[string]backendinterface.Handle // sandboxID -> live handle
	idem         map[string]string                  // sandboxID|key -> executionID
	aggVersions  map[string]int64
	outcomes     map[string]supervisor.Result
	tx           Tx

	leases         map[string]*domain.Lease // sandboxID -> lease
	policy         PolicyConfig
	materializedAt map[string]time.Time
	bgSince        map[string]time.Time
	enforceFlags   map[string]map[string]bool
	checkpoints    map[string]checkpointRecord // checkpointID -> record
	bindings       map[string]*domain.EndpointBinding
	egressPolicies map[string]network.EgressPolicy
	egressAudit    *network.AuditLog
	quotas         map[string]domain.Quota
	metrics        managerMetrics
	// CredentialRevoker is called by DeleteTenant to revoke all credentials
	// issued to a tenant (wired by the credential broker).
	CredentialRevoker func(tenantID string)
}

// managerMetrics holds lightweight operational counters (PLAN §16 SLO
// pass): in-memory only, snapshot on demand, no external deps.
type managerMetrics struct {
	eventsByType      map[domain.EventType]int64
	placementFailures int64
	reconcilerActions int64
}

// MetricsSnapshot is a point-in-time operational view.
type MetricsSnapshot struct {
	SandboxesByState  map[string]int
	ExecutionsByState map[string]int
	EventsByType      map[string]int64
	PlacementFailures int64
	ReconcilerActions int64
}

// Metrics returns a consistent snapshot of operational counters.
func (m *Manager) Metrics() MetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap := MetricsSnapshot{
		SandboxesByState:  map[string]int{},
		ExecutionsByState: map[string]int{},
		EventsByType:      map[string]int64{},
		PlacementFailures: m.metrics.placementFailures,
		ReconcilerActions: m.metrics.reconcilerActions,
	}
	for _, sb := range m.sandboxes {
		snap.SandboxesByState[string(sb.ObservedState)]++
	}
	for _, ex := range m.executions {
		snap.ExecutionsByState[string(ex.State)]++
	}
	for et, n := range m.metrics.eventsByType {
		snap.EventsByType[string(et)] = n
	}
	return snap
}

// checkpointRecord pairs the backend checkpoint payload with its durable
// control-plane record (FR-SR-005).
type checkpointRecord struct {
	data backendinterface.CheckpointData
	rec  domain.Checkpoint
}

// PolicyConfig is the default lease/enforcement policy (PLAN §10).
type PolicyConfig struct {
	ProcessLimit      int
	MemoryLimitBytes  int64
	WallDeadline      time.Duration
	MaxBackgroundWall time.Duration
}

// DefaultPolicy is permissive enough to never fire in the base suite.
var DefaultPolicy = PolicyConfig{
	ProcessLimit:      256,
	MemoryLimitBytes:  1 << 30,
	WallDeadline:      24 * time.Hour,
	MaxBackgroundWall: time.Hour,
}

// SetQuota installs a tenant admission quota (PLAN §13).
func (m *Manager) SetQuota(q domain.Quota) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.quotas[q.TenantID] = q
}

// SetPolicy overrides the default lease policy for subsequently created
// sandboxes and re-arms enforcement.
func (m *Manager) SetPolicy(p PolicyConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy = p
}

func New(clock *domain.ManualClock, ids *domain.IDGen, ws workspace.Store, rt Runtime, outbox *eventservice.Outbox, store Store, hostID string) *Manager {
	egressAudit, _ := network.NewAuditLog("")
	return &Manager{
		clock: clock, ids: ids, ws: ws, rt: rt, outbox: outbox, store: store, hostID: hostID,
		sandboxes: map[string]*domain.Sandbox{}, executions: map[string]*domain.Execution{},
		incarnations: map[string]*domain.RuntimeIncarnation{}, handles: map[string]backendinterface.Handle{},
		idem: map[string]string{}, aggVersions: map[string]int64{},
		outcomes:       map[string]supervisor.Result{},
		leases:         map[string]*domain.Lease{},
		checkpoints:    map[string]checkpointRecord{},
		bindings:       map[string]*domain.EndpointBinding{},
		quotas:         map[string]domain.Quota{},
		metrics:        managerMetrics{eventsByType: map[domain.EventType]int64{}},
		egressPolicies: map[string]network.EgressPolicy{"default": {DefaultAllow: true}},
		egressAudit:    egressAudit,
		policy:         DefaultPolicy,
		materializedAt: map[string]time.Time{},
		bgSince:        map[string]time.Time{},
		enforceFlags:   map[string]map[string]bool{},
	}
}

// flushTx commits the accumulated transaction (state + events) atomically.
func (m *Manager) flushTx() error {
	if m.tx.Empty() {
		return nil
	}
	if err := m.store.Commit(m.tx); err != nil {
		return err
	}
	m.tx = Tx{}
	return nil
}

func (m *Manager) txSandbox(sb *domain.Sandbox) {
	cp := *sb
	m.tx.Sandboxes = append(m.tx.Sandboxes, &cp)
}

func (m *Manager) txExecution(ex *domain.Execution) {
	cp := *ex
	m.tx.Executions = append(m.tx.Executions, &cp)
}

func (m *Manager) txIncarnation(inc *domain.RuntimeIncarnation) {
	cp := *inc
	m.tx.Incarnations = append(m.tx.Incarnations, &cp)
}

// NewFromStore rebuilds a manager from persisted state (control-plane
// restart, FR-AV-001). Workspace store, outbox, backend, and ID generator are
// supplied by the caller.
func NewFromStore(clock *domain.ManualClock, ids *domain.IDGen, store Store, ws workspace.Store, rt Runtime, outbox *eventservice.Outbox, hostID string) (*Manager, error) {
	snap, err := store.Load()
	if err != nil {
		return nil, err
	}
	m := New(clock, ids, ws, rt, outbox, store, hostID)
	for _, sb := range snap.Sandboxes {
		sb := sb
		m.sandboxes[sb.SandboxID] = &sb
		if sb.RuntimeIncarnationID != nil {
			m.handles[sb.SandboxID] = backendinterface.Handle{IncarnationID: *sb.RuntimeIncarnationID}
		}
	}
	for _, ex := range snap.Executions {
		ex := ex
		m.executions[ex.ExecutionID] = &ex
	}
	for _, inc := range snap.Incarnations {
		inc := inc
		m.incarnations[inc.IncarnationID] = &inc
	}
	for k, v := range snap.IdempotencyKeys {
		m.idem[k] = v
	}
	for k, v := range snap.Outcomes {
		m.outcomes[k] = v
	}
	for k, v := range snap.Leases {
		v := v
		m.leases[k] = &v
	}
	for k, v := range snap.Checkpoints {
		v := v
		m.checkpoints[k] = checkpointRecord{rec: v}
	}
	for k, v := range snap.Bindings {
		v := v
		m.bindings[k] = &v
	}
	if outbox.Len() == 0 {
		for _, ev := range snap.Events {
			outbox.Append(ev)
		}
	}
	events, _ := outbox.Replay(0)
	for _, ev := range events {
		if ev.AggregateVersion > m.aggVersions[ev.AggregateID] {
			m.aggVersions[ev.AggregateID] = ev.AggregateVersion
		}
	}
	if err := m.reconcileLocked(); err != nil {
		return nil, err
	}
	if err := m.flushTx(); err != nil {
		return nil, err
	}
	return m, nil
}

// reconcileLocked converges desired vs actual state after a control-plane
// restart (FR-LC-005): interrupted sandboxes are fenced to a safe state and
// non-terminal executions are finalized from a stored outcome or failed
// explicitly, never silently completed.
func (m *Manager) reconcileLocked() error {
	m.metrics.reconcilerActions++
	return m.reconcileInnerLocked()
}

func (m *Manager) reconcileInnerLocked() error {
	for _, sb := range m.sandboxes {
		switch sb.ObservedState {
		case domain.SandboxRunning, domain.SandboxBackgroundActive, domain.SandboxQuiescent:
			h, ok := m.handles[sb.SandboxID]
			if ok && m.rt.Alive(h) {
				continue
			}
			delete(m.handles, sb.SandboxID)
			if sb.RuntimeIncarnationID != nil {
				if inc, ok := m.incarnations[*sb.RuntimeIncarnationID]; ok {
					inc.State = domain.IncarnationLost
					m.txIncarnation(inc)
				}
				sb.RuntimeIncarnationID = nil
			}
			if err := m.transition(sb, domain.SandboxFailed); err != nil {
				return err
			}
			m.emit(sb, sb.SandboxID, domain.EventSandboxFailed, map[string]any{
				"reason": "incarnation unverified after control-plane restart",
			})
			if err := m.transition(sb, domain.SandboxSuspended); err != nil {
				return err
			}
			m.emit(sb, sb.SandboxID, domain.EventSandboxSuspended, map[string]any{
				"workspace_generation": sb.WorkspaceGeneration,
				"reconciled":           true,
			})
		case domain.SandboxStarting, domain.SandboxResuming:
			if err := m.transition(sb, domain.SandboxFailed); err != nil {
				return err
			}
			m.emit(sb, sb.SandboxID, domain.EventSandboxFailed, map[string]any{
				"reason": "materialization interrupted by control-plane restart",
			})
			if err := m.transition(sb, domain.SandboxUnmaterialized); err != nil {
				return err
			}
		case domain.SandboxSuspending:
			if err := m.transition(sb, domain.SandboxSuspended); err != nil {
				return err
			}
		}
	}
	for _, ex := range m.executions {
		if ex.State.Terminal() {
			continue
		}
		sb, ok := m.sandboxes[ex.SandboxID]
		if !ok {
			continue
		}
		if outcome, found := m.outcomes[ex.ExecutionID]; found {
			if err := m.finalizeCompletedLocked(sb, ex, outcome); err != nil {
				return err
			}
			continue
		}
		// An execution whose incarnation verified alive in the sandbox pass
		// above is still genuinely running: leave it RUNNING so its client
		// can complete it (and its workspace writes commit under its own
		// cause) rather than failing it by assumption.
		if h, live := m.handles[ex.SandboxID]; live && m.rt.Alive(h) {
			continue
		}
		if err := domain.TransitionExecution(ex.State, domain.ExecutionFailed); err != nil {
			return err
		}
		ex.State = domain.ExecutionFailed
		now := m.clock.Now()
		ex.CompletedAt = &now
		reason := "control-plane restart before completion"
		ex.TerminalReason = &reason
		m.txExecution(ex)
		m.emit(sb, ex.ExecutionID, domain.EventExecutionFailed, map[string]any{
			"execution_id": ex.ExecutionID,
			"reason":       reason,
		})
	}
	return nil
}

// emit appends an event to the outbox while the manager lock is held, making
// the state change and event write atomic (transactional outbox).
func (m *Manager) emit(sb *domain.Sandbox, aggregateID string, et domain.EventType, payload map[string]any) {
	m.aggVersions[aggregateID]++
	if payload == nil {
		payload = map[string]any{}
	}
	payload["sandbox_id"] = sb.SandboxID
	ev := domain.Event{
		EventID:          m.ids.Next("ev"),
		AggregateID:      aggregateID,
		AggregateVersion: m.aggVersions[aggregateID],
		EventType:        et,
		Timestamp:        m.clock.Now(),
		TenantID:         sb.TenantID,
		TaskRef:          sb.TaskRef,
		SchemaVersion:    api.SchemaVersionV1,
		Payload:          payload,
	}
	m.outbox.Append(ev)
	m.tx.Events = append(m.tx.Events, ev)
	if m.metrics.eventsByType == nil {
		m.metrics.eventsByType = map[domain.EventType]int64{}
	}
	m.metrics.eventsByType[et]++
}

func (m *Manager) transition(sb *domain.Sandbox, to domain.SandboxState) error {
	if sb.ObservedState == to {
		// Already in the target state: a true no-op, never a silent
		// version bump.
		return nil
	}
	if err := domain.TransitionSandbox(sb.ObservedState, to); err != nil {
		return err
	}
	if to == domain.SandboxBackgroundActive {
		m.bgSince[sb.SandboxID] = m.clock.Now()
	} else {
		delete(m.bgSince, sb.SandboxID)
	}
	sb.ObservedState = to
	sb.Version++
	m.txSandbox(sb)
	return nil
}

func (m *Manager) CreateSandbox(req api.CreateSandboxRequest) (*domain.Sandbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Validate placement fields: an out-of-range priority or an unknown
	// class must fail loudly, never silently become preemptible background.
	if req.Priority < 0 || req.Priority > 100 {
		return nil, fmt.Errorf("%w: priority %d out of range 0-100", domain.ErrInvalidRequest, req.Priority)
	}
	class := req.Class
	if class == "" {
		// Documented safe default: INTERACTIVE (never preemptible by
		// another tenant's interactive work).
		class = domain.ClassInteractive
	}
	if class != domain.ClassInteractive && class != domain.ClassBackground {
		return nil, fmt.Errorf("%w: unknown class %q", domain.ErrInvalidRequest, req.Class)
	}
	ws, err := m.ws.Create(req.TenantID, req.EnvironmentID)
	if err != nil {
		return nil, err
	}
	sb := &domain.Sandbox{
		SandboxID:           m.ids.Next("sb"),
		TenantID:            req.TenantID,
		TaskRef:             req.TaskRef,
		EnvironmentID:       req.EnvironmentID,
		WorkspaceID:         ws.WorkspaceID,
		DesiredState:        domain.SandboxUnmaterialized,
		ObservedState:       domain.SandboxUnmaterialized,
		ExecutionEpoch:      0,
		WorkspaceGeneration: ws.HeadGeneration,
		PolicyRef:           req.PolicyRef,
		Priority:            req.Priority,
		WorkloadClass:       class,
		StartupCommands:     append([]string{}, req.StartupCommands...),
		BaselineCommands:    append([]string{}, req.BaselineCommands...),
		Version:             1,
	}
	lease := &domain.Lease{
		LeaseID:           m.ids.Next("lease"),
		TenantID:          sb.TenantID,
		TaskRef:           sb.TaskRef,
		SandboxID:         sb.SandboxID,
		CPUPolicy:         "shared",
		MemoryLimit:       m.policy.MemoryLimitBytes,
		WallDeadline:      m.clock.Now().Add(m.policy.WallDeadline),
		ProcessLimit:      m.policy.ProcessLimit,
		Priority:          0,
		BackgroundPolicy:  "bounded",
		NetworkPolicyRef:  "default",
		MaxBackgroundWall: m.policy.MaxBackgroundWall,
	}
	sb.LeaseRef = &lease.LeaseID
	m.leases[sb.SandboxID] = lease
	m.tx.Leases = append(m.tx.Leases, lease)
	m.sandboxes[sb.SandboxID] = sb
	m.txSandbox(sb)
	if err := m.flushTx(); err != nil {
		return nil, err
	}
	cp := *sb
	return &cp, nil
}

func (m *Manager) GetSandbox(sandboxID string) (*domain.Sandbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sb, ok := m.sandboxes[sandboxID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *sb
	return &cp, nil
}

func (m *Manager) materializeLocked(sb *domain.Sandbox, report *api.RestoreReport) error {
	if err := m.checkQuotaLocked(sb); err != nil {
		return err
	}
	head, err := m.ws.GetHead(sb.WorkspaceID)
	if err != nil {
		return err
	}
	manifest, err := m.ws.Materialize(sb.WorkspaceID, head.Generation)
	if err != nil {
		return err
	}
	// The prepared-environment artifact is the immutable base layer; the
	// committed workspace generation overlays it (FR-ENV-004, FR-WS-006).
	if m.envs != nil && sb.EnvironmentID != "" {
		base, err := m.envs.ArtifactManifest(sb.EnvironmentID)
		if err != nil {
			return err
		}
		for path, content := range manifest {
			base[path] = content
		}
		manifest = base
	}
	priorEpoch := sb.ExecutionEpoch
	sb.ExecutionEpoch++

	incID := m.ids.Next("inc")
	egressEnv := network.Serialize(network.EgressPolicy{})
	if lease, ok := m.leases[sb.SandboxID]; ok {
		if pol, ok := m.egressPolicies[lease.NetworkPolicyRef]; ok {
			egressEnv = network.Serialize(pol)
		}
	}
	spec := backendinterface.Spec{
		SandboxID:           sb.SandboxID,
		IncarnationID:       incID,
		Epoch:               sb.ExecutionEpoch,
		EnvironmentID:       sb.EnvironmentID,
		WorkspaceID:         sb.WorkspaceID,
		WorkspaceGeneration: head.Generation,
		WorkspaceManifest:   manifest,
		Env:                 map[string]string{"AGENT_SANDBOX_EGRESS": egressEnv},
		Priority:            sb.Priority,
	}
	h, err := m.rt.Create(spec)
	// Fleet full: preempt (suspend) strictly-lower-priority BACKGROUND
	// sandboxes until placement succeeds or no victim remains (PLAN §13).
	// A victim whose suspend fails is excluded and the next-lowest-priority
	// victim is tried rather than abandoning or retrying the same victim.
	excluded := map[string]bool{}
	for preempts := 0; err != nil && preempts < 8; preempts++ {
		victim := m.preemptableLocked(sb, excluded)
		if victim == nil {
			break
		}
		// Preemption must reclaim the victim's capacity: workspace-only
		// suspend, never a RAM-retaining checkpoint. The preemption event is
		// emitted only after the victim's suspend actually succeeds — never
		// for a preemption that did not happen.
		if serr := m.suspendWithReasonLocked(victim, "preempted", false); serr != nil {
			excluded[victim.SandboxID] = true
			continue
		}
		m.emit(victim, victim.SandboxID, domain.EventSandboxPreempted, map[string]any{
			"preempted_by":       sb.SandboxID,
			"victim_priority":    victim.Priority,
			"requester_priority": sb.Priority,
		})
		h, err = m.rt.Create(spec)
	}
	if err != nil {
		m.metrics.placementFailures++
		return err
	}
	if err := m.rt.Start(h); err != nil {
		return err
	}
	if err := m.runStartupLocked(sb, h, incID); err != nil {
		m.rt.Terminate(h)
		delete(m.handles, sb.SandboxID)
		if terr := m.transition(sb, domain.SandboxFailed); terr != nil {
			return terr
		}
		m.emit(sb, sb.SandboxID, domain.EventSandboxFailed, map[string]any{
			"reason": "startup command failed",
			"detail": err.Error(),
		})
		return err
	}
	now := m.clock.Now()
	m.materializedAt[sb.SandboxID] = now
	m.handles[sb.SandboxID] = h
	hostID := m.hostID
	metadata := map[string]string{}
	if pt, ok := m.rt.(PlacementTracker); ok {
		if placedHost, fence, found := pt.PlacementOf(incID); found {
			hostID = placedHost
			metadata["placement_fence"] = itoaInt64(fence)
		}
	}
	m.incarnations[incID] = &domain.RuntimeIncarnation{
		IncarnationID:      incID,
		SandboxID:          sb.SandboxID,
		ExecutionEpoch:     sb.ExecutionEpoch,
		RuntimeBackend:     "fake",
		HostID:             hostID,
		State:              domain.IncarnationRunning,
		StartedAt:          now,
		LastHeartbeat:      now,
		SupervisorEndpoint: "fake://supervisor/" + incID,
		RuntimeMetadata:    metadata,
	}
	sb.RuntimeIncarnationID = &incID
	sb.WorkspaceGeneration = head.Generation
	m.txIncarnation(m.incarnations[incID])
	if err := m.transition(sb, domain.SandboxRunning); err != nil {
		return err
	}
	if report != nil {
		report.NewEpoch = sb.ExecutionEpoch
		report.RestoredGeneration = head.Generation
	}
	if priorEpoch > 0 {
		m.emit(sb, sb.SandboxID, domain.EventExecutionStateReset, map[string]any{
			"prior_epoch":          priorEpoch,
			"new_epoch":            sb.ExecutionEpoch,
			"workspace_generation": head.Generation,
			"lost_classes":         domain.AllVolatileLostClasses,
		})
	}
	m.emit(sb, sb.SandboxID, domain.EventSandboxMaterialized, map[string]any{
		"execution_epoch":      sb.ExecutionEpoch,
		"workspace_generation": head.Generation,
		"incarnation_id":       incID,
	})
	return nil
}

// checkQuotaLocked enforces tenant admission quotas at materialization:
// exceeding a limit is an explicit QuotaExceededError plus event, never
// silent queueing (PLAN §13). Zero limits are unlimited; CPU weight is one
// unit per live sandbox.
func (m *Manager) checkQuotaLocked(sb *domain.Sandbox) error {
	q, ok := m.quotas[sb.TenantID]
	if !ok {
		return nil
	}
	var live, mem int64
	for id, other := range m.sandboxes {
		if other.TenantID != sb.TenantID || id == sb.SandboxID {
			continue
		}
		if _, ok := m.handles[id]; !ok {
			continue
		}
		live++
		if l := m.leases[id]; l != nil {
			mem += l.MemoryLimit
		}
	}
	thisMem := int64(0)
	if l := m.leases[sb.SandboxID]; l != nil {
		thisMem = l.MemoryLimit
	}
	deny := func(resource string, limit int64) error {
		m.emit(sb, sb.SandboxID, domain.EventQuotaExceeded, map[string]any{
			"tenant_id": sb.TenantID,
			"resource":  resource,
			"limit":     limit,
		})
		qerr := &domain.QuotaExceededError{TenantID: sb.TenantID, Resource: resource, Limit: limit}
		if ferr := m.flushTx(); ferr != nil {
			// The caller-facing error stays the quota error; the
			// persistence failure is surfaced alongside it.
			return fmt.Errorf("%w (denial event not persisted: %v)", qerr, ferr)
		}
		return qerr
	}
	if q.MaxLiveSandboxes > 0 && live+1 > int64(q.MaxLiveSandboxes) {
		return deny("live_sandboxes", int64(q.MaxLiveSandboxes))
	}
	if q.MaxMemoryBytes > 0 && mem+thisMem > q.MaxMemoryBytes {
		return deny("memory_bytes", q.MaxMemoryBytes)
	}
	if q.MaxCPUWeight > 0 && live+1 > q.MaxCPUWeight {
		return deny("cpu_weight", q.MaxCPUWeight)
	}
	return nil
}

// authorizeTenant enforces per-tenant ownership (INV-028): a request that
// asserts a tenant must assert the sandbox's owner. An empty tenant defaults
// to the owner (single-tenant/dev callers); authenticating the principal
// itself remains a gateway concern (DESIGN §6.1).
func authorizeTenant(sb *domain.Sandbox, tenantID string) error {
	if tenantID != "" && tenantID != sb.TenantID {
		return &domain.UnauthorizedError{TenantID: tenantID, OwnerID: sb.TenantID, SandboxID: sb.SandboxID}
	}
	return nil
}

// preemptableLocked picks the lowest-priority live BACKGROUND-class victim
// for an INTERACTIVE requester; strictly lower priority only, so equal
// priority never preempts. Sandboxes in excluded (earlier victims whose
// suspend failed) are skipped.
func (m *Manager) preemptableLocked(requester *domain.Sandbox, excluded map[string]bool) *domain.Sandbox {
	if requester.WorkloadClass != domain.ClassInteractive {
		return nil
	}
	var victim *domain.Sandbox
	for id, other := range m.sandboxes {
		if id == requester.SandboxID || excluded[id] || other.WorkloadClass != domain.ClassBackground {
			continue
		}
		if _, live := m.handles[id]; !live {
			continue
		}
		if other.Priority >= requester.Priority {
			continue
		}
		if victim == nil || other.Priority < victim.Priority {
			victim = other
		}
	}
	return victim
}

// runStartupLocked executes per-session startup commands after workspace
// materialization and before RUNNING. A failed startup is explicit: the
// sandbox transitions to FAILED with an event rather than silently reporting
// RUNNING without its services (FR-ENV-005).
func (m *Manager) runStartupLocked(sb *domain.Sandbox, h backendinterface.Handle, incID string) error {
	commands := make([]domain.Operation, 0, len(sb.StartupCommands)+len(sb.BaselineCommands))
	for _, cmd := range sb.StartupCommands {
		commands = append(commands, domain.Operation{Command: cmd})
	}
	for _, cmd := range sb.BaselineCommands {
		commands = append(commands, domain.Operation{Command: cmd, Baseline: true})
	}
	for i, op := range commands {
		cmd := op.Command
		startupID := incID + "-startup-" + itoaInt(i)
		if err := m.rt.Exec(h, startupID, op); err != nil {
			return fmt.Errorf("startup command %d %q: %w", i, cmd, err)
		}
		res, err := m.rt.WaitExecution(h, startupID)
		if err != nil {
			return fmt.Errorf("startup command %d %q: %w", i, cmd, err)
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("startup command %d %q exited %d", i, cmd, res.ExitCode)
		}
	}
	return nil
}

func itoaInt64(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func itoaInt(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// Materialize brings an UNMATERIALIZED sandbox to RUNNING, or rematerializes
// one whose runtime was lost (FAILED), with an explicit epoch reset.
func (m *Manager) Materialize(sandboxID string) (*api.RestoreReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sb, ok := m.sandboxes[sandboxID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	report := &api.RestoreReport{Version: api.SchemaVersionV1, SandboxID: sandboxID, PriorEpoch: sb.ExecutionEpoch}
	switch sb.ObservedState {
	case domain.SandboxUnmaterialized:
		if err := m.transition(sb, domain.SandboxStarting); err != nil {
			return nil, err
		}
	case domain.SandboxFailed:
		report.UncommittedStateLost = true
		report.LostClasses = domain.AllVolatileLostClasses
		if err := m.transition(sb, domain.SandboxStarting); err != nil {
			return nil, err
		}
	default:
		return nil, domain.ErrIllegalState
	}
	if err := m.materializeLocked(sb, report); err != nil {
		// Any failure after the STARTING transition must leave the sandbox
		// in a valid, persisted state so a later Materialize retry is legal
		// instead of wedging on STARTING (FAILED is retriable).
		if sb.ObservedState == domain.SandboxStarting {
			if terr := m.transition(sb, domain.SandboxFailed); terr != nil {
				return nil, terr
			}
			m.emit(sb, sb.SandboxID, domain.EventSandboxFailed, map[string]any{
				"reason": "materialize failed",
				"detail": err.Error(),
			})
		}
		if ferr := m.flushTx(); ferr != nil {
			return nil, ferr
		}
		return nil, err
	}
	if err := m.flushTx(); err != nil {
		return nil, err
	}
	return report, nil
}

// KillRuntime simulates loss of the physical runtime incarnation (INV-001).
func (m *Manager) KillRuntime(sandboxID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sb, ok := m.sandboxes[sandboxID]
	if !ok {
		return domain.ErrNotFound
	}
	h, ok := m.handles[sandboxID]
	if !ok {
		return domain.ErrIllegalState
	}
	m.rt.KillRuntime(h)
	if err := m.markRuntimeLostLocked(sb, "runtime incarnation lost"); err != nil {
		return err
	}
	return m.flushTx()
}

// markRuntimeLostLocked records loss of the current incarnation and fails
// the sandbox explicitly (INV-024); recovery happens on rematerialization.
// All non-terminal executions of the sandbox are finalized FAILED with an
// explicit terminal reason, so a reconnecting client gets a terminal result
// immediately rather than after the next control-plane restart (INV-010).
func (m *Manager) markRuntimeLostLocked(sb *domain.Sandbox, reason string) error {
	delete(m.handles, sb.SandboxID)
	if sb.RuntimeIncarnationID != nil {
		if inc, ok := m.incarnations[*sb.RuntimeIncarnationID]; ok {
			inc.State = domain.IncarnationLost
			m.txIncarnation(inc)
		}
		sb.RuntimeIncarnationID = nil
	}
	if err := m.transition(sb, domain.SandboxFailed); err != nil {
		return err
	}
	m.emit(sb, sb.SandboxID, domain.EventSandboxFailed, map[string]any{
		"reason": reason,
	})
	for _, ex := range m.executions {
		if ex.SandboxID != sb.SandboxID || ex.State.Terminal() {
			continue
		}
		if err := domain.TransitionExecution(ex.State, domain.ExecutionFailed); err != nil {
			return err
		}
		ex.State = domain.ExecutionFailed
		now := m.clock.Now()
		ex.CompletedAt = &now
		ex.TerminalReason = &reason
		m.txExecution(ex)
		m.emit(sb, ex.ExecutionID, domain.EventExecutionFailed, map[string]any{
			"execution_id": ex.ExecutionID,
			"reason":       reason,
		})
	}
	return nil
}

func (m *Manager) sandboxByIncarnationLocked(incID string) *domain.Sandbox {
	for _, sb := range m.sandboxes {
		if sb.RuntimeIncarnationID != nil && *sb.RuntimeIncarnationID == incID {
			return sb
		}
	}
	return nil
}

var execStartable = map[domain.SandboxState]bool{
	domain.SandboxRunning:          true,
	domain.SandboxBackgroundActive: true,
	domain.SandboxQuiescent:        true,
}

// StartExecution launches an Execution (INV-010, INV-011, FR-EP-004).
func (m *Manager) StartExecution(req api.StartExecutionRequest) (*domain.Execution, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sb, ok := m.sandboxes[req.SandboxID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if err := authorizeTenant(sb, req.TenantID); err != nil {
		return nil, err
	}
	if req.IdempotencyKey != "" {
		if existingID, dup := m.idem[req.SandboxID+"|"+req.IdempotencyKey]; dup {
			if ex, ok := m.executions[existingID]; ok {
				cp := *ex
				return &cp, nil
			}
			// Stale idempotency record (execution gone): drop it and treat
			// the request as new rather than dereferencing nil.
			delete(m.idem, req.SandboxID+"|"+req.IdempotencyKey)
		}
	}
	if !execStartable[sb.ObservedState] {
		return nil, domain.ErrIllegalState
	}
	if dest := req.Operation.EgressDestination; dest != "" {
		pol, ok := m.egressPolicies["default"]
		ref := "default"
		if lease, lok := m.leases[sb.SandboxID]; lok {
			ref = lease.NetworkPolicyRef
			pol, ok = m.egressPolicies[ref]
		}
		decision := network.EgressDecision{Destination: dest, Allowed: false, Reason: "no egress policy for ref " + ref, At: m.clock.Now()}
		if ok {
			decision = network.EvaluateEgress(pol, dest, m.clock.Now())
		}
		m.egressAudit.Record("egress", sb.SandboxID, fmt.Sprintf("%s allowed=%v reason=%q", dest, decision.Allowed, decision.Reason), m.clock.Now())
		if !decision.Allowed {
			return nil, fmt.Errorf("%w: %s (%s)", domain.ErrEgressDenied, dest, decision.Reason)
		}
	}
	// Fence whenever the caller supplies an expected epoch (INV-008);
	// DependsOnVolatileState only documents intent, it does not gate the
	// fence itself.
	if req.ExpectedEpoch != 0 && req.ExpectedEpoch != sb.ExecutionEpoch {
		return nil, &domain.EpochConflictError{
			SandboxID: sb.SandboxID, Expected: req.ExpectedEpoch, Actual: sb.ExecutionEpoch,
		}
	}
	h := m.handles[sb.SandboxID]
	now := m.clock.Now()
	ex := &domain.Execution{
		ExecutionID:                  m.ids.Next("ex"),
		IdempotencyKey:               req.IdempotencyKey,
		TenantID:                     sb.TenantID,
		SandboxID:                    sb.SandboxID,
		PrincipalID:                  req.PrincipalID,
		ExecutionEpoch:               sb.ExecutionEpoch,
		RequestedWorkspaceGeneration: sb.WorkspaceGeneration,
		Operation:                    req.Operation,
		State:                        domain.ExecutionPending,
		CreatedAt:                    now,
		GenerationBefore:             sb.WorkspaceGeneration,
	}
	if err := domain.TransitionExecution(ex.State, domain.ExecutionDispatched); err != nil {
		return nil, err
	}
	ex.State = domain.ExecutionDispatched
	m.executions[ex.ExecutionID] = ex
	m.txExecution(ex)
	if req.IdempotencyKey != "" {
		m.idem[req.SandboxID+"|"+req.IdempotencyKey] = ex.ExecutionID
		m.tx.Idempotency = append(m.tx.Idempotency, IdempotencyRecord{
			SandboxID: req.SandboxID, Key: req.IdempotencyKey, ExecutionID: ex.ExecutionID,
		})
	}
	execErr := m.rt.Exec(h, ex.ExecutionID, req.Operation)
	if execErr != nil && !isAckLost(execErr) {
		var execErrTyped *backendinterface.ExecError
		if errors.As(execErr, &execErrTyped) {
			if terr := domain.TransitionExecution(ex.State, domain.ExecutionFailed); terr != nil {
				return nil, terr
			}
			ex.State = domain.ExecutionFailed
			ex.CompletedAt = &now
			code := execErrTyped.ExitCode
			ex.ExitCode = &code
			reason := "operation failed"
			ex.TerminalReason = &reason
			m.txExecution(ex)
			m.emit(sb, ex.ExecutionID, domain.EventExecutionFailed, map[string]any{
				"execution_id": ex.ExecutionID, "exit_code": code,
			})
			if err := m.flushTx(); err != nil {
				return nil, err
			}
			cp := *ex
			return &cp, nil
		}
		delete(m.executions, ex.ExecutionID)
		if req.IdempotencyKey != "" {
			delete(m.idem, req.SandboxID+"|"+req.IdempotencyKey)
		}
		m.tx = Tx{}
		return nil, execErr
	}
	if err := domain.TransitionExecution(ex.State, domain.ExecutionRunning); err != nil {
		return nil, err
	}
	ex.State = domain.ExecutionRunning
	ex.StartedAt = &now
	m.txExecution(ex)
	if sb.ObservedState == domain.SandboxQuiescent || sb.ObservedState == domain.SandboxBackgroundActive {
		if err := m.transition(sb, domain.SandboxRunning); err != nil {
			return nil, err
		}
	}
	m.emit(sb, ex.ExecutionID, domain.EventExecutionStarted, map[string]any{
		"execution_id":    ex.ExecutionID,
		"principal_id":    ex.PrincipalID,
		"execution_epoch": ex.ExecutionEpoch,
	})
	if err := m.flushTx(); err != nil {
		return nil, err
	}
	cp := *ex
	if isAckLost(execErr) {
		return &cp, backendinterface.AckLostError{}
	}
	return &cp, nil
}

func isAckLost(err error) bool {
	var ack backendinterface.AckLostError
	return errors.As(err, &ack)
}

// CompleteExecution finishes a RUNNING execution successfully: commits a new
// workspace generation when writes are pending and recomputes quiescence
// (INV-012). The runtime wait is guest-paced and unbounded, so m.mu is
// released across it — a wedged guest must never wedge the control plane —
// and the execution state is re-validated before finalizing.
func (m *Manager) CompleteExecution(executionID string) (*domain.Execution, error) {
	m.mu.Lock()
	ex, ok := m.executions[executionID]
	if !ok {
		m.mu.Unlock()
		return nil, domain.ErrNotFound
	}
	sb := m.sandboxes[ex.SandboxID]
	if sb == nil {
		m.mu.Unlock()
		return nil, domain.ErrNotFound
	}
	h, live := m.handles[sb.SandboxID]
	if !live {
		m.mu.Unlock()
		return nil, domain.ErrIllegalState
	}
	m.mu.Unlock()

	outcome, err := m.rt.WaitExecution(h, executionID)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	ex, ok = m.executions[executionID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	sb = m.sandboxes[ex.SandboxID]
	if sb == nil {
		return nil, domain.ErrNotFound
	}
	if ex.State == domain.ExecutionCompleted {
		// Finalized concurrently while the wait was in flight (reconciler
		// or a duplicate CompleteExecution): return the recorded state
		// without re-appending the outcome or re-committing.
		cp := *ex
		return &cp, nil
	}
	// Persist the observed outcome before the workspace commit / state
	// update chain so recovery can finalize exactly once (PLAN §6).
	m.outcomes[executionID] = outcome
	m.tx.Outcomes = append(m.tx.Outcomes, OutcomeRecord{ExecutionID: executionID, Result: outcome})
	if err := m.flushTx(); err != nil {
		return nil, err
	}
	if err := m.finalizeCompletedLocked(sb, ex, outcome); err != nil {
		return nil, err
	}
	if err := m.recomputeQuiescenceLocked(sb); err != nil {
		return nil, err
	}
	if err := m.flushTx(); err != nil {
		return nil, err
	}
	cp := *ex
	return &cp, nil
}

// finalizeCompletedLocked moves an execution to COMPLETED with the observed
// outcome, committing pending workspace writes idempotently. Used by normal
// completion and by the reconciler.
func (m *Manager) finalizeCompletedLocked(sb *domain.Sandbox, ex *domain.Execution, outcome supervisor.Result) error {
	if ex.State != domain.ExecutionCompleted {
		if err := domain.TransitionExecution(ex.State, domain.ExecutionCompleted); err != nil {
			return err
		}
		ex.State = domain.ExecutionCompleted
	}
	code := outcome.ExitCode
	ex.ExitCode = &code
	ex.ResourceUsage = outcome.Usage
	if !outcome.StartedAt.IsZero() {
		ex.StartedAt = &outcome.StartedAt
	}
	if !outcome.CompletedAt.IsZero() {
		ex.CompletedAt = &outcome.CompletedAt
	} else {
		now := m.clock.Now()
		ex.CompletedAt = &now
	}
	stdout := outcome.StdoutRef
	if stdout == "" {
		stdout = "out://" + ex.ExecutionID + "/stdout"
	}
	stderr := outcome.StderrRef
	if stderr == "" {
		stderr = "out://" + ex.ExecutionID + "/stderr"
	}
	ex.StdoutRef = &stdout
	ex.StderrRef = &stderr
	h := m.handles[sb.SandboxID]
	if err := m.commitLocked(sb, h, &ex.ExecutionID); err != nil {
		return err
	}
	generationAfter := sb.WorkspaceGeneration
	ex.GenerationAfter = &generationAfter
	m.txExecution(ex)
	m.emit(sb, ex.ExecutionID, domain.EventExecutionCompleted, map[string]any{
		"execution_id":     ex.ExecutionID,
		"principal_id":     ex.PrincipalID,
		"exit_code":        code,
		"stdout_ref":       stdout,
		"stderr_ref":       stderr,
		"generation_after": sb.WorkspaceGeneration,
	})
	return nil
}

// quiescentLocked is THE quiescence policy (INV-012, PLAN §10): a sandbox is
// quiescent iff it has no active API executions AND no live non-baseline
// descendants. Baseline services (e.g. a tagged dev server) are always
// metered and lease-bound, but never block quiescence.
func (m *Manager) quiescentLocked(sb *domain.Sandbox) bool {
	h, ok := m.handles[sb.SandboxID]
	if !ok {
		return false
	}
	for _, ex := range m.executions {
		if ex.SandboxID == sb.SandboxID && ex.State == domain.ExecutionRunning {
			return false
		}
	}
	return m.rt.LiveNonBaselineDescendants(h) == 0
}

func (m *Manager) recomputeQuiescenceLocked(sb *domain.Sandbox) error {
	if sb.ObservedState != domain.SandboxRunning {
		return nil
	}
	if m.quiescentLocked(sb) {
		return m.transition(sb, domain.SandboxQuiescent)
	}
	return m.transition(sb, domain.SandboxBackgroundActive)
}

// commitLocked commits pending runtime writes as a new workspace generation.
// It is idempotent by cause_execution_id so recovery can replay it safely.
func (m *Manager) commitLocked(sb *domain.Sandbox, h backendinterface.Handle, causeExecutionID *string) error {
	head, err := m.ws.GetHead(sb.WorkspaceID)
	if err != nil {
		return err
	}
	if causeExecutionID != nil && head.CauseExecutionID != nil && *head.CauseExecutionID == *causeExecutionID {
		// Idempotent replay: the commit already happened, but the sandbox's
		// persisted generation may have regressed (e.g. recovered from a
		// pre-commit journal) — persist the corrected value.
		if sb.WorkspaceGeneration != head.Generation {
			sb.WorkspaceGeneration = head.Generation
			sb.Version++
			m.txSandbox(sb)
		}
		return nil
	}
	if !m.rt.Dirty(h) {
		return nil
	}
	files, err := m.rt.WorkspaceFiles(h)
	if err != nil {
		return err
	}
	gen, err := m.ws.Commit(sb.WorkspaceID, head.Generation, files, causeExecutionID)
	if err != nil {
		return err
	}
	m.rt.MarkCommitted(h)
	sb.WorkspaceGeneration = gen.Generation
	sb.Version++
	m.txSandbox(sb)
	m.emit(sb, sb.WorkspaceID, domain.EventWorkspaceCommitted, map[string]any{
		"workspace_id":       sb.WorkspaceID,
		"generation":         gen.Generation,
		"parent_generation":  head.Generation,
		"integrity_digest":   gen.IntegrityDigest,
		"cause_execution_id": causeExecutionID,
	})
	return nil
}

// CommitWorkspace explicitly commits pending workspace state (FR-WS-004).
func (m *Manager) CommitWorkspace(req api.CommitWorkspaceRequest) (*domain.WorkspaceGeneration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sb, ok := m.sandboxes[req.SandboxID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if err := authorizeTenant(sb, req.TenantID); err != nil {
		return nil, err
	}
	h, ok := m.handles[req.SandboxID]
	if !ok {
		return nil, domain.ErrIllegalState
	}
	var cause *string
	if req.CauseExecutionID != "" {
		cause = &req.CauseExecutionID
	}
	if err := m.commitLocked(sb, h, cause); err != nil {
		return nil, err
	}
	if err := m.flushTx(); err != nil {
		return nil, err
	}
	head, err := m.ws.GetHead(sb.WorkspaceID)
	if err != nil {
		return nil, err
	}
	return &head, nil
}

// CancelExecution cancels a non-terminal execution (FR-EX-007). Cancelling
// an already-terminal execution is an idempotent read: it returns the
// existing terminal state without re-emitting events.
func (m *Manager) CancelExecution(executionID string) (*domain.Execution, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ex, ok := m.executions[executionID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if ex.State.Terminal() {
		cp := *ex
		return &cp, nil
	}
	sb := m.sandboxes[ex.SandboxID]
	if sb == nil {
		return nil, domain.ErrNotFound
	}
	if err := domain.TransitionExecution(ex.State, domain.ExecutionCancelled); err != nil {
		return nil, err
	}
	ex.State = domain.ExecutionCancelled
	now := m.clock.Now()
	ex.CompletedAt = &now
	reason := "cancelled by caller"
	ex.TerminalReason = &reason
	m.txExecution(ex)
	m.emit(sb, ex.ExecutionID, domain.EventExecutionCancelled, map[string]any{
		"execution_id": ex.ExecutionID,
		"principal_id": ex.PrincipalID,
	})
	if err := m.flushTx(); err != nil {
		return nil, err
	}
	cp := *ex
	return &cp, nil
}

func (m *Manager) GetExecution(executionID string) (*domain.Execution, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ex, ok := m.executions[executionID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *ex
	return &cp, nil
}

func (m *Manager) Executions(sandboxID string) []*domain.Execution {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*domain.Execution
	for _, ex := range m.executions {
		if ex.SandboxID == sandboxID {
			cp := *ex
			out = append(out, &cp)
		}
	}
	return out
}

// Suspend performs a workspace-only suspend: commit, terminate runtime,
// reclaim (FR-SR-002).
func (m *Manager) Suspend(sandboxID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sb, ok := m.sandboxes[sandboxID]
	if !ok {
		return domain.ErrNotFound
	}
	return m.suspendLocked(sb)
}

// suspendLocked is the lock-free suspend body, shared by the public API and
// scheduler preemption.
func (m *Manager) suspendLocked(sb *domain.Sandbox) error {
	return m.suspendWithReasonLocked(sb, "", true)
}

// suspendWithReasonLocked is THE suspend path (explicit Suspend, preemption,
// and wall-deadline enforcement all route through it): incarnation records,
// endpoint-binding suspension, and handle cleanup are identical regardless
// of trigger (INV-017). allowCheckpoint distinguishes intent: an explicit
// Suspend prefers EXECUTION_STATE checkpoint continuity, while
// enforcement-triggered suspends (preemption, deadlines) must RECLAIM
// resources, so they take the workspace-only path — a checkpoint keeps RAM
// allocated and would defeat the enforcement.
func (m *Manager) suspendWithReasonLocked(sb *domain.Sandbox, reason string, allowCheckpoint bool) error {
	sandboxID := sb.SandboxID
	payloadReason := func(p map[string]any) map[string]any {
		if reason != "" {
			p["reason"] = reason
		}
		return p
	}
	if err := m.transition(sb, domain.SandboxSuspending); err != nil {
		return err
	}
	for _, b := range m.bindings {
		if b.SandboxID == sandboxID && b.State == domain.EndpointActive {
			b.State = domain.EndpointSuspended
			m.tx.Bindings = append(m.tx.Bindings, b)
		}
	}
	h, live := m.handles[sandboxID]
	// 10-step suspend (PLAN §11): stop admission (SUSPENDING rejects new
	// execs) -> safe point -> commit workspace -> record lost-on-resume
	// inventory -> checkpoint or terminate -> release -> SUSPENDED.
	if live {
		if err := m.commitLocked(sb, h, nil); err != nil {
			return err
		}
		if allowCheckpoint && m.rt.Capabilities().SupportsCheckpoint {
			if err := m.checkpointSuspendLocked(sb, h, payloadReason); err == nil {
				return m.flushTx()
			}
			// Checkpoint failed: fall back to workspace-only suspend.
		}
		lost := m.lostInventoryLocked(h)
		if err := m.rt.Terminate(h); err != nil {
			return err
		}
		delete(m.handles, sandboxID)
		if sb.RuntimeIncarnationID != nil {
			if inc, ok := m.incarnations[*sb.RuntimeIncarnationID]; ok {
				inc.State = domain.IncarnationTerminated
				m.txIncarnation(inc)
			}
			sb.RuntimeIncarnationID = nil
		}
		if err := m.transition(sb, domain.SandboxSuspended); err != nil {
			return err
		}
		m.emit(sb, sb.SandboxID, domain.EventSandboxSuspended, payloadReason(map[string]any{
			"mode":                 "workspace_only",
			"workspace_generation": sb.WorkspaceGeneration,
			"lost_processes":       lost,
		}))
		return m.flushTx()
	}
	if sb.RuntimeIncarnationID != nil {
		if inc, ok := m.incarnations[*sb.RuntimeIncarnationID]; ok {
			inc.State = domain.IncarnationTerminated
			m.txIncarnation(inc)
		}
		sb.RuntimeIncarnationID = nil
	}
	if err := m.transition(sb, domain.SandboxSuspended); err != nil {
		return err
	}
	m.emit(sb, sb.SandboxID, domain.EventSandboxSuspended, payloadReason(map[string]any{
		"mode":                 "workspace_only",
		"workspace_generation": sb.WorkspaceGeneration,
	}))
	return m.flushTx()
}

// checkpointSuspendLocked pauses the incarnation and records an
// EXECUTION_STATE checkpoint. STOP/CONT-class backends keep RAM allocated
// (honestly reported as 0 reclaimed); snapshot-class backends
// (Capabilities.CheckpointReclaimsMemory) are terminated after capture and
// report the reclaimed RAM — Restore boots back from the checkpoint with
// real continuity. STOP/CONT-class handles stay live for a continuity
// resume; reclaim-class handles are dropped with the terminated VM so the
// sandbox no longer counts against live-sandbox quotas and is never picked
// as a preemption victim (its capacity is already reclaimed). Resume
// re-registers the handle Restore returns.
func (m *Manager) checkpointSuspendLocked(sb *domain.Sandbox, h backendinterface.Handle, payloadReason func(map[string]any) map[string]any) error {
	if err := m.rt.Pause(h); err != nil {
		return err
	}
	data, err := m.rt.Snapshot(h)
	if err != nil {
		m.rt.Resume(h)
		return err
	}
	cpID := m.ids.Next("cp")
	rec := domain.Checkpoint{
		CheckpointID:        cpID,
		SandboxID:           sb.SandboxID,
		ExecutionEpoch:      sb.ExecutionEpoch,
		WorkspaceGeneration: sb.WorkspaceGeneration,
		Type:                domain.CheckpointExecutionState,
		RuntimeBackend:      data.Metadata["class"],
		CreatedAt:           m.clock.Now(),
	}
	m.checkpoints[cpID] = checkpointRecord{data: data, rec: rec}
	m.tx.Checkpoints = append(m.tx.Checkpoints, &rec)
	sb.CheckpointRef = &cpID
	ramReclaimed := int64(0)
	incState := domain.IncarnationPaused
	if m.rt.Capabilities().CheckpointReclaimsMemory {
		if st, err := m.rt.Stats(h); err == nil {
			ramReclaimed = st.MemoryBytes
		}
		if err := m.rt.Terminate(h); err != nil {
			return err
		}
		delete(m.handles, sb.SandboxID)
		incState = domain.IncarnationTerminated
	}
	if sb.RuntimeIncarnationID != nil {
		if inc, ok := m.incarnations[*sb.RuntimeIncarnationID]; ok {
			inc.State = incState
			m.txIncarnation(inc)
		}
	}
	if err := m.transition(sb, domain.SandboxSuspended); err != nil {
		return err
	}
	m.emit(sb, sb.SandboxID, domain.EventSandboxSuspended, payloadReason(map[string]any{
		"mode":                 "execution_state",
		"checkpoint_id":        cpID,
		"workspace_generation": sb.WorkspaceGeneration,
		"ram_reclaimed_bytes":  ramReclaimed,
	}))
	return nil
}

// lostInventoryLocked records the process inventory that will not survive a
// workspace-only suspend (the explicit lost-on-resume list, PLAN §11 step 4).
func (m *Manager) lostInventoryLocked(h backendinterface.Handle) []string {
	inv, err := m.rt.ProcessInventory(h)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(inv))
	for _, p := range inv {
		out = append(out, fmt.Sprintf("%d:%s", p.PID, p.Command))
	}
	return out
}

// Resume restores a suspended sandbox. With an EXECUTION_STATE checkpoint
// and continuity guaranteed (all checkpointed PIDs alive and owned), the
// epoch is RETAINED and no ExecutionStateReset is emitted (FR-SR-005).
// Otherwise it falls back to workspace-only recovery: epoch increment,
// startup rerun, ExecutionStateReset — never false continuity (INV-009).
func (m *Manager) Resume(sandboxID string) (*api.RestoreReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sb, ok := m.sandboxes[sandboxID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if err := m.transition(sb, domain.SandboxResuming); err != nil {
		return nil, err
	}
	if sb.CheckpointRef != nil {
		if record, ok := m.checkpoints[*sb.CheckpointRef]; ok {
			h, live := m.handles[sandboxID]
			// Reclaim-class backends drop the handle at suspend; continuity
			// is still available via Restore from the checkpoint, and the
			// fresh handle is re-registered.
			if live || m.rt.Capabilities().CheckpointReclaimsMemory {
				if newHandle, err := m.rt.Restore(record.data); err == nil {
					m.handles[sandboxID] = newHandle
					return m.resumeWithContinuityLocked(sb, record)
				}
				// Continuity broken: clean the stale incarnation and fall
				// back to workspace-only recovery.
				if live {
					m.rt.Terminate(h)
					delete(m.handles, sandboxID)
				}
			}
			delete(m.checkpoints, *sb.CheckpointRef)
		}
		sb.CheckpointRef = nil
		if sb.RuntimeIncarnationID != nil {
			if inc, ok := m.incarnations[*sb.RuntimeIncarnationID]; ok {
				inc.State = domain.IncarnationTerminated
				m.txIncarnation(inc)
			}
			sb.RuntimeIncarnationID = nil
		}
	}
	report := &api.RestoreReport{
		Version:              api.SchemaVersionV1,
		SandboxID:            sandboxID,
		PriorEpoch:           sb.ExecutionEpoch,
		UncommittedStateLost: true,
		LostClasses:          domain.AllVolatileLostClasses,
	}
	if err := m.materializeLocked(sb, report); err != nil {
		return nil, err
	}
	m.emit(sb, sb.SandboxID, domain.EventSandboxResumed, map[string]any{
		"continuity":           "workspace_only",
		"execution_epoch":      sb.ExecutionEpoch,
		"workspace_generation": sb.WorkspaceGeneration,
	})
	if err := m.flushTx(); err != nil {
		return nil, err
	}
	return report, nil
}

// resumeWithContinuityLocked completes a checkpoint resume: same
// incarnation, same epoch, no ExecutionStateReset.
func (m *Manager) resumeWithContinuityLocked(sb *domain.Sandbox, record checkpointRecord) (*api.RestoreReport, error) {
	if sb.RuntimeIncarnationID != nil {
		if inc, ok := m.incarnations[*sb.RuntimeIncarnationID]; ok {
			inc.State = domain.IncarnationRunning
			m.txIncarnation(inc)
		}
	}
	if err := m.transition(sb, domain.SandboxRunning); err != nil {
		return nil, err
	}
	m.emit(sb, sb.SandboxID, domain.EventSandboxResumed, map[string]any{
		"continuity":           "execution_state",
		"checkpoint_id":        record.rec.CheckpointID,
		"execution_epoch":      sb.ExecutionEpoch,
		"workspace_generation": sb.WorkspaceGeneration,
	})
	if err := m.recomputeQuiescenceLocked(sb); err != nil {
		return nil, err
	}
	if err := m.flushTx(); err != nil {
		return nil, err
	}
	return &api.RestoreReport{
		Version:            api.SchemaVersionV1,
		SandboxID:          sb.SandboxID,
		PriorEpoch:         sb.ExecutionEpoch,
		NewEpoch:           sb.ExecutionEpoch,
		RestoredGeneration: sb.WorkspaceGeneration,
	}, nil
}

// CreateEndpointBinding binds a logical name to a sandbox target port,
// fenced to the current execution epoch (PLAN §12). Bindings are durable
// via the store tx and expire at TTL on Tick.
func (m *Manager) CreateEndpointBinding(req api.CreateEndpointBindingRequest) (*domain.EndpointBinding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sb, ok := m.sandboxes[req.SandboxID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if err := authorizeTenant(sb, req.TenantID); err != nil {
		return nil, err
	}
	b := &domain.EndpointBinding{
		BindingID:      m.ids.Next("bind"),
		TenantID:       sb.TenantID,
		SandboxID:      sb.SandboxID,
		ExecutionEpoch: sb.ExecutionEpoch,
		TargetPort:     req.TargetPort,
		LogicalName:    req.LogicalName,
		AuthPolicy:     req.AuthPolicy,
		State:          domain.EndpointActive,
	}
	if req.TTL > 0 {
		b.ExpiresAt = m.clock.Now().Add(req.TTL)
	}
	m.bindings[b.BindingID] = b
	m.tx.Bindings = append(m.tx.Bindings, b)
	m.emit(sb, sb.SandboxID, domain.EventEndpointBound, map[string]any{
		"binding_id":      b.BindingID,
		"logical_name":    b.LogicalName,
		"target_port":     b.TargetPort,
		"execution_epoch": b.ExecutionEpoch,
	})
	if err := m.flushTx(); err != nil {
		return nil, err
	}
	cp := *b
	return &cp, nil
}

// ListEndpointBindings returns copies of a sandbox's bindings.
func (m *Manager) ListEndpointBindings(sandboxID string) []*domain.EndpointBinding {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*domain.EndpointBinding
	for _, b := range m.bindings {
		if b.SandboxID == sandboxID {
			cp := *b
			out = append(out, &cp)
		}
	}
	return out
}

// UnbindEndpoint deletes a binding (terminal UNBOUND state).
func (m *Manager) UnbindEndpoint(bindingID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.bindings[bindingID]
	if !ok {
		return domain.ErrNotFound
	}
	return m.unbindLocked(b, "unbound")
}

func (m *Manager) unbindLocked(b *domain.EndpointBinding, reason string) error {
	b.State = domain.EndpointUnbound
	m.tx.Bindings = append(m.tx.Bindings, b)
	sb := m.sandboxes[b.SandboxID]
	if sb == nil {
		sb = &domain.Sandbox{SandboxID: b.SandboxID, TenantID: b.TenantID}
	}
	m.emit(sb, sb.SandboxID, domain.EventEndpointUnbound, map[string]any{
		"binding_id": b.BindingID,
		"reason":     reason,
	})
	return nil
}

// BindingView is the network.BindingSource implementation for the gateway.
func (m *Manager) BindingView(bindingID string) (network.BindingView, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.bindings[bindingID]
	if !ok {
		return network.BindingView{}, false
	}
	view := network.BindingView{Binding: *b, Now: m.clock.Now()}
	if sb, ok := m.sandboxes[b.SandboxID]; ok {
		view.CurrentEpoch = sb.ExecutionEpoch
		_, live := m.handles[b.SandboxID]
		view.SandboxActive = live
	}
	return view, true
}

// SetEgressPolicy installs an egress policy under a lease policy ref.
func (m *Manager) SetEgressPolicy(ref string, p network.EgressPolicy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.egressPolicies[ref] = p
}

// EgressAuditEntries returns the egress decision audit trail.
func (m *Manager) EgressAuditEntries() []network.AuditEntry {
	return m.egressAudit.Entries()
}

func (m *Manager) Terminate(sandboxID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sb, ok := m.sandboxes[sandboxID]
	if !ok {
		return domain.ErrNotFound
	}
	return m.terminateLocked(sb)
}

func (m *Manager) terminateLocked(sb *domain.Sandbox) error {
	sandboxID := sb.SandboxID
	if h, ok := m.handles[sandboxID]; ok {
		if err := m.rt.Terminate(h); err != nil {
			return err
		}
		delete(m.handles, sandboxID)
	}
	if sb.RuntimeIncarnationID != nil {
		if inc, ok := m.incarnations[*sb.RuntimeIncarnationID]; ok {
			inc.State = domain.IncarnationTerminated
			m.txIncarnation(inc)
		}
		sb.RuntimeIncarnationID = nil
	}
	for _, b := range m.bindings {
		if b.SandboxID == sandboxID && (b.State == domain.EndpointActive || b.State == domain.EndpointSuspended) {
			if err := m.unbindLocked(b, "sandbox_terminated"); err != nil {
				return err
			}
		}
	}
	if err := m.transition(sb, domain.SandboxTerminated); err != nil {
		return err
	}
	// Drop per-sandbox scheduler state (placement fence) so it does not
	// outlive the sandbox.
	if rs, ok := m.rt.(interface{ ReleaseSandbox(string) }); ok {
		rs.ReleaseSandbox(sandboxID)
	}
	return m.flushTx()
}

// DeleteTenant offboards a tenant (PLAN §16): every sandbox is terminated
// (which also unbinds its endpoints), quotas are dropped, issued
// credentials are revoked via the wired revoker, and workspace data is
// marked for GC. Explicit and evented, never silent.
func (m *Manager) DeleteTenant(tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var workspaces []string
	for _, sb := range m.sandboxes {
		if sb.TenantID != tenantID {
			continue
		}
		if sb.ObservedState != domain.SandboxTerminated {
			if err := m.terminateLocked(sb); err != nil {
				return err
			}
		}
		workspaces = append(workspaces, sb.WorkspaceID)
	}
	delete(m.quotas, tenantID)
	if m.CredentialRevoker != nil {
		m.CredentialRevoker(tenantID)
	}
	gcTotal := 0
	for _, wsID := range workspaces {
		if n, err := m.ws.GC(wsID); err == nil {
			gcTotal += n
		}
	}
	m.emit(&domain.Sandbox{SandboxID: tenantID, TenantID: tenantID}, tenantID, domain.EventTenantDeleted, map[string]any{
		"sandboxes_terminated":       len(workspaces),
		"workspace_generations_gced": gcTotal,
	})
	return m.flushTx()
}

// LiveDescendants reports the number of live non-baseline processes owned by
// the sandbox's incarnation (quiescence signal, FR-BG-003).
func (m *Manager) LiveDescendants(sandboxID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.handles[sandboxID]
	if !ok {
		return 0
	}
	return m.rt.LiveDescendants(h)
}

// Tick advances the deterministic clock and runtime; sandboxes whose
// background descendants have exited become QUIESCENT.
func (m *Manager) Tick(d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clock.Advance(d)
	m.rt.Tick()
	if lt, ok := m.rt.(LostIncarnationTracker); ok {
		for _, incID := range lt.LostIncarnations() {
			sb := m.sandboxByIncarnationLocked(incID)
			if sb == nil {
				continue
			}
			if err := m.markRuntimeLostLocked(sb, "host lost"); err != nil {
				return err
			}
		}
	}
	for _, sb := range m.sandboxes {
		if err := m.enforceLeaseLocked(sb); err != nil {
			return err
		}
		if sb.ObservedState != domain.SandboxBackgroundActive {
			continue
		}
		if _, ok := m.handles[sb.SandboxID]; !ok {
			continue
		}
		if m.quiescentLocked(sb) {
			if err := m.transition(sb, domain.SandboxQuiescent); err != nil {
				return err
			}
		}
	}
	now := m.clock.Now()
	for _, b := range m.bindings {
		if (b.State == domain.EndpointActive || b.State == domain.EndpointSuspended) && !b.ExpiresAt.IsZero() && now.After(b.ExpiresAt) {
			b.State = domain.EndpointExpired
			m.tx.Bindings = append(m.tx.Bindings, b)
			if sb := m.sandboxes[b.SandboxID]; sb != nil {
				m.emit(sb, sb.SandboxID, domain.EventEndpointUnbound, map[string]any{
					"binding_id": b.BindingID,
					"reason":     "ttl_expired",
				})
			}
		}
	}
	return m.flushTx()
}

// enforceLeaseLocked applies lease limits to one live sandbox, emitting
// ResourceLimitApproaching at 80% and ResourceLimitExceeded plus a policy
// action at 100% (FR-BG-004, INV-015). Actions: exceeding background
// descendants are killed; a sandbox past its wall deadline is suspended.
func (m *Manager) enforceLeaseLocked(sb *domain.Sandbox) error {
	lease, ok := m.leases[sb.SandboxID]
	if !ok {
		return nil
	}
	flags := m.enforceFlags[sb.SandboxID]
	if flags == nil {
		flags = map[string]bool{}
		m.enforceFlags[sb.SandboxID] = flags
	}
	now := m.clock.Now()
	h, live := m.handles[sb.SandboxID]
	if live && execStartable[sb.ObservedState] && now.After(lease.WallDeadline) {
		// Wall-deadline enforcement routes through the shared suspend path
		// so incarnation records, binding suspension, and handle cleanup
		// match an explicit Suspend exactly.
		return m.suspendWithReasonLocked(sb, "wall_deadline", false)
	}
	if !live {
		return nil
	}
	if sb.ObservedState != domain.SandboxRunning && sb.ObservedState != domain.SandboxBackgroundActive && sb.ObservedState != domain.SandboxQuiescent {
		return nil
	}
	stats, err := m.rt.Stats(h)
	if err != nil {
		return nil
	}
	check := func(resource string, used, limit int64) error {
		if limit <= 0 {
			return nil
		}
		ratio := float64(used) / float64(limit)
		switch {
		case ratio >= 1.0:
			if !flags[resource+"_exceeded"] {
				flags[resource+"_exceeded"] = true
				m.emit(sb, sb.SandboxID, domain.EventResourceLimitExceeded, map[string]any{
					"resource": resource, "used": used, "limit": limit,
					"action": "terminate_background",
				})
			}
			return m.rt.TerminateBackground(h)
		case ratio >= 0.8:
			if !flags[resource+"_approaching"] {
				flags[resource+"_approaching"] = true
				m.emit(sb, sb.SandboxID, domain.EventResourceLimitApproaching, map[string]any{
					"resource": resource, "used": used, "limit": limit,
				})
			}
		default:
			flags[resource+"_approaching"] = false
			flags[resource+"_exceeded"] = false
		}
		return nil
	}
	if err := check("process_count", int64(stats.ProcessCount), int64(lease.ProcessLimit)); err != nil {
		return err
	}
	if err := check("memory_bytes", stats.MemoryBytes, lease.MemoryLimit); err != nil {
		return err
	}
	if sb.ObservedState == domain.SandboxBackgroundActive && lease.MaxBackgroundWall > 0 {
		if since, ok := m.bgSince[sb.SandboxID]; ok && now.Sub(since) > lease.MaxBackgroundWall {
			if !flags["background_wall_exceeded"] {
				flags["background_wall_exceeded"] = true
				m.emit(sb, sb.SandboxID, domain.EventResourceLimitExceeded, map[string]any{
					"resource": "background_wall",
					"action":   "terminate_background",
				})
			}
			return m.rt.TerminateBackground(h)
		}
	}
	return nil
}

// Usage returns host-side usage counters for a live sandbox.
func (m *Manager) Usage(sandboxID string) (backendinterface.Stats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.handles[sandboxID]
	if !ok {
		return backendinterface.Stats{}, domain.ErrIllegalState
	}
	return m.rt.Stats(h)
}

// RuntimeFiles exposes the live runtime's workspace view for verification.
func (m *Manager) RuntimeFiles(sandboxID string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.handles[sandboxID]
	if !ok {
		return nil, domain.ErrIllegalState
	}
	return m.rt.WorkspaceFiles(h)
}

func (m *Manager) WorkspaceManifest(sandboxID string, generation int64) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sb, ok := m.sandboxes[sandboxID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return m.ws.ReadManifest(sb.WorkspaceID, generation)
}

func (m *Manager) Outbox() *eventservice.Outbox { return m.outbox }

// SetEnvironmentSource wires the prepared-environment build service.
func (m *Manager) SetEnvironmentSource(es EnvironmentSource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.envs = es
}
