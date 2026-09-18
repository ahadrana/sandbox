// Package domain defines the core IDs, enums, aggregates, and lifecycle
// state machines of the Agent Sandbox Platform.
package domain

import (
	"strconv"
	"sync"
	"time"
)

// Clock supplies time to logic paths; implementations must be injectable.
type Clock interface {
	Now() time.Time
}

// ManualClock is a deterministic Clock for tests and the conformance
// harness. It is goroutine-safe.
type ManualClock struct {
	mu sync.Mutex
	t  time.Time
}

func NewManualClock(start time.Time) *ManualClock { return &ManualClock{t: start} }

func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *ManualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// IDGen generates deterministic, unique IDs. It is goroutine-safe.
type IDGen struct {
	mu    sync.Mutex
	n     int64
	scope string
}

func NewIDGen() *IDGen { return &IDGen{} }

// NewScopedIDGen returns an IDGen whose IDs embed a scope segment:
// "prefix-scope-N" instead of "prefix-N". A control-plane process uses a
// per-boot scope so IDs it allocates after a restart can never collide with
// IDs a long-lived host-agent still remembers from a previous boot.
func NewScopedIDGen(scope string) *IDGen { return &IDGen{scope: scope} }

func (g *IDGen) Next(prefix string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	if g.scope != "" {
		return prefix + "-" + g.scope + "-" + itoa(g.n)
	}
	return prefix + "-" + itoa(g.n)
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

type EnvironmentStatus string

const (
	EnvironmentBuilding EnvironmentStatus = "BUILDING"
	EnvironmentActive   EnvironmentStatus = "ACTIVE"
	EnvironmentFailed   EnvironmentStatus = "FAILED"
	EnvironmentRetired  EnvironmentStatus = "RETIRED"
)

type SandboxState string

const (
	SandboxUnmaterialized   SandboxState = "UNMATERIALIZED"
	SandboxStarting         SandboxState = "STARTING"
	SandboxRunning          SandboxState = "RUNNING"
	SandboxBackgroundActive SandboxState = "BACKGROUND_ACTIVE"
	SandboxQuiescent        SandboxState = "QUIESCENT"
	SandboxSuspending       SandboxState = "SUSPENDING"
	SandboxSuspended        SandboxState = "SUSPENDED"
	SandboxResuming         SandboxState = "RESUMING"
	SandboxFailed           SandboxState = "FAILED"
	SandboxTerminated       SandboxState = "TERMINATED"
)

type ExecutionState string

const (
	ExecutionPending    ExecutionState = "PENDING"
	ExecutionDispatched ExecutionState = "DISPATCHED"
	ExecutionRunning    ExecutionState = "RUNNING"
	ExecutionCompleted  ExecutionState = "COMPLETED"
	ExecutionFailed     ExecutionState = "FAILED"
	ExecutionTimedOut   ExecutionState = "TIMED_OUT"
	ExecutionCancelled  ExecutionState = "CANCELLED"
)

func (s ExecutionState) Terminal() bool {
	switch s {
	case ExecutionCompleted, ExecutionFailed, ExecutionTimedOut, ExecutionCancelled:
		return true
	}
	return false
}

// Quota is a tenant admission-control limit at materialization (PLAN §13);
// zero fields are unlimited.
type Quota struct {
	TenantID         string
	MaxLiveSandboxes int
	MaxMemoryBytes   int64
	MaxCPUWeight     int64
}

// Workload classes for placement preemption.
const (
	ClassInteractive = "INTERACTIVE"
	ClassBackground  = "BACKGROUND"
)

type IncarnationState string

const (
	IncarnationStarting   IncarnationState = "STARTING"
	IncarnationRunning    IncarnationState = "RUNNING"
	IncarnationPaused     IncarnationState = "PAUSED"
	IncarnationLost       IncarnationState = "LOST"
	IncarnationTerminated IncarnationState = "TERMINATED"
)

type CheckpointType string

const (
	CheckpointWorkspaceOnly  CheckpointType = "WORKSPACE_ONLY"
	CheckpointExecutionState CheckpointType = "EXECUTION_STATE"
)

type EndpointBindingState string

const (
	EndpointActive    EndpointBindingState = "ACTIVE"
	EndpointSuspended EndpointBindingState = "SUSPENDED"
	EndpointReleased  EndpointBindingState = "RELEASED"
	EndpointExpired   EndpointBindingState = "EXPIRED"
	// EndpointUnbound is the terminal state after explicit delete or
	// sandbox terminate.
	EndpointUnbound EndpointBindingState = "UNBOUND"
)

// LostStateClass identifies a class of volatile state invalidated by an
// execution-epoch reset.
type LostStateClass string

const (
	LostProcess      LostStateClass = "PROCESS"
	LostMemory       LostStateClass = "MEMORY"
	LostListener     LostStateClass = "LISTENER"
	LostShellSession LostStateClass = "SHELL_SESSION"
)

// AllVolatileLostClasses is the full set lost on workspace-only recovery.
var AllVolatileLostClasses = []LostStateClass{
	LostProcess, LostMemory, LostListener, LostShellSession,
}

// Event types (FR-EV-001).
type EventType string

const (
	EventSandboxMaterialized      EventType = "SandboxMaterialized"
	EventSandboxSuspended         EventType = "SandboxSuspended"
	EventSandboxResumed           EventType = "SandboxResumed"
	EventSandboxFailed            EventType = "SandboxFailed"
	EventExecutionStarted         EventType = "ExecutionStarted"
	EventExecutionCompleted       EventType = "ExecutionCompleted"
	EventExecutionFailed          EventType = "ExecutionFailed"
	EventExecutionCancelled       EventType = "ExecutionCancelled"
	EventExecutionTimedOut        EventType = "ExecutionTimedOut"
	EventExecutionStateReset      EventType = "ExecutionStateReset"
	EventWorkspaceCommitted       EventType = "WorkspaceCommitted"
	EventResourceLimitApproaching EventType = "ResourceLimitApproaching"
	EventResourceLimitExceeded    EventType = "ResourceLimitExceeded"
	EventEndpointBound            EventType = "EndpointBound"
	EventEndpointUnbound          EventType = "EndpointUnbound"
	// EventEndpointPublishFailed records a data-plane publish failure on
	// an otherwise-ACTIVE binding (the binding stays bound; reachability
	// is degraded until a republish succeeds).
	EventEndpointPublishFailed EventType = "EndpointPublishFailed"
	EventQuotaExceeded         EventType = "QuotaExceeded"
	EventTenantDeleted         EventType = "TenantDeleted"
	EventSandboxPreempted      EventType = "SandboxPreempted"
	// Environment hook lifecycle (ADR-011 step 2): emitted around the
	// start/terminal hook block on every epoch-creating materialization.
	EventEnvironmentHooksStarted   EventType = "EnvironmentHooksStarted"
	EventEnvironmentHooksCompleted EventType = "EnvironmentHooksCompleted"
	EventEnvironmentHooksFailed    EventType = "EnvironmentHooksFailed"
)

type Tenant struct {
	TenantID string
	PolicyID string
	QuotaID  string
}

type RepoInput struct {
	RepoURL string
	SHA     string
}

// EnvironmentRecipe is an environment's restart recipe (ADR-011 step 2):
// hooks run on every epoch-creating materialization of a sandbox built from
// that environment. Start runs sequentially and must exit 0; Terminals are
// long-running processes launched (not waited on) after Start completes.
// Hooks must be idempotent: any sandbox may re-run them on a later epoch.
type EnvironmentRecipe struct {
	Start     []string `json:"start,omitempty"`
	Terminals []string `json:"terminals,omitempty"`
}

type Environment struct {
	EnvironmentID   string
	Name            string // tenant-visible family
	Version         int64
	Status          EnvironmentStatus
	BaseRuntimeRef  string
	RepoInputs      []RepoInput
	ConfigDigest    string
	ArtifactRefs    []string
	LogRef          string
	CreatedAt       time.Time
	IntegrityDigest string
}

type Workspace struct {
	WorkspaceID       string
	TenantID          string
	BaseEnvironmentID string
	HeadGeneration    int64
}

type WorkspaceGeneration struct {
	WorkspaceID      string
	Generation       int64
	ParentGeneration *int64
	ManifestRef      string
	IntegrityDigest  string
	CommittedAt      time.Time
	CauseExecutionID *string
}

type Sandbox struct {
	SandboxID            string
	TenantID             string
	TaskRef              string
	EnvironmentID        string
	WorkspaceID          string
	DesiredState         SandboxState
	ObservedState        SandboxState
	ExecutionEpoch       int64
	WorkspaceGeneration  int64
	PolicyRef            string
	LeaseRef             *string
	RuntimeIncarnationID *string
	CheckpointRef        *string
	// StartupCommands run per session after workspace materialization,
	// before RUNNING (FR-ENV-005): services/dev servers belong here, not in
	// the immutable environment.
	// Priority (0-100) and WorkloadClass (INTERACTIVE|BACKGROUND) drive
	// placement preemption (PLAN §13).
	Priority        int
	WorkloadClass   string
	StartupCommands []string
	// BaselineCommands are startup commands tagged as baseline services:
	// metered and lease-bound, but never blocking quiescence.
	BaselineCommands []string
	// StartHooks/TerminalHooks are the sandbox's restart recipe (ADR-011):
	// the environment's start/terminal hooks resolved at create time (or
	// from the snapshot package on restore) so an epoch-creating resume
	// reconstructs services even after the environment was deleted or
	// upgraded. Start hooks run sequentially and must exit 0; terminal
	// hooks are long-running processes launched after start completes.
	StartHooks    []string
	TerminalHooks []string
	Version       int64
}

type RuntimeIncarnation struct {
	IncarnationID      string
	SandboxID          string
	ExecutionEpoch     int64
	RuntimeBackend     string
	HostID             string
	State              IncarnationState
	StartedAt          time.Time
	LastHeartbeat      time.Time
	SupervisorEndpoint string
	RuntimeMetadata    map[string]string
}

// BackgroundSpec describes a background descendant spawned by an Operation.
type BackgroundSpec struct {
	Name string
	// Ticks is how many runtime ticks the descendant stays alive.
	Ticks int
}

// Operation is the requested work of an Execution.
type Operation struct {
	Command string
	// Writes are workspace file mutations applied on success.
	Writes map[string]string
	// SpawnBackground lists descendants that outlive the operation.
	SpawnBackground []BackgroundSpec
	// Baseline designates a startup service: metered and lease-bound, but it
	// never blocks sandbox quiescence.
	Baseline bool
	// Hook labels an environment hook execution (ADR-011): "start" or
	// "terminal". Empty is a normal execution. Lets UIs/audits distinguish
	// restart-recipe work from agent-driven work (INV-010).
	Hook string
	// Env carries per-execution environment variables (e.g. broker-issued
	// credential tokens) delivered to the process but never embedded in
	// event payloads (INV-025).
	Env map[string]string
	// EgressDestination declares a network destination for supervisor-layer
	// egress policy evaluation (PLAN §12); empty means undeclared.
	EgressDestination string
	ExitCode          int
	Fail              bool
}

type ResourceUsage struct {
	CPUSeconds   float64
	MemoryBytes  int64
	StorageBytes int64
}

type Execution struct {
	ExecutionID                  string
	IdempotencyKey               string
	TenantID                     string
	SandboxID                    string
	PrincipalID                  string
	ExecutionEpoch               int64
	RequestedWorkspaceGeneration int64
	Operation                    Operation
	State                        ExecutionState
	CreatedAt                    time.Time
	StartedAt                    *time.Time
	CompletedAt                  *time.Time
	ExitCode                     *int
	TerminalReason               *string
	StdoutRef                    *string
	StderrRef                    *string
	GenerationBefore             int64
	GenerationAfter              *int64
	ResourceUsage                ResourceUsage
}

type Lease struct {
	LeaseID          string
	TenantID         string
	TaskRef          string
	SandboxID        string
	CPUPolicy        string
	MemoryLimit      int64
	WallDeadline     time.Time
	StorageLimit     int64
	ProcessLimit     int
	NetworkPolicyRef string
	Priority         int
	BackgroundPolicy string
	// MaxBackgroundWall bounds continuous BACKGROUND_ACTIVE wall time.
	MaxBackgroundWall time.Duration
}

type Checkpoint struct {
	CheckpointID          string
	SandboxID             string
	ExecutionEpoch        int64
	WorkspaceGeneration   int64
	Type                  CheckpointType
	RuntimeBackend        string
	CompatibilityMetadata map[string]string
	Artifacts             []string
	CreatedAt             time.Time
}

type EndpointBinding struct {
	BindingID      string
	TenantID       string
	SandboxID      string
	ExecutionEpoch int64
	TargetPort     int
	LogicalName    string
	AuthPolicy     string
	ExpiresAt      time.Time
	State          EndpointBindingState
}

// Event is the durable event envelope. Bulk stdout/stderr is never embedded;
// payloads carry references only.
type Event struct {
	EventID          string
	AggregateID      string
	AggregateVersion int64
	EventType        EventType
	Timestamp        time.Time
	TenantID         string
	TaskRef          string
	SchemaVersion    int
	Payload          map[string]any
}
