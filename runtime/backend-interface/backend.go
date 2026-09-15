// Package backendinterface defines the runtime backend contract. It must not
// expose vendor-specific (Firecracker/Kubernetes) concepts (INV-026).
package backendinterface

import "errors"

var (
	ErrRuntimeGone     = errors.New("runtime incarnation gone")
	ErrNotFound        = errors.New("runtime handle not found")
	ErrIllegalState    = errors.New("runtime in wrong state for operation")
	ErrResponseDropped = errors.New("fault injection: response dropped")
	ErrSupervisorDead  = errors.New("fault injection: supervisor dead")
)

// AckLostError reports a response lost after the operation was applied;
// callers must retry with the same idempotency key.
type AckLostError struct{}

func (AckLostError) Error() string { return "fault injection: ack lost after apply" }

// ExecError reports an operation that ran and failed.
type ExecError struct {
	ExitCode int
}

func (e *ExecError) Error() string { return "operation failed" }

type Spec struct {
	SandboxID           string
	IncarnationID       string
	Epoch               int64
	EnvironmentID       string
	WorkspaceID         string
	WorkspaceGeneration int64
	MemoryBytes         int64
	WorkspaceManifest   map[string]string
	// Env carries incarnation-wide environment (e.g. the serialized egress
	// policy as AGENT_SANDBOX_EGRESS) added to every spawned process.
	Env map[string]string
	// Priority (0-100) is forwarded to the scheduler.
	Priority int
	// CheckpointFacts, when non-nil, carries the host-facts metadata
	// (arch/kernel_release/cpu_part) of the checkpoint this create
	// materializes a restore from (copied from CheckpointData.Metadata,
	// P1.7). Placement uses it to gate the checkpoint-locality bonus to
	// hosts whose facts match exactly; backends ignore it.
	CheckpointFacts map[string]string
}

type Handle struct {
	IncarnationID string
}

type Stats struct {
	CPUSeconds    float64
	MemoryBytes   int64
	ProcessCount  int
	UptimeSeconds int64
}

type CheckpointData struct {
	IncarnationID string
	Files         map[string]string
	Metadata      map[string]string
}

// IsolationClass declares the strength of a backend's isolation boundary
// (PLAN §9 gate: differences require explicit capability declarations).
type IsolationClass string

const (
	IsolationProcess   IsolationClass = "PROCESS"
	IsolationNamespace IsolationClass = "NAMESPACE"
	IsolationVM        IsolationClass = "VM"
)

// Capabilities declares what a backend actually supports; conformance tests
// skip on missing capabilities rather than failing on silent differences.
type Capabilities struct {
	IsolationClass   IsolationClass
	SupportsPause    bool
	SupportsSnapshot bool
	SupportsRestore  bool
	// SupportsCheckpoint declares execution-state checkpointing (STOP/CONT
	// or snapshot class): pause + snapshot capture the live execution.
	SupportsCheckpoint bool
	// CheckpointReclaimsMemory declares snapshot-class checkpoints whose
	// capture lets the runtime be terminated and its RAM honestly reported
	// as reclaimed (e.g. full VM snapshot to disk); Restore boots back from
	// the checkpoint with real continuity. When false (STOP/CONT class),
	// RAM stays allocated across a checkpoint suspend and is reported 0.
	CheckpointReclaimsMemory bool
	NetworkIsolated          bool
	HostCredentialFree       bool
}

// Backend is the runtime backend contract (DESIGN §6.7).
type Backend interface {
	Capabilities() Capabilities
	Create(spec Spec) (Handle, error)
	Start(h Handle) error
	Pause(h Handle) error
	Resume(h Handle) error
	Snapshot(h Handle) (CheckpointData, error)
	Restore(cp CheckpointData) (Handle, error)
	Terminate(h Handle) error
	Stats(h Handle) (Stats, error)
}
