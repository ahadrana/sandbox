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
	// ErrPortConflict reports a host port already published for another
	// incarnation (typed so callers can distinguish it from plumbing
	// errors).
	ErrPortConflict = errors.New("host port already published")
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
	// SupportsPortPublish declares the endpoint data plane (ADR-007): the
	// backend can DNAT a host TCP port to an incarnation's guest port
	// (PortPublisher). False when the backend has no host networking.
	SupportsPortPublish bool
}

// PortPublisher is the endpoint data-plane seam (ADR-007): backends with
// host networking expose a guest TCP port on the host's address so endpoint
// bindings are reachable as host:port. The manager publishes a binding's
// target port while its sandbox is live and unpublishes on suspend,
// unbind, and expiry; the backend additionally tears every published rule
// down with the incarnation's networking (Terminate/KillRuntime/Restore).
// It is an OPTIONAL capability interface — backends assert it, never the
// Backend contract.
type PortPublisher interface {
	// PublishPort DNATs hostPort (on every host address) to the
	// incarnation's guestIP:guestPort. Deterministic conflict semantics:
	// the host port is fixed (no dynamic allocation) and a port owned by
	// another live incarnation fails with ErrPortConflict. Idempotent for
	// an identical re-publish (resume republish).
	PublishPort(h Handle, guestPort, hostPort int) error
	// UnpublishPort removes the hostPort DNAT rule; unknown ports are a
	// no-op (teardown is the backstop).
	UnpublishPort(h Handle, hostPort int) error
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
