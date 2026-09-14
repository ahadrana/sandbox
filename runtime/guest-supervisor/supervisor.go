// Package supervisor defines the guest-supervisor protocol: the data-plane
// contract between the control plane and a runtime incarnation (DESIGN §6.8).
// It is transport-agnostic; the local backend provides an in-process
// implementation and a remote transport can replace it later.
package supervisor

import (
	"errors"
	"time"

	"github.com/agent-sandbox/platform/domain"
)

var (
	ErrNotFound    = errors.New("execution not found")
	ErrTooLarge    = errors.New("requested chunk exceeds maximum")
	ErrUnsupported = errors.New("operation unsupported by this backend")
)

// MaxChunkBytes bounds a single StreamOutput read (backpressure contract).
const MaxChunkBytes = 1 << 20

type ExecRequest struct {
	ExecutionID string
	Command     string
	Env         map[string]string
	// Baseline tags a startup service: metered, but never quiescence-blocking.
	Baseline bool
}

type StatusResponse struct {
	ExecutionID string
	Running     bool
	ExitCode    int
	StartedAt   time.Time
	CompletedAt time.Time
}

// Result is the terminal outcome of an execution.
type Result struct {
	ExitCode    int
	StdoutRef   string
	StderrRef   string
	Usage       domain.ResourceUsage
	StartedAt   time.Time
	CompletedAt time.Time
}

type ProcessInfo struct {
	PID     int
	PGID    int
	Command string
}

// OutputChunk is one bounded chunk of a stream read.
type OutputChunk struct {
	Data   []byte
	Offset int64
	EOF    bool
}

// API is the supervisor protocol surface.
type API interface {
	// Exec starts a command asynchronously and returns once it is launched.
	Exec(req ExecRequest) error
	Status(executionID string) (StatusResponse, error)
	// Wait blocks until the execution exits and returns its terminal result.
	Wait(executionID string) (Result, error)
	Cancel(executionID string) error
	// ReadOutput returns at most maxBytes (capped at MaxChunkBytes) from
	// offset; output is spilled to storage, never buffered unboundedly.
	ReadOutput(executionID string, stderr bool, offset int64, maxBytes int) (OutputChunk, error)
	// ProcessInventory lists non-baseline processes owned by the incarnation.
	ProcessInventory() ([]ProcessInfo, error)
	Health() error
}
