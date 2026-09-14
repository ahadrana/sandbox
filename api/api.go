// Package api defines the versioned public API schemas of the platform.
package api

import (
	"time"

	"github.com/agent-sandbox/platform/domain"
)

// SchemaVersionV1 is the current schema version carried by requests and events.
const SchemaVersionV1 = 1

type CreateSandboxRequest struct {
	Version       int
	TenantID      string
	TaskRef       string
	EnvironmentID string
	PolicyRef     string
	// Priority (0-100) and Class (INTERACTIVE|BACKGROUND) drive placement
	// preemption when the fleet is full.
	Priority         int
	Class            string
	StartupCommands  []string
	BaselineCommands []string
}

type CreateSandboxResponse struct {
	Version int
	Sandbox domain.Sandbox
}

// StartExecutionRequest launches an Execution. IdempotencyKey makes launch
// retry-safe; ExpectedEpoch fences volatile-state-dependent operations.
// TenantID is the caller's asserted tenant context: when set, it must match
// the sandbox's owning tenant (INV-028).
type StartExecutionRequest struct {
	Version                int
	SandboxID              string
	TenantID               string
	PrincipalID            string
	IdempotencyKey         string
	Operation              domain.Operation
	ExpectedEpoch          int64
	DependsOnVolatileState bool
}

type ExecutionHandle struct {
	Version     int
	ExecutionID string
	SandboxID   string
	State       domain.ExecutionState
	Epoch       int64
}

// RestoreReport makes recovery semantics explicit: which generation was
// restored, whether uncommitted state was lost, and the epoch transition.
type RestoreReport struct {
	Version              int
	SandboxID            string
	PriorEpoch           int64
	NewEpoch             int64
	RestoredGeneration   int64
	UncommittedStateLost bool
	LostClasses          []domain.LostStateClass
}

type CommitWorkspaceRequest struct {
	Version          int
	SandboxID        string
	TenantID         string
	CauseExecutionID string
}

// CreateEndpointBindingRequest binds a logical name to a sandbox target port
// with an auth policy and TTL; the binding is fenced to the current
// execution epoch (PLAN §12).
type CreateEndpointBindingRequest struct {
	Version     int
	SandboxID   string
	TenantID    string
	TargetPort  int
	LogicalName string
	AuthPolicy  string
	TTL         time.Duration
}
