package domain

import "errors"

var (
	ErrIllegalTransition  = errors.New("illegal state transition")
	ErrEpochConflict      = errors.New("execution epoch conflict")
	ErrIllegalState       = errors.New("operation not allowed in current state")
	ErrEgressDenied       = errors.New("egress destination denied by policy")
	ErrNotFound           = errors.New("not found")
	ErrGenerationConflict = errors.New("workspace generation conflict")
)

// EpochConflictError describes a stale-epoch rejection (FR-EP-004).
type EpochConflictError struct {
	SandboxID string
	Expected  int64
	Actual    int64
}

func (e *EpochConflictError) Error() string {
	return "execution epoch conflict: sandbox " + e.SandboxID +
		" expected " + itoa(e.Expected) + " actual " + itoa(e.Actual)
}

func (e *EpochConflictError) Unwrap() error { return ErrEpochConflict }

// QuotaExceededError reports tenant quota admission denial at
// materialization (PLAN §13): explicit, never silent queueing.
type QuotaExceededError struct {
	TenantID string
	Resource string
	Limit    int64
}

func (e *QuotaExceededError) Error() string {
	return "tenant " + e.TenantID + " quota exceeded: " + e.Resource
}

// ErrUnauthorized marks cross-tenant access rejection (INV-028).
var ErrUnauthorized = errors.New("cross-tenant access denied")

// ErrInvalidRequest marks a request that fails schema validation (e.g.
// Priority out of range, unknown workload Class).
var ErrInvalidRequest = errors.New("invalid request")

// UnauthorizedError reports a request whose asserted tenant does not own the
// target sandbox. Authentication of the principal itself remains a gateway
// concern (DESIGN §6.1); this is ownership enforcement only.
type UnauthorizedError struct {
	TenantID  string
	OwnerID   string
	SandboxID string
}

func (e *UnauthorizedError) Error() string {
	return "tenant " + e.TenantID + " cannot access sandbox " + e.SandboxID +
		" owned by tenant " + e.OwnerID
}

func (e *UnauthorizedError) Unwrap() error { return ErrUnauthorized }

var sandboxTransitions = map[SandboxState][]SandboxState{
	SandboxUnmaterialized:   {SandboxStarting, SandboxFailed, SandboxTerminated},
	SandboxStarting:         {SandboxRunning, SandboxFailed, SandboxTerminated},
	SandboxRunning:          {SandboxBackgroundActive, SandboxQuiescent, SandboxSuspending, SandboxFailed, SandboxTerminated},
	SandboxBackgroundActive: {SandboxRunning, SandboxQuiescent, SandboxSuspending, SandboxFailed, SandboxTerminated},
	SandboxQuiescent:        {SandboxRunning, SandboxSuspending, SandboxFailed, SandboxTerminated},
	SandboxSuspending:       {SandboxSuspended, SandboxFailed, SandboxTerminated},
	SandboxSuspended:        {SandboxResuming, SandboxFailed, SandboxTerminated},
	SandboxResuming:         {SandboxRunning, SandboxFailed, SandboxTerminated},
	SandboxFailed:           {SandboxStarting, SandboxSuspended, SandboxUnmaterialized, SandboxTerminated},
	SandboxTerminated:       {},
}

// TransitionSandbox enforces the sandbox lifecycle state machine.
// Self-transitions are illegal: idempotent replay must be handled by the
// caller, not by silently re-entering a state.
func TransitionSandbox(from, to SandboxState) error {
	if from == to {
		return ErrIllegalTransition
	}
	for _, t := range sandboxTransitions[from] {
		if t == to {
			return nil
		}
	}
	return ErrIllegalTransition
}

var executionTransitions = map[ExecutionState][]ExecutionState{
	ExecutionPending:    {ExecutionDispatched, ExecutionCancelled},
	ExecutionDispatched: {ExecutionRunning, ExecutionCancelled, ExecutionTimedOut},
	ExecutionRunning:    {ExecutionCompleted, ExecutionFailed, ExecutionTimedOut, ExecutionCancelled},
}

// TransitionExecution enforces the execution lifecycle state machine.
// Self-transitions are illegal (see TransitionSandbox).
func TransitionExecution(from, to ExecutionState) error {
	if from == to {
		return ErrIllegalTransition
	}
	for _, t := range executionTransitions[from] {
		if t == to {
			return nil
		}
	}
	return ErrIllegalTransition
}
