// Package agentdriver is the deterministic reference agent. It drives
// scenarios through the public API surface with a seeded RNG and no LLM
// (INV-003, DESIGN §13).
package agentdriver

import (
	"math/rand"
	"time"

	"github.com/agent-sandbox/platform/api"
	"github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/domain"
)

type Driver struct {
	Mgr         *sandboxmanager.Manager
	TenantID    string
	PrincipalID string

	rng *rand.Rand
	key int
}

func New(mgr *sandboxmanager.Manager, tenantID, principalID string, seed int64) *Driver {
	return &Driver{
		Mgr:         mgr,
		TenantID:    tenantID,
		PrincipalID: principalID,
		rng:         rand.New(rand.NewSource(seed)),
	}
}

// NewKey returns a deterministic, unique idempotency key for this driver.
func (d *Driver) NewKey() string {
	d.key++
	return "idem-" + d.PrincipalID + "-" + itoa(d.key)
}

func itoa(n int) string {
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

// RandomContent generates deterministic pseudo-random file content.
func (d *Driver) RandomContent(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[d.rng.Intn(len(letters))]
	}
	return string(b)
}

func (d *Driver) CreateSandbox(taskRef string) (*domain.Sandbox, error) {
	resp, err := d.Mgr.CreateSandbox(api.CreateSandboxRequest{
		Version:       api.SchemaVersionV1,
		TenantID:      d.TenantID,
		TaskRef:       taskRef,
		EnvironmentID: "env-base-1",
		PolicyRef:     "policy-default",
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// EnsureMaterialized materializes the sandbox if it is not live.
func (d *Driver) EnsureMaterialized(sandboxID string) (*api.RestoreReport, error) {
	sb, err := d.Mgr.GetSandbox(sandboxID)
	if err != nil {
		return nil, err
	}
	switch sb.ObservedState {
	case domain.SandboxUnmaterialized, domain.SandboxFailed:
		return d.Mgr.Materialize(sandboxID)
	case domain.SandboxSuspended:
		return d.Mgr.Resume(sandboxID)
	}
	return &api.RestoreReport{
		Version:            api.SchemaVersionV1,
		SandboxID:          sandboxID,
		NewEpoch:           sb.ExecutionEpoch,
		RestoredGeneration: sb.WorkspaceGeneration,
	}, nil
}

// Exec runs an operation asynchronously and returns the execution handle.
func (d *Driver) Exec(sandboxID string, op domain.Operation) (*domain.Execution, error) {
	sb, err := d.Mgr.GetSandbox(sandboxID)
	if err != nil {
		return nil, err
	}
	return d.Mgr.StartExecution(api.StartExecutionRequest{
		Version:        api.SchemaVersionV1,
		SandboxID:      sandboxID,
		PrincipalID:    d.PrincipalID,
		IdempotencyKey: d.NewKey(),
		Operation:      op,
		ExpectedEpoch:  sb.ExecutionEpoch,
	})
}

// ExecSync runs an operation and waits for successful completion.
func (d *Driver) ExecSync(sandboxID string, op domain.Operation) (*domain.Execution, error) {
	ex, err := d.Exec(sandboxID, op)
	if err != nil {
		return nil, err
	}
	if ex.State == domain.ExecutionFailed {
		return ex, nil
	}
	return d.Mgr.CompleteExecution(ex.ExecutionID)
}

// Advance moves simulated time forward by one tick.
func (d *Driver) Advance() error {
	return d.Mgr.Tick(time.Second)
}
