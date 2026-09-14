package sandboxmanager

import (
	"sync"

	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

// IdempotencyRecord persists one idempotency-key -> execution binding.
type IdempotencyRecord struct {
	SandboxID   string
	Key         string
	ExecutionID string
}

// OutcomeRecord persists an observed execution outcome before the workspace
// commit / state update chain, so recovery can finalize exactly once.
type OutcomeRecord struct {
	ExecutionID string
	Result      supervisor.Result
}

// Tx is one atomic control-plane transaction: state changes and outbox
// events are committed together (transactional outbox, DESIGN §6.10).
type Tx struct {
	Sandboxes    []*domain.Sandbox
	Executions   []*domain.Execution
	Incarnations []*domain.RuntimeIncarnation
	Idempotency  []IdempotencyRecord
	Outcomes     []OutcomeRecord
	Leases       []*domain.Lease
	Checkpoints  []*domain.Checkpoint
	Bindings     []*domain.EndpointBinding
	Events       []domain.Event
}

func (t Tx) Empty() bool {
	return len(t.Sandboxes) == 0 && len(t.Executions) == 0 && len(t.Incarnations) == 0 &&
		len(t.Idempotency) == 0 && len(t.Outcomes) == 0 && len(t.Leases) == 0 &&
		len(t.Checkpoints) == 0 && len(t.Bindings) == 0 && len(t.Events) == 0
}

// Snapshot is the full recoverable control-plane state.
type Snapshot struct {
	Sandboxes       map[string]domain.Sandbox
	Executions      map[string]domain.Execution
	Incarnations    map[string]domain.RuntimeIncarnation
	IdempotencyKeys map[string]string
	Outcomes        map[string]supervisor.Result
	Leases          map[string]domain.Lease
	Checkpoints     map[string]domain.Checkpoint
	Bindings        map[string]domain.EndpointBinding
	Events          []domain.Event
}

// Store is the narrow persistence interface for control-plane metadata.
type Store interface {
	// Commit applies one transaction atomically.
	Commit(tx Tx) error
	Load() (Snapshot, error)
}

func emptySnapshot() Snapshot {
	return Snapshot{
		Sandboxes: map[string]domain.Sandbox{}, Executions: map[string]domain.Execution{},
		Incarnations: map[string]domain.RuntimeIncarnation{}, IdempotencyKeys: map[string]string{},
		Outcomes:    map[string]supervisor.Result{},
		Leases:      map[string]domain.Lease{},
		Checkpoints: map[string]domain.Checkpoint{},
		Bindings:    map[string]domain.EndpointBinding{},
	}
}

// MemoryStore is an in-memory Store for fast tests.
type MemoryStore struct {
	mu   sync.Mutex
	snap Snapshot
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{snap: emptySnapshot()}
}

func (s *MemoryStore) Commit(tx Tx) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	applyTx(&s.snap, tx)
	return nil
}

func applyTx(snap *Snapshot, tx Tx) {
	for _, sb := range tx.Sandboxes {
		snap.Sandboxes[sb.SandboxID] = *sb
	}
	for _, ex := range tx.Executions {
		snap.Executions[ex.ExecutionID] = *ex
	}
	for _, inc := range tx.Incarnations {
		snap.Incarnations[inc.IncarnationID] = *inc
	}
	for _, r := range tx.Idempotency {
		snap.IdempotencyKeys[r.SandboxID+"|"+r.Key] = r.ExecutionID
	}
	for _, o := range tx.Outcomes {
		snap.Outcomes[o.ExecutionID] = o.Result
	}
	for _, l := range tx.Leases {
		snap.Leases[l.SandboxID] = *l
	}
	for _, cp := range tx.Checkpoints {
		snap.Checkpoints[cp.CheckpointID] = *cp
	}
	for _, b := range tx.Bindings {
		snap.Bindings[b.BindingID] = *b
	}
	snap.Events = append(snap.Events, tx.Events...)
}

func (s *MemoryStore) Load() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copySnapshot(s.snap), nil
}

func copySnapshot(in Snapshot) Snapshot {
	out := emptySnapshot()
	for k, v := range in.Sandboxes {
		out.Sandboxes[k] = v
	}
	for k, v := range in.Executions {
		out.Executions[k] = v
	}
	for k, v := range in.Incarnations {
		out.Incarnations[k] = v
	}
	for k, v := range in.IdempotencyKeys {
		out.IdempotencyKeys[k] = v
	}
	for k, v := range in.Outcomes {
		out.Outcomes[k] = v
	}
	for k, v := range in.Leases {
		out.Leases[k] = v
	}
	for k, v := range in.Checkpoints {
		out.Checkpoints[k] = v
	}
	for k, v := range in.Bindings {
		out.Bindings[k] = v
	}
	out.Events = append(out.Events, in.Events...)
	return out
}
