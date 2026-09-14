// Package fakebackend is a deterministic, scriptable in-memory
// RuntimeBackend with fault-injection hooks.
package fakebackend

import (
	"errors"
	"fmt"
	"sync"

	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/runtime/backend-interface"
	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

type runtime struct {
	spec        backendinterface.Spec
	files       map[string]string
	started     bool
	paused      bool
	dead        bool
	terminated  bool
	dirty       bool
	descendants map[string]int
	baseline    map[string]bool
	stats       backendinterface.Stats
	statsSet    bool
	ops         map[string]domain.Operation
}

// Faults controls deterministic fault injection.
type Faults struct {
	DropResponses  bool
	LoseAcks       bool
	SupervisorDead bool
	// FailCreate makes Create fail, simulating placement/runtime rejection.
	FailCreate bool
	// CorruptCheckpoint makes Restore fail as if checkpoint metadata were
	// corrupt or incompatible (INV-009 fallback testing).
	CorruptCheckpoint bool
}

// Backend is a deterministic fake RuntimeBackend.
type Backend struct {
	mu       sync.Mutex
	runtimes map[string]*runtime
	Faults   Faults
}

func New() *Backend {
	return &Backend{runtimes: map[string]*runtime{}}
}

// Capabilities declares the fake's scripted surface.
func (b *Backend) Capabilities() backendinterface.Capabilities {
	return backendinterface.Capabilities{
		IsolationClass:     backendinterface.IsolationProcess,
		SupportsPause:      true,
		SupportsSnapshot:   true,
		SupportsRestore:    true,
		SupportsCheckpoint: true,
	}
}

func copyFiles(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (b *Backend) get(h backendinterface.Handle) (*runtime, error) {
	r, ok := b.runtimes[h.IncarnationID]
	if !ok || r.terminated {
		return nil, backendinterface.ErrNotFound
	}
	if r.dead {
		return nil, backendinterface.ErrRuntimeGone
	}
	return r, nil
}

func (b *Backend) Create(spec backendinterface.Spec) (backendinterface.Handle, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Faults.FailCreate {
		return backendinterface.Handle{}, errors.New("injected create failure")
	}
	b.runtimes[spec.IncarnationID] = &runtime{
		spec:        spec,
		files:       copyFiles(spec.WorkspaceManifest),
		descendants: map[string]int{},
		baseline:    map[string]bool{},
		ops:         map[string]domain.Operation{},
	}
	return backendinterface.Handle{IncarnationID: spec.IncarnationID}, nil
}

func (b *Backend) Start(h backendinterface.Handle) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.get(h)
	if err != nil {
		return err
	}
	if r.started {
		return backendinterface.ErrIllegalState
	}
	r.started = true
	return nil
}

func (b *Backend) Pause(h backendinterface.Handle) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.get(h)
	if err != nil {
		return err
	}
	if !r.started || r.paused {
		return backendinterface.ErrIllegalState
	}
	r.paused = true
	return nil
}

func (b *Backend) Resume(h backendinterface.Handle) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.get(h)
	if err != nil {
		return err
	}
	if !r.paused {
		return backendinterface.ErrIllegalState
	}
	r.paused = false
	return nil
}

func (b *Backend) Snapshot(h backendinterface.Handle) (backendinterface.CheckpointData, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.get(h)
	if err != nil {
		return backendinterface.CheckpointData{}, err
	}
	return backendinterface.CheckpointData{
		IncarnationID: h.IncarnationID,
		Files:         copyFiles(r.files),
		Metadata:      map[string]string{"backend": "fake"},
	}, nil
}

func (b *Backend) Restore(cp backendinterface.CheckpointData) (backendinterface.Handle, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Faults.CorruptCheckpoint {
		return backendinterface.Handle{}, fmt.Errorf("checkpoint metadata corrupt or incompatible")
	}
	b.runtimes[cp.IncarnationID] = &runtime{
		spec:        backendinterface.Spec{IncarnationID: cp.IncarnationID},
		files:       copyFiles(cp.Files),
		started:     true,
		descendants: map[string]int{},
		ops:         map[string]domain.Operation{},
	}
	return backendinterface.Handle{IncarnationID: cp.IncarnationID}, nil
}

func (b *Backend) Terminate(h backendinterface.Handle) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.runtimes[h.IncarnationID]
	if !ok {
		return nil
	}
	r.terminated = true
	r.files = nil
	r.descendants = nil
	return nil
}

func (b *Backend) Stats(h backendinterface.Handle) (backendinterface.Stats, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.get(h)
	if err != nil {
		return backendinterface.Stats{}, err
	}
	if !r.statsSet {
		r.stats.ProcessCount = len(r.descendants)
	}
	return r.stats, nil
}

// ScriptStats overrides reported usage (deterministic policy testing).
func (b *Backend) ScriptStats(h backendinterface.Handle, stats backendinterface.Stats) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r, err := b.get(h); err == nil {
		r.stats = stats
		r.statsSet = true
	}
}

// Exec applies an operation to the runtime's workspace view. It is the fake
// supervisor data path; faults are applied deterministically.
func (b *Backend) Exec(h backendinterface.Handle, executionID string, op domain.Operation) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Faults.DropResponses {
		return backendinterface.ErrResponseDropped
	}
	if b.Faults.SupervisorDead {
		return backendinterface.ErrSupervisorDead
	}
	r, err := b.get(h)
	if err != nil {
		return err
	}
	if !r.started || r.paused {
		return backendinterface.ErrIllegalState
	}
	for path, content := range op.Writes {
		r.files[path] = content
		r.dirty = true
	}
	for _, bg := range op.SpawnBackground {
		r.descendants[bg.Name] = bg.Ticks
		r.baseline[bg.Name] = op.Baseline
	}
	r.stats.CPUSeconds += 0.01 * float64(1+len(op.SpawnBackground))
	r.ops[executionID] = op
	if b.Faults.LoseAcks {
		return backendinterface.AckLostError{}
	}
	if op.Fail {
		return &backendinterface.ExecError{ExitCode: op.ExitCode}
	}
	return nil
}

// WaitExecution returns the scripted terminal result immediately.
func (b *Backend) WaitExecution(h backendinterface.Handle, executionID string) (supervisor.Result, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.get(h)
	if err != nil {
		return supervisor.Result{}, err
	}
	op, ok := r.ops[executionID]
	if !ok {
		return supervisor.Result{}, supervisor.ErrNotFound
	}
	return supervisor.Result{
		ExitCode:  op.ExitCode,
		StdoutRef: "out://" + executionID + "/stdout",
		StderrRef: "out://" + executionID + "/stderr",
		Usage:     domain.ResourceUsage{CPUSeconds: r.stats.CPUSeconds},
	}, nil
}

// KillRuntime simulates a crash: volatile state and uncommitted writes die.
func (b *Backend) KillRuntime(h backendinterface.Handle) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r, ok := b.runtimes[h.IncarnationID]; ok {
		r.dead = true
		r.files = nil
		r.descendants = nil
		r.dirty = false
	}
}

// Alive reports whether the incarnation still exists in this backend.
func (b *Backend) Alive(h backendinterface.Handle) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.runtimes[h.IncarnationID]
	return ok && !r.dead && !r.terminated
}

// Tick advances all descendants by one tick; expired descendants exit.
func (b *Backend) Tick() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, r := range b.runtimes {
		for name, ticks := range r.descendants {
			if ticks <= 1 {
				delete(r.descendants, name)
			} else {
				r.descendants[name] = ticks - 1
			}
		}
	}
}

func (b *Backend) LiveDescendants(h backendinterface.Handle) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.get(h)
	if err != nil {
		return 0
	}
	return len(r.descendants)
}

// ProcessInventory synthesizes one scripted entry per descendant.
func (b *Backend) ProcessInventory(h backendinterface.Handle) ([]supervisor.ProcessInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.get(h)
	if err != nil {
		return nil, err
	}
	out := make([]supervisor.ProcessInfo, 0, len(r.descendants))
	for name := range r.descendants {
		out = append(out, supervisor.ProcessInfo{Command: name})
	}
	return out, nil
}

// LiveNonBaselineDescendants counts scripted descendants that are not
// baseline-tagged.
func (b *Backend) LiveNonBaselineDescendants(h backendinterface.Handle) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.get(h)
	if err != nil {
		return 0
	}
	n := 0
	for name := range r.descendants {
		if !r.baseline[name] {
			n++
		}
	}
	return n
}

// TerminateBackground removes all non-baseline scripted descendants.
func (b *Backend) TerminateBackground(h backendinterface.Handle) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.get(h)
	if err != nil {
		return err
	}
	for name := range r.descendants {
		if !r.baseline[name] {
			delete(r.descendants, name)
			delete(r.baseline, name)
		}
	}
	return nil
}

// WorkspaceFiles returns the runtime's current full workspace view.
func (b *Backend) WorkspaceFiles(h backendinterface.Handle) (map[string]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.get(h)
	if err != nil {
		return nil, err
	}
	return copyFiles(r.files), nil
}

// Dirty reports whether the runtime holds uncommitted workspace writes.
func (b *Backend) Dirty(h backendinterface.Handle) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.get(h)
	if err != nil {
		return false
	}
	return r.dirty
}

// MarkCommitted records that the runtime's writes were committed durably.
func (b *Backend) MarkCommitted(h backendinterface.Handle) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r, err := b.get(h); err == nil {
		r.dirty = false
	}
}

// IsAckLost classifies an error as a lost-ACK fault.
func IsAckLost(err error) bool {
	var ack backendinterface.AckLostError
	return errors.As(err, &ack)
}
