package localbackend

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/runtime/backend-interface"
	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

// CommandWrapper rewrites the argv/env of every spawned command, allowing
// stronger-isolation variants (e.g. bubblewrap) to confine the process while
// keeping identical lifecycle semantics.
type CommandWrapper func(argv, env []string, wsDir string) (newArgv, newEnv []string)

// Option configures a Backend.
type Option func(*Backend)

// WithCommandWrapper confines all spawned commands through w.
func WithCommandWrapper(w CommandWrapper) Option {
	return func(b *Backend) { b.wrapper = w }
}

// WithCapabilities overrides the declared capabilities.
func WithCapabilities(c backendinterface.Capabilities) Option {
	return func(b *Backend) { b.caps = c }
}

type incarnation struct {
	id      string
	spec    backendinterface.Spec
	wsDir   string
	sup     *localSupervisor
	started bool
	paused  bool
	dead    bool
	dirty   bool
	ops     map[string]domain.Operation
}

// Backend is a local process-based RuntimeBackend (dev/test).
type Backend struct {
	mu      sync.Mutex
	root    string
	incs    map[string]*incarnation
	wrapper CommandWrapper
	caps    backendinterface.Capabilities
	// CorruptCheckpoint is a test fault hook: Restore fails as if the
	// checkpoint metadata were corrupt or incompatible (INV-009).
	CorruptCheckpoint bool
}

// New creates a backend storing incarnation workspaces under root.
func New(root string, opts ...Option) (*Backend, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	b := &Backend{
		root: root,
		incs: map[string]*incarnation{},
		caps: backendinterface.Capabilities{
			IsolationClass:     backendinterface.IsolationProcess,
			SupportsPause:      true,
			SupportsCheckpoint: true,
		},
	}
	for _, opt := range opts {
		opt(b)
	}
	return b, nil
}

// Capabilities declares this backend's isolation surface.
func (b *Backend) Capabilities() backendinterface.Capabilities { return b.caps }

func (b *Backend) get(h backendinterface.Handle) (*incarnation, error) {
	inc, ok := b.incs[h.IncarnationID]
	if !ok {
		return nil, backendinterface.ErrNotFound
	}
	if inc.dead {
		return nil, backendinterface.ErrRuntimeGone
	}
	return inc, nil
}

func (b *Backend) Create(spec backendinterface.Spec) (backendinterface.Handle, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	dir := filepath.Join(b.root, spec.IncarnationID)
	wsDir := filepath.Join(dir, "workspace")
	outDir := filepath.Join(dir, "output")
	if err := os.MkdirAll(wsDir, 0o755); err != nil {
		return backendinterface.Handle{}, err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return backendinterface.Handle{}, err
	}
	for path, content := range spec.WorkspaceManifest {
		if err := writeWorkspaceFile(wsDir, path, content); err != nil {
			return backendinterface.Handle{}, err
		}
	}
	sup := newLocalSupervisor(wsDir, outDir, spec.IncarnationID, b.wrapper)
	for k, v := range spec.Env {
		sup.extraEnv = append(sup.extraEnv, k+"="+v)
	}
	b.incs[spec.IncarnationID] = &incarnation{
		id:    spec.IncarnationID,
		spec:  spec,
		wsDir: wsDir,
		sup:   sup,
		ops:   map[string]domain.Operation{},
	}
	return backendinterface.Handle{IncarnationID: spec.IncarnationID}, nil
}

func writeWorkspaceFile(wsDir, path, content string) error {
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return fmt.Errorf("unsafe workspace path: %q", path)
	}
	full := filepath.Join(wsDir, clean)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	return os.WriteFile(full, []byte(content), 0o644)
}

func (b *Backend) Start(h backendinterface.Handle) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, err := b.get(h)
	if err != nil {
		return err
	}
	if inc.started {
		return backendinterface.ErrIllegalState
	}
	inc.started = true
	return nil
}

// Pause SIGSTOPs every owned process: CPU is reclaimed, RAM is not (STOP/CONT
// class checkpointing — the honest capability boundary).
func (b *Backend) Pause(h backendinterface.Handle) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, err := b.get(h)
	if err != nil {
		return err
	}
	if !inc.started || inc.paused {
		return backendinterface.ErrIllegalState
	}
	for _, p := range mustInventory(inc.sup) {
		syscall.Kill(p.PID, syscall.SIGSTOP)
	}
	inc.paused = true
	return nil
}

// Resume SIGCONTs every owned stopped process.
func (b *Backend) Resume(h backendinterface.Handle) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, err := b.get(h)
	if err != nil {
		return err
	}
	if !inc.paused {
		return backendinterface.ErrIllegalState
	}
	for _, p := range mustInventory(inc.sup) {
		syscall.Kill(p.PID, syscall.SIGCONT)
	}
	inc.paused = false
	return nil
}

// Snapshot records the STOP/CONT checkpoint: the paused process inventory
// plus the workspace view. No memory image is captured — RAM state is the
// still-resident stopped processes themselves.
func (b *Backend) Snapshot(h backendinterface.Handle) (backendinterface.CheckpointData, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, err := b.get(h)
	if err != nil {
		return backendinterface.CheckpointData{}, err
	}
	if !inc.paused {
		return backendinterface.CheckpointData{}, backendinterface.ErrIllegalState
	}
	inv := mustInventory(inc.sup)
	pids := make([]string, 0, len(inv))
	for _, p := range inv {
		pids = append(pids, strconv.Itoa(p.PID))
	}
	files, err := readWorkspaceFiles(inc.wsDir)
	if err != nil {
		return backendinterface.CheckpointData{}, err
	}
	return backendinterface.CheckpointData{
		IncarnationID: h.IncarnationID,
		Files:         files,
		Metadata: map[string]string{
			"class": "stop_cont",
			"pids":  strings.Join(pids, ","),
		},
	}, nil
}

// Restore validates a STOP/CONT checkpoint: continuity is guaranteed only
// when every checkpointed PID is still alive and still owned by this
// incarnation (INV-009); otherwise it fails and the caller falls back to
// workspace-only recovery. On success the stopped processes are SIGCONTed
// and the same incarnation continues.
func (b *Backend) Restore(cp backendinterface.CheckpointData) (backendinterface.Handle, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.CorruptCheckpoint {
		return backendinterface.Handle{}, fmt.Errorf("checkpoint metadata corrupt or incompatible")
	}
	if cp.Metadata["class"] != "stop_cont" {
		return backendinterface.Handle{}, fmt.Errorf("unsupported checkpoint class %q", cp.Metadata["class"])
	}
	inc, err := b.get(backendinterface.Handle{IncarnationID: cp.IncarnationID})
	if err != nil {
		return backendinterface.Handle{}, err
	}
	if inc.dead {
		return backendinterface.Handle{}, fmt.Errorf("incarnation terminated while checkpointed")
	}
	marker := incarnationEnvMarker + cp.IncarnationID
	for _, pidStr := range strings.Split(cp.Metadata["pids"], ",") {
		if pidStr == "" {
			continue
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return backendinterface.Handle{}, fmt.Errorf("corrupt pid entry %q", pidStr)
		}
		environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil || !hasEnvEntry(string(environ), marker) {
			return backendinterface.Handle{}, fmt.Errorf("checkpointed pid %d no longer alive and owned", pid)
		}
	}
	for _, p := range mustInventory(inc.sup) {
		syscall.Kill(p.PID, syscall.SIGCONT)
	}
	inc.paused = false
	return backendinterface.Handle{IncarnationID: cp.IncarnationID}, nil
}

// Terminate kills every process owned by the incarnation (process groups and
// daemonized descendants alike) and removes its working directory.
func (b *Backend) Terminate(h backendinterface.Handle) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, ok := b.incs[h.IncarnationID]
	if !ok {
		return nil
	}
	b.killProcesses(inc)
	inc.dead = true
	os.RemoveAll(filepath.Join(b.root, inc.id))
	return nil
}

// markerOwned re-verifies, immediately before a kill, that pid still carries
// the incarnation marker — closing the PID-reuse window between the
// inventory scan and the SIGKILL.
func markerOwned(marker string, pid int) bool {
	environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	return err == nil && hasEnvEntry(string(environ), marker)
}

func (b *Backend) killProcesses(inc *incarnation) {
	marker := inc.sup.marker
	for _, p := range mustInventory(inc.sup) {
		if markerOwned(marker, p.PID) {
			syscall.Kill(p.PID, syscall.SIGKILL)
		}
	}
	inc.sup.mu.Lock()
	for _, t := range inc.sup.execs {
		if t.cmd.Process != nil && markerOwned(marker, t.cmd.Process.Pid) {
			syscall.Kill(-t.cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	inc.sup.mu.Unlock()
}

func mustInventory(s *localSupervisor) []supervisor.ProcessInfo {
	inv, err := s.ProcessInventory()
	if err != nil {
		return nil
	}
	return inv
}

// Stats reports host-side usage: live CPU/RSS from /proc plus finished-exec
// rusage accumulated by the supervisor (INV-016).
func (b *Backend) Stats(h backendinterface.Handle) (backendinterface.Stats, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, err := b.get(h)
	if err != nil {
		return backendinterface.Stats{}, err
	}
	inv := mustInventory(inc.sup)
	cpu, rss := hostUsage(inv)
	inc.sup.mu.Lock()
	cpu += inc.sup.finishedCPU
	inc.sup.mu.Unlock()
	return backendinterface.Stats{CPUSeconds: cpu, MemoryBytes: rss, ProcessCount: len(inv)}, nil
}

// LiveNonBaselineDescendants counts live owned processes excluding baseline
// service process groups (quiescence signal, PLAN §10).
func (b *Backend) LiveNonBaselineDescendants(h backendinterface.Handle) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, err := b.get(h)
	if err != nil {
		return 0
	}
	baseline := inc.sup.baselinePGIDs()
	n := 0
	for _, p := range mustInventory(inc.sup) {
		if !baseline[p.PGID] {
			n++
		}
	}
	return n
}

// TerminateBackground kills every live non-baseline descendant (policy
// enforcement); baseline services and the incarnation survive.
func (b *Backend) TerminateBackground(h backendinterface.Handle) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, err := b.get(h)
	if err != nil {
		return err
	}
	baseline := inc.sup.baselinePGIDs()
	killedPGID := map[int]bool{}
	for _, p := range mustInventory(inc.sup) {
		if baseline[p.PGID] {
			continue
		}
		if !markerOwned(inc.sup.marker, p.PID) {
			continue // PID reused by an unowned process since the scan
		}
		if p.PGID > 0 && !killedPGID[p.PGID] {
			syscall.Kill(-p.PGID, syscall.SIGKILL)
			killedPGID[p.PGID] = true
		}
		syscall.Kill(p.PID, syscall.SIGKILL)
	}
	return nil
}

// Exec applies the operation: scripted Writes are materialized to the
// workspace dir, SpawnBackground maps to real sleep processes, and Command
// runs via the supervisor.
func (b *Backend) Exec(h backendinterface.Handle, executionID string, op domain.Operation) error {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return err
	}
	if !inc.started || inc.paused {
		b.mu.Unlock()
		return backendinterface.ErrIllegalState
	}
	inc.ops[executionID] = op
	if len(op.Writes) > 0 {
		// Record dirtiness under the lock, at op-recording time: a
		// concurrent MarkCommitted must never claim durability for a write
		// that is still in flight (INV-006).
		inc.dirty = true
	}
	b.mu.Unlock()

	for path, content := range op.Writes {
		if err := writeWorkspaceFile(inc.wsDir, path, content); err != nil {
			return err
		}
	}
	if op.Command != "" {
		if err := inc.sup.Exec(supervisor.ExecRequest{ExecutionID: executionID, Command: op.Command, Baseline: op.Baseline, Env: op.Env}); err != nil {
			return err
		}
	}
	for i, bg := range op.SpawnBackground {
		secs := 0.25 * float64(bg.Ticks)
		bgID := fmt.Sprintf("%s#bg-%d-%s", executionID, i, bg.Name)
		if err := inc.sup.Exec(supervisor.ExecRequest{
			ExecutionID: bgID,
			Command:     fmt.Sprintf("sleep %.2f", secs),
			Baseline:    op.Baseline,
		}); err != nil {
			return err
		}
	}
	return nil
}

// WaitExecution blocks until the operation's command exits and returns its
// result; operations without a command complete immediately.
func (b *Backend) WaitExecution(h backendinterface.Handle, executionID string) (supervisor.Result, error) {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return supervisor.Result{}, err
	}
	op, known := inc.ops[executionID]
	b.mu.Unlock()
	if !known {
		return supervisor.Result{}, supervisor.ErrNotFound
	}
	if op.Command == "" {
		return supervisor.Result{ExitCode: op.ExitCode}, nil
	}
	return inc.sup.Wait(executionID)
}

// ProcessInventory exposes the incarnation's live owned processes.
func (b *Backend) ProcessInventory(h backendinterface.Handle) ([]supervisor.ProcessInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, err := b.get(h)
	if err != nil {
		return nil, err
	}
	return inc.sup.ProcessInventory()
}

func (b *Backend) LiveDescendants(h backendinterface.Handle) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, err := b.get(h)
	if err != nil {
		return 0
	}
	return len(mustInventory(inc.sup))
}

// WorkspaceFiles reads the incarnation workspace dir into a manifest.
func (b *Backend) WorkspaceFiles(h backendinterface.Handle) (map[string]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, err := b.get(h)
	if err != nil {
		return nil, err
	}
	return readWorkspaceFiles(inc.wsDir)
}

func readWorkspaceFiles(wsDir string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.Walk(wsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(wsDir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[rel] = string(data)
		return nil
	})
	return out, err
}

func (b *Backend) Dirty(h backendinterface.Handle) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, err := b.get(h)
	if err != nil {
		return false
	}
	return inc.dirty
}

func (b *Backend) MarkCommitted(h backendinterface.Handle) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if inc, err := b.get(h); err == nil {
		inc.dirty = false
	}
}

// KillRuntime simulates a crash: all owned processes die and the working
// directory (uncommitted state) is destroyed.
func (b *Backend) KillRuntime(h backendinterface.Handle) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, ok := b.incs[h.IncarnationID]
	if !ok {
		return
	}
	b.killProcesses(inc)
	inc.dead = true
	os.RemoveAll(filepath.Join(b.root, inc.id))
}

// LiveHandles lists incarnations still present in this backend; a restarted
// host agent adopts them.
func (b *Backend) LiveHandles() []backendinterface.Handle {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []backendinterface.Handle
	for id, inc := range b.incs {
		if !inc.dead {
			out = append(out, backendinterface.Handle{IncarnationID: id})
		}
	}
	return out
}

// LiveSpecs returns the retained create-spec metadata of every live
// incarnation, so a restarted host agent can rebuild ownership and fencing
// state at adoption (INV-016).
func (b *Backend) LiveSpecs() []backendinterface.Spec {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []backendinterface.Spec
	for _, inc := range b.incs {
		if !inc.dead {
			out = append(out, inc.spec)
		}
	}
	return out
}

// Alive reports whether the incarnation still exists in this backend.
func (b *Backend) Alive(h backendinterface.Handle) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, ok := b.incs[h.IncarnationID]
	return ok && !inc.dead
}

// Tick is a no-op: the local backend lives in real time.
func (b *Backend) Tick() {}
