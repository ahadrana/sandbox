//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

// agent mirrors runtime/local-backend/supervisor.go's semantics inside the
// guest: same ownership marker, env last-wins, process-group isolation,
// output spill files, wait4 rusage.
type agent struct {
	workDir  string
	outDir   string
	marker   string
	mu       sync.Mutex
	execs    map[string]*trackedExec
	finished float64 // finished CPU seconds (metering, INV-016)
}

type trackedExec struct {
	cmd       *exec.Cmd
	done      chan struct{}
	result    supervisor.Result
	startedAt time.Time
	baseline  bool
	pgid      int
}

func newAgent(workDir, outDir, incarnationID string) *agent {
	return &agent{
		workDir: workDir,
		outDir:  outDir,
		marker:  "AGENT_SANDBOX_INCARNATION=" + incarnationID,
		execs:   map[string]*trackedExec{},
	}
}

func validateExecutionID(id string) error {
	if id == "" || strings.ContainsAny(id, "/\\\x00") || strings.Contains(id, "..") {
		return fmt.Errorf("invalid execution ID %q", id)
	}
	return nil
}

func (a *agent) Exec(req supervisor.ExecRequest) error {
	if err := validateExecutionID(req.ExecutionID); err != nil {
		return err
	}
	a.mu.Lock()
	if _, dup := a.execs[req.ExecutionID]; dup {
		a.mu.Unlock()
		return nil
	}
	stdoutPath := filepath.Join(a.outDir, req.ExecutionID+".stdout")
	stderrPath := filepath.Join(a.outDir, req.ExecutionID+".stderr")
	stdout, err := os.Create(stdoutPath)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	stderr, err := os.Create(stderrPath)
	if err != nil {
		stdout.Close()
		a.mu.Unlock()
		return err
	}
	// env last-wins per key: ambient, then marker, then per-request.
	envMap := map[string]string{}
	for _, e := range os.Environ() {
		if k, v, ok := strings.Cut(e, "="); ok {
			envMap[k] = v
		}
	}
	k, v, _ := strings.Cut(a.marker, "=")
	envMap[k] = v
	for k, v := range req.Env {
		envMap[k] = v
	}
	env := make([]string, 0, len(envMap))
	for k, v := range envMap {
		env = append(env, k+"="+v)
	}
	cmd := exec.Command("/bin/sh", "-c", req.Command)
	cmd.Dir = a.workDir
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	t := &trackedExec{cmd: cmd, done: make(chan struct{}), baseline: req.Baseline}
	a.execs[req.ExecutionID] = t
	a.mu.Unlock()

	if err := cmd.Start(); err != nil {
		stdout.Close()
		stderr.Close()
		a.mu.Lock()
		delete(a.execs, req.ExecutionID)
		a.mu.Unlock()
		return err
	}
	t.startedAt = time.Now()
	t.pgid = cmd.Process.Pid
	t.result.StdoutRef = "guest://" + stdoutPath
	t.result.StderrRef = "guest://" + stderrPath
	t.result.StartedAt = t.startedAt
	go func() {
		waitErr := cmd.Wait()
		stdout.Close()
		stderr.Close()
		t.result.CompletedAt = time.Now()
		t.result.ExitCode = 0
		if waitErr != nil {
			if exitErr, ok := waitErr.(*exec.ExitError); ok {
				t.result.ExitCode = exitErr.ExitCode()
			} else {
				t.result.ExitCode = -1
			}
		}
		if st := cmd.ProcessState; st != nil {
			t.result.Usage.CPUSeconds = st.UserTime().Seconds() + st.SystemTime().Seconds()
		}
		a.mu.Lock()
		a.finished += t.result.Usage.CPUSeconds
		a.mu.Unlock()
		close(t.done)
	}()
	return nil
}

func (a *agent) get(executionID string) (*trackedExec, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.execs[executionID]
	if !ok {
		return nil, supervisor.ErrNotFound
	}
	return t, nil
}

func (a *agent) Status(executionID string) (supervisor.StatusResponse, error) {
	t, err := a.get(executionID)
	if err != nil {
		return supervisor.StatusResponse{}, err
	}
	select {
	case <-t.done:
		return supervisor.StatusResponse{
			ExecutionID: executionID, Running: false,
			ExitCode: t.result.ExitCode, StartedAt: t.startedAt, CompletedAt: t.result.CompletedAt,
		}, nil
	default:
		return supervisor.StatusResponse{ExecutionID: executionID, Running: true, StartedAt: t.startedAt}, nil
	}
}

func (a *agent) Wait(executionID string) (supervisor.Result, error) {
	t, err := a.get(executionID)
	if err != nil {
		return supervisor.Result{}, err
	}
	<-t.done
	return t.result, nil
}

func (a *agent) Cancel(executionID string) error {
	t, err := a.get(executionID)
	if err != nil {
		return err
	}
	if t.cmd.Process != nil {
		syscall.Kill(-t.cmd.Process.Pid, syscall.SIGKILL)
	}
	return nil
}

func (a *agent) ReadOutput(executionID string, stderr bool, offset int64, maxBytes int) (supervisor.OutputChunk, error) {
	if err := validateExecutionID(executionID); err != nil {
		return supervisor.OutputChunk{}, err
	}
	if maxBytes < 0 || offset < 0 {
		return supervisor.OutputChunk{}, fmt.Errorf("negative offset/maxBytes")
	}
	if maxBytes > supervisor.MaxChunkBytes {
		return supervisor.OutputChunk{}, supervisor.ErrTooLarge
	}
	name := executionID + ".stdout"
	if stderr {
		name = executionID + ".stderr"
	}
	f, err := os.Open(filepath.Join(a.outDir, name))
	if err != nil {
		return supervisor.OutputChunk{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return supervisor.OutputChunk{}, err
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return supervisor.OutputChunk{}, err
	}
	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	eof := offset+int64(n) >= st.Size()
	if t, err := a.get(executionID); err == nil {
		select {
		case <-t.done:
		default:
			eof = false
		}
	}
	return supervisor.OutputChunk{Data: buf[:n], Offset: offset, EOF: eof}, nil
}

// ProcessInventory lists live processes carrying the incarnation marker by
// scanning /proc; this catches background and daemonized descendants.
func (a *agent) ProcessInventory() ([]supervisor.ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []supervisor.ProcessInfo
	for _, e := range entries {
		pid, err := atoi(e.Name())
		if err != nil {
			continue
		}
		environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil || len(environ) == 0 {
			continue
		}
		if !hasEnvEntry(string(environ), a.marker) {
			continue
		}
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		out = append(out, supervisor.ProcessInfo{
			PID:     pid,
			PGID:    readPGID(pid),
			Command: strings.ReplaceAll(strings.TrimRight(string(cmdline), "\x00"), "\x00", " "),
		})
	}
	return out, nil
}

// baselinePGIDs mirrors the local supervisor: baseline execs' process groups
// never block quiescence.
func (a *agent) baselinePGIDs() map[int]bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[int]bool{}
	for _, t := range a.execs {
		if t.baseline && t.pgid > 0 {
			out[t.pgid] = true
		}
	}
	return out
}

func (a *agent) baselinePGIDList() []int {
	set := a.baselinePGIDs()
	out := make([]int, 0, len(set))
	for pgid := range set {
		out = append(out, pgid)
	}
	return out
}

// TerminateBackground kills every live non-baseline descendant (policy
// enforcement); baseline services and the agent survive.
func (a *agent) TerminateBackground() error {
	baseline := a.baselinePGIDs()
	inv, err := a.ProcessInventory()
	if err != nil {
		return err
	}
	killedPGID := map[int]bool{}
	for _, p := range inv {
		if baseline[p.PGID] {
			continue
		}
		if !markerOwned(a.marker, p.PID) {
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

func markerOwned(marker string, pid int) bool {
	environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	return err == nil && hasEnvEntry(string(environ), marker)
}

func hasEnvEntry(environ, entry string) bool {
	for _, e := range strings.Split(environ, "\x00") {
		if e == entry {
			return true
		}
	}
	return false
}

func readPGID(pid int) int {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return -1
	}
	s := string(stat)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return -1
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 3 {
		return -1
	}
	pgid, err := atoi(fields[2])
	if err != nil {
		return -1
	}
	return pgid
}

func atoi(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// checkWorkspacePath rejects absolute and escaping relative paths.
func checkWorkspacePath(path string) error {
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("unsafe workspace path: %q", path)
	}
	return nil
}

// WriteFile materializes a workspace file under the work dir.
func (a *agent) WriteFile(path, content string) error {
	if err := checkWorkspacePath(path); err != nil {
		return err
	}
	full := filepath.Join(a.workDir, filepath.Clean(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	return os.WriteFile(full, []byte(content), 0o644)
}

func (a *agent) ReadFile(path string) ([]byte, error) {
	if err := checkWorkspacePath(path); err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(a.workDir, filepath.Clean(path)))
}

// WorkspaceFiles walks the work dir into a manifest map.
func (a *agent) WorkspaceFiles() (map[string]string, error) {
	out := map[string]string{}
	err := filepath.Walk(a.workDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(a.workDir, path)
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
