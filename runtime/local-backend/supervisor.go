// Package localbackend is a dev/test RuntimeBackend that runs real OS
// processes on the host with process-group isolation. Each incarnation gets a
// working directory materialized from a committed workspace generation.
package localbackend

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

// incarnationEnvMarker tags every process owned by an incarnation; it
// survives fork/setsid/daemonization and is the ownership boundary for
// inventory and termination (INV-013).
const incarnationEnvMarker = "AGENT_SANDBOX_INCARNATION="

type trackedExec struct {
	cmd       *exec.Cmd
	done      chan struct{}
	result    supervisor.Result
	startedAt time.Time
	baseline  bool
	pgid      int
}

// localSupervisor is the in-process supervisor.API implementation.
type localSupervisor struct {
	wsDir       string
	outDir      string
	marker      string
	wrapper     CommandWrapper
	extraEnv    []string
	mu          sync.Mutex
	execs       map[string]*trackedExec
	finishedCPU float64
}

func newLocalSupervisor(wsDir, outDir, incarnationID string, wrapper CommandWrapper) *localSupervisor {
	return &localSupervisor{
		wsDir:   wsDir,
		outDir:  outDir,
		marker:  incarnationEnvMarker + incarnationID,
		wrapper: wrapper,
		execs:   map[string]*trackedExec{},
	}
}

// validateExecutionID rejects IDs that could escape the output directory
// when joined into a file path (the supervisor is the security boundary;
// execution IDs are caller-controlled).
func validateExecutionID(id string) error {
	if id == "" || strings.ContainsAny(id, "/\\\x00") || strings.Contains(id, "..") {
		return fmt.Errorf("invalid execution ID %q", id)
	}
	return nil
}

func (s *localSupervisor) Exec(req supervisor.ExecRequest) error {
	if err := validateExecutionID(req.ExecutionID); err != nil {
		return err
	}
	s.mu.Lock()
	if _, dup := s.execs[req.ExecutionID]; dup {
		s.mu.Unlock()
		return nil
	}
	stdoutPath := filepath.Join(s.outDir, req.ExecutionID+".stdout")
	stderrPath := filepath.Join(s.outDir, req.ExecutionID+".stderr")
	stdout, err := os.Create(stdoutPath)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	stderr, err := os.Create(stderrPath)
	if err != nil {
		stdout.Close()
		s.mu.Unlock()
		return err
	}
	env := append([]string{}, os.Environ()...)
	env = append(env, s.marker)
	env = append(env, s.extraEnv...)
	for k, v := range req.Env {
		env = append(env, k+"="+v)
	}
	argv := []string{"/bin/sh", "-c", req.Command}
	if s.wrapper != nil {
		argv, env = s.wrapper(argv, env, s.wsDir)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = s.wsDir
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	t := &trackedExec{cmd: cmd, done: make(chan struct{}), baseline: req.Baseline}
	s.execs[req.ExecutionID] = t
	s.mu.Unlock()

	if err := cmd.Start(); err != nil {
		stdout.Close()
		stderr.Close()
		// Do not leak the exec entry: a start failure must leave no
		// permanent waiter and must not consume the execution ID — a retry
		// with the same ID is a fresh attempt.
		s.mu.Lock()
		delete(s.execs, req.ExecutionID)
		s.mu.Unlock()
		return err
	}
	t.startedAt = time.Now()
	t.pgid = cmd.Process.Pid
	t.result.StdoutRef = "file://" + stdoutPath
	t.result.StderrRef = "file://" + stderrPath
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
		s.mu.Lock()
		s.finishedCPU += t.result.Usage.CPUSeconds
		s.mu.Unlock()
		close(t.done)
	}()
	return nil
}

func (s *localSupervisor) get(executionID string) (*trackedExec, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.execs[executionID]
	if !ok {
		return nil, supervisor.ErrNotFound
	}
	return t, nil
}

func (s *localSupervisor) Status(executionID string) (supervisor.StatusResponse, error) {
	t, err := s.get(executionID)
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

func (s *localSupervisor) Wait(executionID string) (supervisor.Result, error) {
	t, err := s.get(executionID)
	if err != nil {
		return supervisor.Result{}, err
	}
	<-t.done
	return t.result, nil
}

func (s *localSupervisor) Cancel(executionID string) error {
	t, err := s.get(executionID)
	if err != nil {
		return err
	}
	if t.cmd.Process != nil {
		syscall.Kill(-t.cmd.Process.Pid, syscall.SIGKILL)
	}
	return nil
}

func (s *localSupervisor) ReadOutput(executionID string, stderr bool, offset int64, maxBytes int) (supervisor.OutputChunk, error) {
	if err := validateExecutionID(executionID); err != nil {
		return supervisor.OutputChunk{}, err
	}
	if maxBytes > supervisor.MaxChunkBytes {
		return supervisor.OutputChunk{}, supervisor.ErrTooLarge
	}
	name := executionID + ".stdout"
	if stderr {
		name = executionID + ".stderr"
	}
	f, err := os.Open(filepath.Join(s.outDir, name))
	if err != nil {
		return supervisor.OutputChunk{}, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, 0); err != nil {
		return supervisor.OutputChunk{}, err
	}
	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	st, _ := f.Stat()
	eof := offset+int64(n) >= st.Size()
	if t, err := s.get(executionID); err == nil {
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
func (s *localSupervisor) ProcessInventory() ([]supervisor.ProcessInfo, error) {
	return scanProc(s.marker)
}

// baselinePGIDs returns the process groups of baseline-tagged execs.
func (s *localSupervisor) baselinePGIDs() map[int]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[int]bool{}
	for _, t := range s.execs {
		if t.baseline && t.pgid > 0 {
			out[t.pgid] = true
		}
	}
	return out
}

// hostUsage sums live CPU (utime+stime) and RSS from /proc for the given
// inventory — host-side accounting, never guest self-report (INV-016).
func hostUsage(inv []supervisor.ProcessInfo) (cpuSeconds float64, rssBytes int64) {
	for _, p := range inv {
		if stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.PID)); err == nil {
			str := string(stat)
			if i := strings.LastIndex(str, ")"); i >= 0 {
				fields := strings.Fields(str[i+1:])
				// after comm: state ppid pgrp session tty_nr tpgid flags
				// minflt cminflt majflt cmajflt utime stime
				if len(fields) >= 13 {
					utime, _ := atoi(fields[11])
					stime, _ := atoi(fields[12])
					cpuSeconds += float64(utime+stime) / 100.0
				}
			}
		}
		if status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", p.PID)); err == nil {
			for _, line := range strings.Split(string(status), "\n") {
				if strings.HasPrefix(line, "VmRSS:") {
					var kb int
					fmt.Sscanf(line, "VmRSS: %d kB", &kb)
					rssBytes += int64(kb) * 1024
				}
			}
		}
	}
	return cpuSeconds, rssBytes
}

func (s *localSupervisor) Health() error { return nil }

func scanProc(marker string) ([]supervisor.ProcessInfo, error) {
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
			continue // includes zombies and exited processes
		}
		if !hasEnvEntry(string(environ), marker) {
			continue
		}
		pgid := readPGID(pid)
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		out = append(out, supervisor.ProcessInfo{
			PID:     pid,
			PGID:    pgid,
			Command: strings.ReplaceAll(strings.TrimRight(string(cmdline), "\x00"), "\x00", " "),
		})
	}
	return out, nil
}

// hasEnvEntry reports whether the NUL-separated environ contains the exact
// KEY=VALUE entry.
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
	// after comm: state ppid pgrp
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
