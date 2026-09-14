package localbackend

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

// This file spawns and reaps the per-incarnation supervisor daemon: the same
// guest-supervisor binary the Firecracker backend runs inside the microVM
// (ADR 004 — one supervisor implementation), here listening on a unix socket
// in the incarnation directory. The backend keeps host-side bookkeeping
// (dirs, manifest, signals, /proc stats); every supervisor operation goes
// over the wire.

const (
	daemonBinEnv      = "LOCAL_BACKEND_DAEMON_BIN"
	daemonDialTimeout = 10 * time.Second
	daemonBootTimeout = 10 * time.Second
)

// daemonProc is a running supervisor daemon plus its reaper.
type daemonProc struct {
	cmd    *exec.Cmd
	pgid   int
	reaped chan struct{} // closed when cmd.Wait returns
}

// Alive reports whether the daemon process is still running (the reaper
// goroutine reaps promptly, so a closed channel means exited).
func (d *daemonProc) Alive() bool {
	select {
	case <-d.reaped:
		return false
	default:
		return true
	}
}

// Kill SIGKILLs the daemon's process group and waits for the reaper.
func (d *daemonProc) Kill() {
	if d.pgid > 0 {
		syscall.Kill(-d.pgid, syscall.SIGKILL)
	}
	select {
	case <-d.reaped:
	case <-time.After(5 * time.Second):
	}
	daemonRegistry.mu.Lock()
	daemonRegistry.killed[d.pgid] = true
	daemonRegistry.mu.Unlock()
}

// spawnDaemon starts the supervisor daemon for one incarnation: scrubbed
// environment plus the incarnation ID, its own process group, cwd at the
// incarnation workspace. The wrapper, when set, rewrites the daemon's
// argv/env (the isolated backend confines the whole daemon under
// bubblewrap).
func spawnDaemon(bin, dir, wsDir, outDir, incarnationID string, specEnv map[string]string, wrapper CommandWrapper) (*daemonProc, error) {
	sock := filepath.Join(dir, "supervisor.sock")
	argv := []string{bin, "-listen", "unix://" + sock, "-workdir", wsDir, "-outdir", outDir}
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"AGENT_SANDBOX_INCARNATION_ID=" + incarnationID,
	}
	for k, v := range specEnv {
		env = append(env, k+"="+v)
	}
	if wrapper != nil {
		argv, env = wrapper(argv, env, wsDir)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = wsDir
	cmd.Env = env
	// Own process group (group-kill at teardown) and Pdeathsig: a daemon
	// must never outlive the backend process itself — the bwrap wrapper
	// carries the equivalent --die-with-parent.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn supervisor daemon: %w", err)
	}
	d := &daemonProc{cmd: cmd, pgid: cmd.Process.Pid, reaped: make(chan struct{})}
	go func() {
		cmd.Wait()
		close(d.reaped)
	}()
	// The pidfile lets a later backend over the same root sweep a daemon
	// whose owner never terminated it (crash between Create and Terminate).
	os.WriteFile(filepath.Join(dir, "supervisor.pid"), []byte(strconv.Itoa(d.pgid)), 0o644)
	registerDaemon(d)
	return d, nil
}

// daemonRegistry tracks every spawned daemon and whether the backend killed
// it, so test suites can assert teardown actually reaps (LeakedDaemons).
var daemonRegistry = struct {
	mu     sync.Mutex
	killed map[int]bool
}{killed: map[int]bool{}}

func registerDaemon(d *daemonProc) {
	daemonRegistry.mu.Lock()
	daemonRegistry.killed[d.pgid] = false
	daemonRegistry.mu.Unlock()
}

// LeakedDaemons returns pids of daemons the backend killed (Terminate/
// KillRuntime/Kill) that are STILL present in /proc — i.e. teardown failed
// to reap. Never-terminated incarnations legitimately have live daemons;
// they die with the backend process (Pdeathsig).
func LeakedDaemons() []int {
	daemonRegistry.mu.Lock()
	defer daemonRegistry.mu.Unlock()
	var out []int
	for pid, killed := range daemonRegistry.killed {
		if !killed {
			continue
		}
		if _, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
			out = append(out, pid)
		}
	}
	return out
}

// dial returns a wire client for the incarnation's daemon socket.
func (d *daemonProc) client(dir string) *supervisor.Client {
	sock := filepath.Join(dir, "supervisor.sock")
	c := supervisor.NewClient(func() (supervisor.Conn, error) {
		conn, err := net.DialTimeout("unix", sock, daemonDialTimeout)
		if err != nil {
			return nil, fmt.Errorf("supervisor dial: %w", err)
		}
		return conn, nil
	}, daemonDialTimeout)
	c.Alive = d.Alive
	return c
}

// waitHealth polls the daemon's Health until it answers or the boot timeout
// elapses.
func waitHealth(c *supervisor.Client) error {
	deadline := time.Now().Add(daemonBootTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := c.Health(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("supervisor daemon did not become healthy: %v", lastErr)
}

// sweepStrayDaemons kills supervisor daemons left under root by a previous
// backend instance (pidfile + cmdline/env identity check, so an unrelated
// process reusing the pid is never signaled).
func sweepStrayDaemons(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, e.Name(), "supervisor.pid"))
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 0 {
			continue
		}
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil || !strings.Contains(string(cmdline), "guest-supervisor") {
			continue
		}
		environ, _ := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if !strings.Contains(string(environ), "AGENT_SANDBOX_INCARNATION_ID=") {
			continue
		}
		syscall.Kill(-pid, syscall.SIGKILL) // daemon pgid == daemon pid
	}
}

var daemonBuild struct {
	once sync.Once
	path string
	err  error
}

// resolveDaemonBin finds the supervisor daemon binary: explicit config, then
// the LOCAL_BACKEND_DAEMON_BIN override, then a build-once-per-process
// `go build` of the daemon package (test/development default).
func resolveDaemonBin(configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	if env := os.Getenv(daemonBinEnv); env != "" {
		return env, nil
	}
	daemonBuild.once.Do(func() {
		dir, err := os.MkdirTemp("", "local-backend-daemon-")
		if err != nil {
			daemonBuild.err = err
			return
		}
		path := filepath.Join(dir, "guest-supervisor")
		cmd := exec.Command("go", "build", "-o", path, "github.com/agent-sandbox/platform/runtime/guest-supervisor/cmd/guest-supervisor")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
		if out, err := cmd.CombinedOutput(); err != nil {
			daemonBuild.err = fmt.Errorf("build guest-supervisor: %v: %s (set %s or WithDaemonBin to a prebuilt binary)", err, out, daemonBinEnv)
			return
		}
		daemonBuild.path = path
	})
	if daemonBuild.err != nil {
		return "", daemonBuild.err
	}
	return daemonBuild.path, nil
}
