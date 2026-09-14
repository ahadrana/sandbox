package localbackend

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	supervisor "github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

// TestMain fails the package if a daemon the backend terminated is still
// present in /proc (teardown failed to reap). Daemons of never-terminated
// incarnations die with this process via Pdeathsig.
func TestMain(m *testing.M) {
	code := m.Run()
	if leaked := LeakedDaemons(); len(leaked) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d unreaped guest-supervisor daemon(s) after tests: pids %v\n", len(leaked), leaked)
		os.Exit(1)
	}
	os.Exit(code)
}

// newTestIncarnation builds a backend with one live incarnation and cleans
// it up (exercising the daemon teardown path) at test end.
func newTestIncarnation(t *testing.T, spec backendinterface.Spec) (*Backend, *incarnation) {
	t.Helper()
	if spec.IncarnationID == "" {
		// Unique marker per test: the inventory scans all of /proc, and a
		// shared marker would pick up other tests' transient processes.
		spec.IncarnationID = "inc-" + strings.NewReplacer("/", "-", "_", "-").Replace(t.Name())
	}
	b, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h, err := b.Create(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Terminate(h) })
	b.mu.Lock()
	inc := b.incs[h.IncarnationID]
	b.mu.Unlock()
	return b, inc
}

// L1: the PID-reuse guard accepts owned processes and rejects unowned ones.
func TestMarkerOwnedGuard(t *testing.T) {
	_, inc := newTestIncarnation(t, backendinterface.Spec{})
	if markerOwned(inc.marker(), os.Getpid()) {
		t.Fatal("unowned process (no marker) accepted by markerOwned")
	}
	if err := inc.sup.Exec(supervisor.ExecRequest{ExecutionID: "ex-mark", Command: "sleep 30"}); err != nil {
		t.Fatal(err)
	}
	inv, err := inc.sup.ProcessInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(inv) == 0 {
		t.Fatal("no owned processes found")
	}
	for _, p := range inv {
		// /proc environ reads are not atomic across execve; a pid scanned
		// mid-exec can read as unowned for a few ms. Retry briefly: a
		// genuinely foreign pid never becomes owned.
		owned := false
		for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if markerOwned(inc.marker(), p.PID) {
				owned = true
				break
			}
		}
		if !owned {
			t.Fatalf("owned pid %d rejected by markerOwned", p.PID)
		}
	}
	if err := inc.sup.Cancel("ex-mark"); err != nil {
		t.Fatal(err)
	}
}

// L2: ReadOutput rejects negative offset/maxBytes instead of panicking, and
// serves valid reads.
func TestReadOutputValidation(t *testing.T) {
	_, inc := newTestIncarnation(t, backendinterface.Spec{})
	if err := inc.sup.Exec(supervisor.ExecRequest{ExecutionID: "ex-out", Command: "echo hello"}); err != nil {
		t.Fatal(err)
	}
	if _, err := inc.sup.Wait("ex-out"); err != nil {
		t.Fatal(err)
	}
	if _, err := inc.sup.ReadOutput("ex-out", false, 0, -1); err == nil {
		t.Fatal("negative maxBytes accepted")
	}
	if _, err := inc.sup.ReadOutput("ex-out", false, -1, 10); err == nil {
		t.Fatal("negative offset accepted")
	}
	if _, err := inc.sup.ReadOutput("ex-out", false, 0, supervisor.MaxChunkBytes+1); !errors.Is(err, supervisor.ErrTooLarge) {
		t.Fatalf("oversized read: err = %v", err)
	}
	chunk, err := inc.sup.ReadOutput("ex-out", false, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	if string(chunk.Data) != "hello\n" || !chunk.EOF {
		t.Fatalf("chunk = %+v", chunk)
	}
}

// L3: per-execution env overrides the incarnation's spec env (last-wins per
// key); spec env is ambient for every execution of the incarnation.
func TestExecEnvOverridesAmbient(t *testing.T) {
	_, inc := newTestIncarnation(t, backendinterface.Spec{
		Env: map[string]string{"OVERRIDE_ME": "spec-value", "EXTRA_ENV_KEY": "extra"},
	})
	if err := inc.sup.Exec(supervisor.ExecRequest{
		ExecutionID: "ex-env",
		Command:     `echo -n "$OVERRIDE_ME,$EXTRA_ENV_KEY" > env-result.txt`,
		Env:         map[string]string{"OVERRIDE_ME": "exec-wins"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := inc.sup.Wait("ex-env"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(inc.wsDir, "env-result.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "exec-wins,extra" {
		t.Fatalf("env = %q, want exec-wins override with spec env preserved", data)
	}
}

// The daemon answers the wire protocol and Terminate reaps it: no live
// process and no zombie may survive teardown.
func TestTerminateReapsDaemon(t *testing.T) {
	b, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h, err := b.Create(backendinterface.Spec{IncarnationID: "inc-reap"})
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	daemon := b.incs[h.IncarnationID].daemon
	b.mu.Unlock()
	if !daemon.Alive() {
		t.Fatal("daemon not alive after Create")
	}
	if err := b.Terminate(h); err != nil {
		t.Fatal(err)
	}
	if daemon.Alive() {
		t.Fatal("daemon still alive after Terminate")
	}
	if _, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", daemon.pgid)); err == nil {
		t.Fatalf("daemon pid %d still present in /proc after Terminate (unreaped)", daemon.pgid)
	}
}

// A fresh backend over a root with a live stray daemon (owner crashed before
// Terminate) sweeps it instead of leaking it.
func TestNewSweepsStrayDaemon(t *testing.T) {
	root := t.TempDir()
	b, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	h, err := b.Create(backendinterface.Spec{IncarnationID: "inc-stray"})
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	stray := b.incs[h.IncarnationID].daemon
	b.incs[h.IncarnationID].dead = true // simulate a crashed owner: forget it
	b.mu.Unlock()
	if !stray.Alive() {
		t.Fatal("daemon not alive")
	}
	if _, err := New(root); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if !stray.Alive() {
			return
		}
	}
	t.Fatal("stray daemon survived backend reconstruction")
}

// markerOwned must stay true for a live owned process even across an execve
// (sh exec'ing its command tail briefly exposes an empty /proc environ —
// the window is inconclusive, not proof of foreign ownership).
func TestMarkerOwnedAcrossExec(t *testing.T) {
	marker := incarnationEnvMarker + "inc-exec-window"
	cmd := exec.Command("/bin/sh", "-c", "exec sleep 30")
	cmd.Env = append(os.Environ(), marker)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	for i := 0; i < 2000; i++ {
		if !markerOwned(marker, cmd.Process.Pid) {
			t.Fatalf("iteration %d: owned pid %d rejected across exec", i, cmd.Process.Pid)
		}
	}
}

// A persistently empty-environ process (zombie) is not owned, and a foreign
// process is not owned — the FL2 protection is unaffected by the retry.
func TestMarkerOwnedNegative(t *testing.T) {
	marker := incarnationEnvMarker + "inc-negative"
	if markerOwned(marker, os.Getpid()) {
		t.Fatal("foreign process accepted by markerOwned")
	}
	// Zombie: started, exited, not yet reaped.
	cmd := exec.Command("/bin/sh", "-c", "true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", cmd.Process.Pid))
		if strings.Contains(string(data), ") Z") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if markerOwned(marker, cmd.Process.Pid) {
		t.Fatal("zombie accepted by markerOwned")
	}
	cmd.Wait()
}
