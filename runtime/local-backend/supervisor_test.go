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

	supervisor "github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

func newTestSupervisor(t *testing.T) *localSupervisor {
	t.Helper()
	root := t.TempDir()
	wsDir := filepath.Join(root, "workspace")
	outDir := filepath.Join(root, "output")
	if err := os.MkdirAll(wsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return newLocalSupervisor(wsDir, outDir, "inc-test", nil)
}

// L1: the PID-reuse guard accepts owned processes and rejects unowned ones.
func TestMarkerOwnedGuard(t *testing.T) {
	s := newTestSupervisor(t)
	if markerOwned(s.marker, os.Getpid()) {
		t.Fatal("unowned process (no marker) accepted by markerOwned")
	}
	if err := s.Exec(supervisor.ExecRequest{ExecutionID: "ex-mark", Command: "sleep 30"}); err != nil {
		t.Fatal(err)
	}
	inv, err := s.ProcessInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(inv) == 0 {
		t.Fatal("no owned processes found")
	}
	for _, p := range inv {
		if !markerOwned(s.marker, p.PID) {
			t.Fatalf("owned pid %d rejected by markerOwned", p.PID)
		}
	}
	if err := s.Cancel("ex-mark"); err != nil {
		t.Fatal(err)
	}
}

// L2: ReadOutput rejects negative offset/maxBytes instead of panicking, and
// serves valid reads.
func TestReadOutputValidation(t *testing.T) {
	s := newTestSupervisor(t)
	if err := s.Exec(supervisor.ExecRequest{ExecutionID: "ex-out", Command: "echo hello"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Wait("ex-out"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadOutput("ex-out", false, 0, -1); err == nil {
		t.Fatal("negative maxBytes accepted")
	}
	if _, err := s.ReadOutput("ex-out", false, -1, 10); err == nil {
		t.Fatal("negative offset accepted")
	}
	if _, err := s.ReadOutput("ex-out", false, 0, supervisor.MaxChunkBytes+1); !errors.Is(err, supervisor.ErrTooLarge) {
		t.Fatalf("oversized read: err = %v", err)
	}
	chunk, err := s.ReadOutput("ex-out", false, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	if string(chunk.Data) != "hello\n" || !chunk.EOF {
		t.Fatalf("chunk = %+v", chunk)
	}
}

// L3: per-execution env overrides ambient env (last-wins per key).
func TestExecEnvOverridesAmbient(t *testing.T) {
	t.Setenv("OVERRIDE_ME", "ambient")
	s := newTestSupervisor(t)
	s.extraEnv = append(s.extraEnv, "EXTRA_ENV_KEY=extra")
	if err := s.Exec(supervisor.ExecRequest{
		ExecutionID: "ex-env",
		Command:     `echo -n "$OVERRIDE_ME,$EXTRA_ENV_KEY" > env-result.txt`,
		Env:         map[string]string{"OVERRIDE_ME": "exec-wins"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Wait("ex-env"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(s.wsDir, "env-result.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "exec-wins,extra" {
		t.Fatalf("env = %q, want exec-wins override with extraEnv preserved", data)
	}
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
