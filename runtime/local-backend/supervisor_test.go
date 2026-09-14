package localbackend

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

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
