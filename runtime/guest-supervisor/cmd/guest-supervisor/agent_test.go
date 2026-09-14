//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

func testAgent(t *testing.T) *agent {
	t.Helper()
	root := t.TempDir()
	return newAgent(filepath.Join(root, "work"), filepath.Join(root, "out"), "inc-test")
}

// FL1: a symlink planted in the workspace must not redirect file ops
// outside the root, and must not be shipped in the workspace manifest.
func TestWorkspaceSymlinkEscape(t *testing.T) {
	a := testAgent(t)
	if err := os.MkdirAll(a.workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(a.workDir, "evil")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReadFile("evil"); err == nil {
		t.Fatal("ReadFile through symlink succeeded")
	}
	if err := a.WriteFile("evil", []byte("pwned")); err == nil {
		t.Fatal("WriteFile through symlink succeeded")
	}
	files, err := a.WorkspaceFiles()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["evil"]; ok {
		t.Fatal("WorkspaceFiles shipped a symlink target's content")
	}
	// Regular files still work.
	if err := a.WriteFile("ok.txt", []byte("fine")); err != nil {
		t.Fatal(err)
	}
	data, err := a.ReadFile("ok.txt")
	if err != nil || string(data) != "fine" {
		t.Fatalf("regular ReadFile: %q, %v", data, err)
	}
	if files2, _ := a.WorkspaceFiles(); string(files2["ok.txt"]) != "fine" {
		t.Fatalf("WorkspaceFiles missing regular file: %v", files2)
	}
}

// FL2: Cancel group-kills only when the group leader still carries the
// incarnation marker; a real exec's group is killed.
func TestCancelRechecksOwnership(t *testing.T) {
	a := testAgent(t)
	for _, d := range []string{a.workDir, a.outDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Unowned pgid: an entry whose recorded pgid belongs to a process
	// without the marker (ourselves) must not be killed.
	a.mu.Lock()
	a.execs["foreign"] = &trackedExec{done: make(chan struct{}), pgid: os.Getpid()}
	a.mu.Unlock()
	if err := a.Cancel("foreign"); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), 0); err != nil {
		t.Fatal("Cancel killed an unowned process group")
	}

	// Owned exec: Cancel kills the whole process group.
	if err := a.Exec(supervisor.ExecRequest{ExecutionID: "real", Command: "sleep 60 & wait"}); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	pgid := a.execs["real"].pgid
	a.mu.Unlock()
	if pgid <= 0 {
		t.Fatal("pgid not published at Exec return (FM12)")
	}
	if err := a.Cancel("real"); err != nil {
		t.Fatal(err)
	}
	res, err := a.Wait("real")
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode == 0 {
		t.Fatal("canceled exec exited 0")
	}
}

// FL3: a failed cmd.Start records an error result and closes done, so Wait
// returns promptly instead of blocking forever.
func TestFailedStartClosesDone(t *testing.T) {
	a := newAgent(filepath.Join(t.TempDir(), "missing-workdir"), t.TempDir(), "inc-test")
	err := a.Exec(supervisor.ExecRequest{ExecutionID: "bad", Command: "true"})
	if err == nil {
		t.Skip("start unexpectedly succeeded (workdir created?)")
	}
	done := make(chan supervisor.Result, 1)
	go func() {
		res, err := a.Wait("bad")
		if err != nil {
			t.Errorf("Wait: %v", err)
		}
		done <- res
	}()
	select {
	case res := <-done:
		if res.ExitCode != -1 {
			t.Fatalf("exit code = %d, want -1", res.ExitCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait still blocked after failed Start (FL3)")
	}
}

// FM12: startedAt/pgid are published before Exec returns; concurrent
// Status/baselinePGIDs readers observe consistent state (run with -race).
func TestExecFieldsPublishedBeforeReturn(t *testing.T) {
	a := testAgent(t)
	for _, d := range []string{a.workDir, a.outDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Exec(supervisor.ExecRequest{ExecutionID: "bg", Command: "sleep 5", Baseline: true}); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	for i := 0; i < 4; i++ {
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				st, err := a.Status("bg")
				if err == nil && st.StartedAt.IsZero() {
					t.Error("Status observed zero startedAt")
				}
				a.baselinePGIDs()
			}
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		tm := a.execs["bg"]
		ok := tm.startedAt.IsZero() == false && tm.pgid > 0
		a.mu.Unlock()
		if ok && len(a.baselinePGIDs()) == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("startedAt/pgid not visible to readers")
}

// Sanity: TerminateBackground skips baseline groups and kills the rest.
func TestTerminateBackgroundSkipsBaseline(t *testing.T) {
	a := testAgent(t)
	for _, d := range []string{a.workDir, a.outDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Exec(supervisor.ExecRequest{ExecutionID: "svc", Command: "sleep 60", Baseline: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.Exec(supervisor.ExecRequest{ExecutionID: "job", Command: "sleep 60"}); err != nil {
		t.Fatal(err)
	}
	if err := a.TerminateBackground(); err != nil {
		t.Fatal(err)
	}
	res, _ := a.Wait("job")
	if res.ExitCode == 0 {
		t.Fatal("non-baseline exec survived TerminateBackground")
	}
	a.mu.Lock()
	svcPGID := a.execs["svc"].pgid
	a.mu.Unlock()
	if err := syscall.Kill(svcPGID, 0); err != nil {
		t.Fatal("baseline exec killed by TerminateBackground")
	}
	if err := a.Cancel("svc"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Wait("svc"); err != nil && !strings.Contains(err.Error(), "not found") {
		t.Fatal(err)
	}
}
