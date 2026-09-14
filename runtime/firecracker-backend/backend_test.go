package firecrackerbackend

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/runtime/backend-interface"
)

// Real-VM tests run only on the KVM host: FC_TEST=1, linux/arm64 (or any
// linux with /dev/kvm writable), firecracker + artifacts present.
func testConfig(t *testing.T) Config {
	t.Helper()
	if os.Getenv("FC_TEST") != "1" {
		t.Skip("FC_TEST != 1; skipping real-microVM test")
	}
	if runtime.GOOS != "linux" {
		t.Skip("firecracker requires linux")
	}
	f, ferr := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if ferr != nil {
		t.Skipf("/dev/kvm not writable: %v", ferr)
	}
	f.Close()
	artifacts := os.Getenv("FC_ARTIFACTS")
	if artifacts == "" {
		home, _ := os.UserHomeDir()
		artifacts = filepath.Join(home, "fc-artifacts")
	}
	bin := os.Getenv("FC_BIN")
	if bin == "" {
		bin = "/usr/local/bin/firecracker"
	}
	for _, p := range []string{filepath.Join(artifacts, "vmlinux.bin"), filepath.Join(artifacts, "rootfs.ext4"), bin} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("missing %s: %v", p, err)
		}
	}
	return Config{
		Root:           t.TempDir(),
		KernelPath:     filepath.Join(artifacts, "vmlinux.bin"),
		RootfsPath:     filepath.Join(artifacts, "rootfs.ext4"),
		FirecrackerBin: bin,
		BootTimeout:    120 * time.Second,
	}
}

// guestSupervisorBin builds the static in-guest daemon once per test run
// (linux/arm64, matching the microVM).
var guestSupervisorBin struct {
	sync.Once
	path string
	err  error
}

func buildGuestSupervisor(t *testing.T) string {
	t.Helper()
	guestSupervisorBin.Do(func() {
		dir, err := os.MkdirTemp("", "fc-gs-build-")
		if err != nil {
			guestSupervisorBin.err = err
			return
		}
		path := filepath.Join(dir, "guest-supervisor")
		cmd := exec.Command("go", "build", "-o", path, "github.com/agent-sandbox/platform/runtime/guest-supervisor/cmd/guest-supervisor")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64")
		if out, err := cmd.CombinedOutput(); err != nil {
			guestSupervisorBin.err = fmt.Errorf("build guest-supervisor: %v: %s", err, out)
			return
		}
		guestSupervisorBin.path = path
	})
	if guestSupervisorBin.err != nil {
		t.Skipf("cannot build guest supervisor: %v", guestSupervisorBin.err)
	}
	return guestSupervisorBin.path
}

func newBackend(t *testing.T) *Backend {
	t.Helper()
	cfg := testConfig(t)
	cfg.GuestSupervisorBin = buildGuestSupervisor(t)
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func createSpec(id string, manifest map[string]string) backendinterface.Spec {
	return backendinterface.Spec{
		SandboxID:         "sb-" + id,
		IncarnationID:     id,
		Epoch:             1,
		MemoryBytes:       256 << 20,
		WorkspaceManifest: manifest,
	}
}

func consoleLog(t *testing.T, b *Backend, id string) string {
	t.Helper()
	b.mu.Lock()
	inc := b.incs[id]
	b.mu.Unlock()
	data, err := os.ReadFile(filepath.Join(inc.dir, "console.log"))
	if err != nil {
		t.Fatalf("read console log: %v", err)
	}
	return string(data)
}

func TestCreateBootTerminate(t *testing.T) {
	b := newBackend(t)
	caps := b.Capabilities()
	if caps.IsolationClass != backendinterface.IsolationVM {
		t.Fatalf("isolation class = %v, want VM", caps.IsolationClass)
	}
	h, err := b.Create(createSpec("inc-boot", nil))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	log := consoleLog(t, b, "inc-boot")
	if !strings.Contains(log, "login:") {
		t.Fatalf("console never reached login prompt; tail:\n%s", tail(log))
	}
	if !b.Alive(h) {
		t.Fatal("Alive = false after boot")
	}
	st, err := b.Stats(h)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.MemoryBytes <= 0 {
		t.Fatalf("Stats.MemoryBytes = %d, want > 0", st.MemoryBytes)
	}
	if err := b.Terminate(h); err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	if b.Alive(h) {
		t.Fatal("Alive = true after Terminate")
	}
	if _, err := os.Stat(filepath.Join(b.cfg.Root, "inc-boot")); !os.IsNotExist(err) {
		t.Fatal("incarnation dir not cleaned after Terminate")
	}
	// Process must really be gone.
	b.mu.Lock()
	inc := b.incs["inc-boot"]
	b.mu.Unlock()
	select {
	case <-inc.exited:
	default:
		t.Fatal("firecracker process still running after Terminate")
	}
}

func TestPauseResume(t *testing.T) {
	b := newBackend(t)
	h, err := b.Create(createSpec("inc-pause", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := b.Pause(h); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	// Firecracker has no GET /vm state endpoint; Pause/Resume succeeding on
	// the API is the state assertion, and the API must stay responsive.
	if err := b.api(b.incs["inc-pause"]).ping(); err != nil {
		t.Fatalf("ping while paused: %v", err)
	}
	if err := b.Resume(h); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if err := b.api(b.incs["inc-pause"]).ping(); err != nil {
		t.Fatalf("ping after resume: %v", err)
	}
	if err := b.Terminate(h); err != nil {
		t.Fatalf("Terminate: %v", err)
	}
}

func TestSnapshotRestore(t *testing.T) {
	b := newBackend(t)
	h, err := b.Create(createSpec("inc-snap", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	before := consoleLog(t, b, "inc-snap")
	cp, err := b.Snapshot(h)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// Crash the source VM; the snapshot must survive (committed state).
	b.KillRuntime(h)
	if b.Alive(h) {
		t.Fatal("Alive = true after KillRuntime")
	}
	h2, err := b.Restore(cp)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if h2.IncarnationID != "inc-snap" {
		t.Fatalf("restored handle = %q", h2.IncarnationID)
	}
	if !b.Alive(h2) {
		t.Fatal("Alive = false after Restore")
	}
	// Continuity: the snapshot captured memory + vCPU state + both drives
	// while paused; the restored process answers its API and the guest
	// resumes exactly where it was (Firecracker guarantee). The pre-snapshot
	// console showed a completed boot.
	if !strings.Contains(before, "login:") {
		t.Fatal("pre-snapshot console missing login prompt")
	}
	if err := b.api(b.incs["inc-snap"]).ping(); err != nil {
		t.Fatalf("ping after restore: %v", err)
	}
	if err := b.Terminate(h2); err != nil {
		t.Fatalf("Terminate: %v", err)
	}
}

func TestWorkspaceDriveMounted(t *testing.T) {
	b := newBackend(t)
	manifest := map[string]string{
		"hello.txt":      "hello workspace",
		"subdir/note.md": "nested file",
		"deep/a/b/c.txt": "deep nesting",
	}
	h, err := b.Create(createSpec("inc-ws", manifest))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// The injected mount unit prints a marker on the serial console. Wait a
	// little past the login prompt if ordering raced.
	deadline := time.Now().Add(30 * time.Second)
	var log string
	for {
		log = consoleLog(t, b, "inc-ws")
		if strings.Contains(log, "AGENT_WORKSPACE_READY") || strings.Contains(log, "AGENT_WORKSPACE_MISSING") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no workspace marker on console; tail:\n%s", tail(log))
		}
		time.Sleep(500 * time.Millisecond)
	}
	if strings.Contains(log, "AGENT_WORKSPACE_MISSING") {
		t.Fatal("workspace drive /dev/vdb missing in guest")
	}
	files, err := b.WorkspaceFiles(h)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range manifest {
		if files[k] != v {
			t.Fatalf("workspace mirror[%q] = %q, want %q", k, files[k], v)
		}
	}
	if err := b.Terminate(h); err != nil {
		t.Fatal(err)
	}
}

func tail(s string) string {
	if len(s) > 1500 {
		return s[len(s)-1500:]
	}
	return s
}

// execOp runs a command operation end-to-end and returns its result.
func execOp(t *testing.T, b *Backend, h backendinterface.Handle, id, command string) (res supervisorResult) {
	t.Helper()
	op := domain.Operation{Command: command}
	if err := b.Exec(h, id, op); err != nil {
		t.Fatalf("Exec %q: %v", command, err)
	}
	r, err := b.WaitExecution(h, id)
	if err != nil {
		t.Fatalf("WaitExecution %q: %v", command, err)
	}
	return supervisorResult{ExitCode: r.ExitCode}
}

type supervisorResult struct{ ExitCode int }

func supOf(t *testing.T, b *Backend, id string) *vsockSupervisor {
	t.Helper()
	b.mu.Lock()
	inc := b.incs[id]
	b.mu.Unlock()
	sup, err := b.supFor(inc)
	if err != nil {
		t.Fatalf("no supervisor transport: %v", err)
	}
	return sup
}

func TestExecEchoAndExitCode(t *testing.T) {
	b := newBackend(t)
	h, err := b.Create(createSpec("inc-exec", map[string]string{"a.txt": "A"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer b.Terminate(h)

	res := execOp(t, b, h, "e1", "echo hello")
	if res.ExitCode != 0 {
		t.Fatalf("echo exit = %d", res.ExitCode)
	}
	chunk, err := supOf(t, b, "inc-exec").ReadOutput("e1", false, 0, 1<<20)
	if err != nil {
		t.Fatalf("ReadOutput: %v", err)
	}
	if strings.TrimSpace(string(chunk.Data)) != "hello" || !chunk.EOF {
		t.Fatalf("stdout = %q eof=%v", chunk.Data, chunk.EOF)
	}

	res = execOp(t, b, h, "e2", "exit 3")
	if res.ExitCode != 3 {
		t.Fatalf("exit 3 -> %d", res.ExitCode)
	}
}

func TestExecWorkingDirAndEnv(t *testing.T) {
	b := newBackend(t)
	h, err := b.Create(createSpec("inc-cwd", map[string]string{"marker.txt": "here"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer b.Terminate(h)
	// Working dir is /workspace: marker.txt (from the manifest drive) must
	// be directly readable.
	res := execOp(t, b, h, "e1", "cat marker.txt")
	chunk, _ := supOf(t, b, "inc-cwd").ReadOutput("e1", false, 0, 1<<20)
	if res.ExitCode != 0 || strings.TrimSpace(string(chunk.Data)) != "here" {
		t.Fatalf("cwd check: exit=%d out=%q", res.ExitCode, chunk.Data)
	}
	res = execOp(t, b, h, "e2", "test \"$AGENT_SANDBOX_INCARNATION\" = inc-cwd")
	if res.ExitCode != 0 {
		t.Fatal("incarnation marker env missing in guest process")
	}
}

func TestBackgroundInventoryAndTerminate(t *testing.T) {
	b := newBackend(t)
	h, err := b.Create(createSpec("inc-bg", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer b.Terminate(h)

	// Shell exits immediately; the backgrounded child stays owned.
	res := execOp(t, b, h, "bg1", "sleep 30 & echo spawned")
	if res.ExitCode != 0 {
		t.Fatalf("spawn exit = %d", res.ExitCode)
	}
	inv, err := b.ProcessInventory(h)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range inv {
		if strings.Contains(p.Command, "sleep 30") {
			found = true
		}
	}
	if !found {
		t.Fatalf("background sleep not in inventory: %+v", inv)
	}
	if b.LiveDescendants(h) == 0 {
		t.Fatal("LiveDescendants = 0 with live background child")
	}

	// setsid daemon must also be visible (ownership survives setsid).
	execOp(t, b, h, "bg2", "setsid --fork sleep 31 </dev/null >/dev/null 2>&1")
	time.Sleep(300 * time.Millisecond) // let the daemonized child exec
	inv, err = b.ProcessInventory(h)
	if err != nil {
		t.Fatalf("ProcessInventory: %v", err)
	}
	found = false
	for _, p := range inv {
		if strings.Contains(p.Command, "sleep 31") {
			found = true
		}
	}
	if !found {
		t.Fatalf("setsid daemon not in inventory: %+v", inv)
	}

	if err := b.TerminateBackground(h); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		inv, _ = b.ProcessInventory(h)
		if len(inv) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("inventory not drained after TerminateBackground: %+v", inv)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestCancelRunningExec(t *testing.T) {
	b := newBackend(t)
	h, err := b.Create(createSpec("inc-cancel", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer b.Terminate(h)
	if err := b.Exec(h, "c1", domain.Operation{Command: "sleep 60"}); err != nil {
		t.Fatal(err)
	}
	if err := supOf(t, b, "inc-cancel").Cancel("c1"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	r, err := b.WaitExecution(h, "c1")
	if err != nil {
		t.Fatalf("Wait after cancel: %v", err)
	}
	if r.ExitCode == 0 {
		t.Fatal("cancelled sleep exited 0")
	}
}

func TestLargeOutputChunks(t *testing.T) {
	b := newBackend(t)
	h, err := b.Create(createSpec("inc-big", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer b.Terminate(h)
	// ~2 MB of deterministic output.
	res := execOp(t, b, h, "big1", "seq 1 300000")
	if res.ExitCode != 0 {
		t.Fatalf("seq exit = %d", res.ExitCode)
	}
	sup := supOf(t, b, "inc-big")
	var total int64
	var last strings.Builder
	const chunkSize = 64 * 1024
	for {
		chunk, err := sup.ReadOutput("big1", false, total, chunkSize)
		if err != nil {
			t.Fatalf("ReadOutput at %d: %v", total, err)
		}
		total += int64(len(chunk.Data))
		last.Reset()
		last.Write(chunk.Data)
		if chunk.EOF {
			break
		}
		if len(chunk.Data) == 0 {
			t.Fatal("empty non-EOF chunk")
		}
	}
	if total < 1<<20 {
		t.Fatalf("total output = %d, want >= 1MB", total)
	}
	if !strings.Contains(last.String(), "300000") {
		t.Fatal("final chunk missing last seq value")
	}
}

func TestSnapshotRestoreThenExec(t *testing.T) {
	b := newBackend(t)
	h, err := b.Create(createSpec("inc-srex", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	res := execOp(t, b, h, "pre1", "echo before-snapshot")
	if res.ExitCode != 0 {
		t.Fatal("pre-snapshot exec failed")
	}
	cp, err := b.Snapshot(h)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	b.KillRuntime(h)
	h2, err := b.Restore(cp)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	defer b.Terminate(h2)
	// vsock reconnect after restore: exec in the restored VM.
	res = execOp(t, b, h2, "post1", "echo after-restore")
	if res.ExitCode != 0 {
		t.Fatal("post-restore exec failed")
	}
	chunk, err := supOf(t, b, "inc-srex").ReadOutput("post1", false, 0, 1<<20)
	if err != nil || strings.TrimSpace(string(chunk.Data)) != "after-restore" {
		t.Fatalf("post-restore output = %q err=%v", chunk.Data, err)
	}
}

func TestGuestWorkspaceFiles(t *testing.T) {
	b := newBackend(t)
	manifest := map[string]string{"orig.txt": "original"}
	h, err := b.Create(createSpec("inc-gws", manifest))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer b.Terminate(h)
	// Guest-side change visible through WorkspaceFiles (live read).
	res := execOp(t, b, h, "w1", "echo guestmade > created.txt")
	if res.ExitCode != 0 {
		t.Fatal("guest write failed")
	}
	files, err := b.WorkspaceFiles(h)
	if err != nil {
		t.Fatal(err)
	}
	if files["orig.txt"] != "original" {
		t.Fatalf("orig.txt = %q", files["orig.txt"])
	}
	if strings.TrimSpace(files["created.txt"]) != "guestmade" {
		t.Fatalf("created.txt = %q (guest-side write not visible)", files["created.txt"])
	}
	// Host-side write path through Exec lands in the guest filesystem.
	if err := b.Exec(h, "w2", domain.Operation{Writes: map[string]string{"dir/host.txt": "fromhost"}}); err != nil {
		t.Fatal(err)
	}
	res = execOp(t, b, h, "w3", "cat dir/host.txt")
	chunk, _ := supOf(t, b, "inc-gws").ReadOutput("w3", false, 0, 1<<20)
	if res.ExitCode != 0 || strings.TrimSpace(string(chunk.Data)) != "fromhost" {
		t.Fatalf("host write not visible in guest: exit=%d out=%q", res.ExitCode, chunk.Data)
	}
}
