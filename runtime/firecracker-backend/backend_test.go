package firecrackerbackend

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/network"
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

// --- Stage 4: networking/egress, jailer, snapshot GC ---

func newNetBackend(t *testing.T) *Backend {
	t.Helper()
	cfg := testConfig(t)
	cfg.GuestSupervisorBin = buildGuestSupervisor(t)
	cfg.Networking = true
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func egressSpec(id string, pol network.EgressPolicy) backendinterface.Spec {
	s := createSpec(id, nil)
	s.Env = map[string]string{"AGENT_SANDBOX_EGRESS": network.Serialize(pol)}
	return s
}

// hostServer serves "ok" on the given tap host IP (must exist already).
func hostServer(t *testing.T, hostIP string) *http.Server {
	t.Helper()
	ln, err := net.Listen("tcp", hostIP+":18080")
	if err != nil {
		t.Fatalf("listen on %s: %v", hostIP, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return srv
}

func curl(t *testing.T, b *Backend, h backendinterface.Handle, id, url string, maxTime int) int {
	t.Helper()
	res := execOp(t, b, h, id, fmt.Sprintf("curl -s --max-time %d -o /dev/null %s", maxTime, url))
	return res.ExitCode
}

func TestEgressPolicy(t *testing.T) {
	b := newNetBackend(t)
	if !b.Capabilities().NetworkIsolated {
		t.Fatal("NetworkIsolated = false with Networking enabled")
	}

	// VM 1: default-allow policy — host service reachable, metadata blocked.
	id1 := "inc-net-allow"
	ns1 := netFor(id1)
	h1, err := b.Create(egressSpec(id1, network.EgressPolicy{DefaultAllow: true}))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h1); err != nil {
		t.Fatalf("Start %s: %v", id1, err)
	}
	hostServer(t, ns1.hostIP)
	if rc := curl(t, b, h1, "n1a", "http://"+ns1.hostIP+":18080/ok", 5); rc != 0 {
		t.Fatalf("default-allow: curl host server exit = %d, want 0", rc)
	}
	if rc := curl(t, b, h1, "n1b", "http://169.254.169.254/", 3); rc == 0 {
		t.Fatal("metadata endpoint reachable under default-allow policy")
	}

	// VM 2: default-allow with the host tap IP denied — host service blocked.
	id2 := "inc-net-deny"
	ns2 := netFor(id2)
	h2, err := b.Create(egressSpec(id2, network.EgressPolicy{DefaultAllow: true, Deny: []string{ns2.hostIP}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h2); err != nil {
		t.Fatalf("Start %s: %v", id2, err)
	}
	hostServer(t, ns2.hostIP)
	if rc := curl(t, b, h2, "n2a", "http://"+ns2.hostIP+":18080/ok", 3); rc == 0 {
		t.Fatal("denied host IP reachable")
	}

	// VM 3: default-deny with only the host tap IP allowed.
	id3 := "inc-net-defdeny"
	ns3 := netFor(id3)
	h3, err := b.Create(egressSpec(id3, network.EgressPolicy{DefaultAllow: false, Allow: []string{ns3.hostIP}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h3); err != nil {
		t.Fatalf("Start %s: %v", id3, err)
	}
	hostServer(t, ns3.hostIP)
	if rc := curl(t, b, h3, "n3a", "http://"+ns3.hostIP+":18080/ok", 5); rc != 0 {
		t.Fatalf("default-deny+allow: curl host server exit = %d, want 0", rc)
	}
	if rc := curl(t, b, h3, "n3b", "http://192.0.2.1/", 3); rc == 0 {
		t.Fatal("non-allowed destination reachable under default-deny policy")
	}

	// Teardown: no TAP devices or egress chains may survive Terminate.
	for _, h := range []backendinterface.Handle{h1, h2, h3} {
		if err := b.Terminate(h); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command("sudo", "-n", "iptables-save").CombinedOutput()
	if err != nil {
		t.Fatalf("iptables-save: %v", err)
	}
	if strings.Contains(string(out), "FC-EGR-") {
		t.Fatalf("egress chains survived Terminate:\n%s", out)
	}
	for _, id := range []string{id1, id2, id3} {
		if err := exec.Command("ip", "link", "show", netFor(id).tap).Run(); err == nil {
			t.Fatalf("tap %s survived Terminate", netFor(id).tap)
		}
	}
}

func TestJailerBoot(t *testing.T) {
	cfg := testConfig(t)
	cfg.GuestSupervisorBin = buildGuestSupervisor(t)
	cfg.JailerBin = os.Getenv("JAILER_BIN")
	if cfg.JailerBin == "" {
		cfg.JailerBin = "/usr/local/bin/jailer"
	}
	cfg.ChrootBase = filepath.Join(t.TempDir(), "jails")
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	if s := b.JailerStatus(); s != "" {
		t.Skipf("jailer not usable on this host: %s", s)
	}
	h, err := b.Create(createSpec("inc-jail", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start (jailed): %v", err)
	}
	if b.JailerStatus() != "" {
		t.Fatalf("jailer fell back to raw spawn: %s", b.JailerStatus())
	}
	b.mu.Lock()
	inc := b.incs["inc-jail"]
	b.mu.Unlock()
	if !inc.jailed {
		t.Fatal("incarnation not marked jailed")
	}
	res := execOp(t, b, h, "j1", "echo jailed-exec")
	if res.ExitCode != 0 {
		t.Fatal("exec in jailed VM failed")
	}

	// Jailed snapshot + restore (bind-mounted snapshot dir).
	cp, err := b.Snapshot(h)
	if err != nil {
		t.Fatalf("Snapshot (jailed): %v", err)
	}
	b.KillRuntime(h)
	h2, err := b.Restore(cp)
	if err != nil {
		t.Fatalf("Restore (jailed): %v", err)
	}
	res = execOp(t, b, h2, "j2", "echo jailed-restored")
	if res.ExitCode != 0 {
		t.Fatal("exec after jailed restore failed")
	}
	if err := b.Terminate(h2); err != nil {
		t.Fatal(err)
	}
	// Jail tree must be gone after Terminate.
	if _, err := os.Stat(filepath.Join(cfg.ChrootBase, "firecracker", "inc-jail")); !os.IsNotExist(err) {
		t.Fatal("jail tree survived Terminate")
	}
}

func TestSnapshotGC(t *testing.T) {
	cfg := testConfig(t)
	cfg.GuestSupervisorBin = buildGuestSupervisor(t)
	cfg.MaxSnapshotsPerIncarnation = 3
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	h, err := b.Create(createSpec("inc-gc", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	var cps []backendinterface.CheckpointData
	for i := 0; i < 4; i++ {
		cp, err := b.Snapshot(h)
		if err != nil {
			t.Fatalf("Snapshot %d: %v", i, err)
		}
		cps = append(cps, cp)
		if err := b.Resume(h); err != nil {
			t.Fatalf("Resume %d: %v", i, err)
		}
	}
	root := b.snapshotDir("inc-gc")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	if len(dirs) != 3 {
		t.Fatalf("retained snapshots = %d, want 3 (%v)", len(dirs), dirs)
	}
	oldestKept := filepath.Join(root, dirs[0])
	if filepath.Base(oldestKept) == filepath.Base(cps[0].Metadata["snapshot_dir"]) {
		t.Fatal("oldest snapshot was not garbage-collected")
	}
	for _, cp := range cps[1:] {
		if _, err := os.Stat(cp.Metadata["snapshot_dir"]); err != nil {
			t.Fatalf("retained snapshot missing: %v", err)
		}
	}

	// The newest retained snapshot must still restore and exec.
	b.KillRuntime(h)
	h2, err := b.Restore(cps[3])
	if err != nil {
		t.Fatalf("Restore newest retained: %v", err)
	}
	defer b.Terminate(h2)
	res := execOp(t, b, h2, "gc1", "echo gc-restore-ok")
	if res.ExitCode != 0 {
		t.Fatal("exec after GC'd restore failed")
	}
}

// --- FH1/FM8/FM13 regression tests (CODE-REVIEW-FC-2026-09-14) ---

// FH1: the shared path rule rejects script metacharacters. Ungated: pure
// host-side validation.
func TestCheckWorkspacePathStrict(t *testing.T) {
	valid := []string{"a.txt", "dir/nested.go", "unicode-é/文件.txt", "dots.../x", "a-b_c.d"}
	for _, p := range valid {
		if err := checkWorkspacePath(p); err != nil {
			t.Fatalf("valid path %q rejected: %v", p, err)
		}
	}
	invalid := []string{
		"x\nrm /tmp/pwn", "x\ry", "x\ty", "with space/name", "back\\slash",
		"ctrl\x01char", "del\x7fchar", "/abs", "../escape", "a/../../b",
	}
	for _, p := range invalid {
		if err := checkWorkspacePath(p); err == nil {
			t.Fatalf("dangerous path %q accepted", p)
		}
	}
}

// FH1: the image builder refuses metacharacter paths before debugfs runs.
func TestBuildWorkspaceImageRejectsMetachars(t *testing.T) {
	img := filepath.Join(t.TempDir(), "ws.img")
	if err := buildWorkspaceImage(img, map[string]string{"x\nrm /tmp/pwn": "x"}); err == nil {
		t.Fatal("newline path accepted by image builder")
	}
	if _, err := os.Stat(img); !os.IsNotExist(err) {
		t.Fatal("image created despite rejected manifest")
	}
	if err := buildWorkspaceImage(img, map[string]string{"with space/f": "x"}); err == nil {
		t.Fatal("space path accepted by image builder")
	}
	// Valid paths still build.
	if err := buildWorkspaceImage(img, map[string]string{"ok/a.txt": "content"}); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
}

// FM8: incarnation IDs are whitelisted before any filesystem/sudo use.
func TestIncarnationIDValidation(t *testing.T) {
	root := t.TempDir()
	b, err := New(Config{Root: root, KernelPath: "k", RootfsPath: "r", FirecrackerBin: "f"})
	if err != nil {
		t.Fatal(err)
	}
	bad := []string{"", "../escape", "a/b", "new\nline", "with space", "..", "a..b", "/abs"}
	for _, id := range bad {
		if _, err := b.Create(createSpec(id, nil)); err == nil {
			t.Fatalf("incarnation ID %q accepted", id)
		}
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if e.Name() != "snapshots" {
			t.Fatalf("directory created for rejected ID: %s", e.Name())
		}
	}
	// Restore validates too.
	_, err = b.Restore(backendinterface.CheckpointData{
		IncarnationID: "../evil",
		Metadata:      map[string]string{"class": snapshotClass, "snapshot_dir": "x"},
	})
	if err == nil {
		t.Fatal("Restore accepted invalid incarnation ID")
	}
}

// FM13: binary file content round-trips byte-identically through the
// supervisor wire (write → WorkspaceFiles → next incarnation's image).
func TestBinaryWorkspaceRoundTrip(t *testing.T) {
	b := newBackend(t)
	var buf []byte
	for i := 0; i < 256; i++ {
		buf = append(buf, byte(i))
	}
	buf = append(buf, 0xff, 0xfe, 0x80, 0x80, 0x00, 0xc0, 0xaf) // invalid UTF-8
	content := string(buf)
	h, err := b.Create(createSpec("inc-bin", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := b.Exec(h, "b1", domain.Operation{Writes: map[string]string{"bin.dat": content}}); err != nil {
		t.Fatal(err)
	}
	files, err := b.WorkspaceFiles(h)
	if err != nil {
		t.Fatal(err)
	}
	if got := files["bin.dat"]; []byte(got) == nil || !bytes.Equal([]byte(got), buf) {
		t.Fatalf("binary content corrupted on the wire: %d bytes, prefix %q", len(got), firstBytes([]byte(got), 16))
	}
	if err := b.Terminate(h); err != nil {
		t.Fatal(err)
	}
	// Commit → rematerialize: the returned manifest becomes the next
	// incarnation's workspace image; content must still be byte-identical.
	h2, err := b.Create(createSpec("inc-bin2", map[string]string{"bin.dat": files["bin.dat"]}))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h2); err != nil {
		t.Fatalf("Start 2: %v", err)
	}
	defer b.Terminate(h2)
	files2, err := b.WorkspaceFiles(h2)
	if err != nil {
		t.Fatal(err)
	}
	if got := files2["bin.dat"]; !bytes.Equal([]byte(got), buf) {
		t.Fatalf("binary content corrupted across rematerialize: %d bytes, prefix %q", len(got), firstBytes([]byte(got), 16))
	}
	// And the guest filesystem itself agrees (independent of the walk).
	res := execOp(t, b, h2, "b2", "wc -c < bin.dat")
	if res.ExitCode != 0 {
		t.Fatal("wc failed")
	}
	chunk, _ := supOf(t, b, "inc-bin2").ReadOutput("b2", false, 0, 1<<10)
	if strings.TrimSpace(string(chunk.Data)) != fmt.Sprint(len(buf)) {
		t.Fatalf("guest file size = %q, want %d", chunk.Data, len(buf))
	}
}

func firstBytes(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// FH1 round-trip: a metacharacter name minted by root inside the guest
// (shell exec bypasses WriteFile validation) is rejected cleanly at the
// next materialization boundary — no debugfs injection, explicit error.
func TestWorkspaceInjectionRoundTrip(t *testing.T) {
	b := newBackend(t)
	h, err := b.Create(createSpec("inc-inj", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(h); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer b.Terminate(h)
	// The direct write path rejects metacharacter names up front.
	if err := b.Exec(h, "i1", domain.Operation{Writes: map[string]string{"x\nrm /tmp/pwn": "x"}}); err == nil {
		t.Fatal("Exec accepted newline filename")
	}
	// Guest root can still create one via the shell; it lands in the walk.
	res := execOp(t, b, h, "i2", "printf pwn > 'evil\nname'")
	if res.ExitCode != 0 {
		t.Fatal("guest shell write failed")
	}
	files, err := b.WorkspaceFiles(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["evil\nname"]; !ok {
		t.Fatalf("poison name missing from walk: %v", files)
	}
	// The materialization boundary (next image build) rejects it cleanly.
	img := filepath.Join(t.TempDir(), "ws.img")
	if err := buildWorkspaceImage(img, files); err == nil {
		t.Fatal("image builder accepted guest-minted poison name")
	}
	if _, err := os.Stat("/tmp/pwn"); !os.IsNotExist(err) {
		t.Fatal("injected debugfs command created /tmp/pwn")
	}
}
