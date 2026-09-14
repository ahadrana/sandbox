// Firecracker backend conformance wiring (ADR-0001 acceptance, INV-026):
// the core contract scenarios in this package run against the firecracker
// VM backend as a third adapter whenever the host offers KVM + artifacts
// (FC_TEST=1); otherwise the firecracker subtests skip with a clear
// message. Firecracker-specific scenarios (snapshot-class checkpoint
// suspend with real RAM reclamation) live here.
package conformance

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

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/domain"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	firecrackerbackend "github.com/agent-sandbox/platform/runtime/firecracker-backend"
)

// firecrackerUnavailable returns "" when the firecracker backend can run
// here, else the reason (used as the skip message).
func firecrackerUnavailable() string {
	if os.Getenv("FC_TEST") != "1" {
		return "FC_TEST != 1; skipping firecracker conformance adapter"
	}
	if runtime.GOOS != "linux" {
		return "firecracker requires linux"
	}
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Sprintf("/dev/kvm not writable: %v", err)
	}
	f.Close()
	artifacts := fcArtifacts()
	for _, p := range []string{filepath.Join(artifacts, "vmlinux.bin"), filepath.Join(artifacts, "rootfs.ext4"), fcBin()} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Sprintf("missing %s: %v", p, err)
		}
	}
	return ""
}

func firecrackerAvailable() bool { return firecrackerUnavailable() == "" }

func fcArtifacts() string {
	if a := os.Getenv("FC_ARTIFACTS"); a != "" {
		return a
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "fc-artifacts")
}

func fcBin() string {
	if b := os.Getenv("FC_BIN"); b != "" {
		return b
	}
	return "/usr/local/bin/firecracker"
}

// guestSupervisorBin builds the static in-guest daemon once per run
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
		// Build for the test host's arch; FC_GUEST_GOARCH overrides (FL10).
		goarch := os.Getenv("FC_GUEST_GOARCH")
		if goarch == "" {
			goarch = runtime.GOARCH
		}
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
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

// firecrackerRuntime constructs the VM backend or skips with the reason.
// Networking stays off here: the egress datapath has its own dedicated
// tests in runtime/firecracker-backend (TestEgressPolicy), and the
// conformance scenarios exercise the lifecycle contract, not packet rules.
func firecrackerRuntime(t *testing.T) *firecrackerbackend.Backend {
	t.Helper()
	if reason := firecrackerUnavailable(); reason != "" {
		t.Skip(reason)
	}
	artifacts := fcArtifacts()
	b, err := firecrackerbackend.New(firecrackerbackend.Config{
		Root:               t.TempDir(),
		KernelPath:         filepath.Join(artifacts, "vmlinux.bin"),
		RootfsPath:         filepath.Join(artifacts, "rootfs.ext4"),
		FirecrackerBin:     fcBin(),
		GuestSupervisorBin: buildGuestSupervisor(t),
		BootTimeout:        120 * time.Second,
		DefaultMemMiB:      256,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func fcBackend(t *testing.T, s *system) *firecrackerbackend.Backend {
	t.Helper()
	b, ok := s.rt.(*firecrackerbackend.Backend)
	if !ok {
		t.Skip("firecracker-only test")
	}
	return b
}

// noCheckpointRuntime wraps the firecracker backend declaring no checkpoint
// support: suspend must take the workspace-only path (INV-026 — the manager
// adapts to the declared capability, the backend does not change).
type noCheckpointRuntime struct {
	sandboxmanager.Runtime
}

func (n noCheckpointRuntime) Capabilities() backendinterface.Capabilities {
	c := n.Runtime.Capabilities()
	c.SupportsCheckpoint = false
	c.CheckpointReclaimsMemory = false
	return c
}

// Workspace-only suspend against the firecracker runtime with checkpoint
// capability masked: committed workspace restored, epoch N -> N+1, reset
// event, startup rerun — the same contract the isolated backend satisfies.
func TestFirecrackerWorkspaceOnlySuspendResume(t *testing.T) {
	s := newSystem(t, "firecracker")
	s.rt = noCheckpointRuntime{s.rt}
	s.mgr = sandboxmanager.New(s.clock, s.ids, s.ws, s.rt, s.outbox, s.store, "host-1")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 72)
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version:         api.SchemaVersionV1,
		TenantID:        "tenant-1",
		TaskRef:         "task-fc-wsonly",
		EnvironmentID:   "env-base-1",
		PolicyRef:       "policy-default",
		StartupCommands: []string{"echo run >> startup.log"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, sb.SandboxID)

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command:         "true",
		Writes:          map[string]string{"committed.txt": "data"},
		SpawnBackground: []domain.BackgroundSpec{{Name: "sleeper", Ticks: 200}},
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	consumer := eventservice.NewConsumer()
	suspended := eventsOfType(consumer.Poll(s.outbox), domain.EventSandboxSuspended)
	if len(suspended) != 1 || suspended[0].Payload["mode"] != "workspace_only" {
		t.Fatalf("want workspace_only suspend event: %v", suspended)
	}
	lost, _ := suspended[0].Payload["lost_processes"].([]string)
	if len(lost) == 0 {
		t.Fatal("lost-on-resume process inventory not recorded")
	}

	report, err := s.mgr.Resume(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.PriorEpoch != 1 || report.NewEpoch != 2 {
		t.Fatalf("epoch %d -> %d, want 1 -> 2", report.PriorEpoch, report.NewEpoch)
	}
	fresh := consumer.Poll(s.outbox)
	if got := eventsOfType(fresh, domain.EventExecutionStateReset); len(got) != 1 {
		t.Fatalf("want one ExecutionStateReset: %v", got)
	}
	resumed := eventsOfType(fresh, domain.EventSandboxResumed)
	if len(resumed) != 1 || resumed[0].Payload["continuity"] != "workspace_only" {
		t.Fatalf("want workspace_only resume event: %v", resumed)
	}
	files, err := s.mgr.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if files["committed.txt"] != "data" {
		t.Fatalf("committed workspace not restored: %v", files)
	}
	if got := strings.Count(files["startup.log"], "run"); got != 2 {
		t.Fatalf("startup reruns = %d, want 2 (log %q)", got, files["startup.log"])
	}
}

// Snapshot-class checkpoint suspend (FR-SR-005, firecracker): the full VM
// snapshot is taken to disk and the VMM terminated — RAM is REALLY reclaimed
// (asserted > 0, unlike STOP/CONT's honest 0) — yet resume retains the epoch
// with genuine continuity: the restored VM has the same guest PIDs and keeps
// running where it stopped.
func TestFirecrackerCheckpointSuspendResumeReclaimsRAM(t *testing.T) {
	s := newSystem(t, "firecracker")
	fcb := fcBackend(t, s)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 73)
	sb, _ := d.CreateSandbox("task-fc-checkpoint")
	mustMaterialize(t, d, sb.SandboxID)

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "sleep 60 & echo bg-started",
		Writes:  map[string]string{"committed.txt": "data"},
	}); err != nil {
		t.Fatal(err)
	}
	incID := *mustGetSandbox(t, s, sb.SandboxID).RuntimeIncarnationID
	h := backendinterface.Handle{IncarnationID: incID}
	var invBefore map[int]string
	pollUntil(t, 10*time.Second, "background process visible in guest inventory", func() bool {
		inv, err := fcb.ProcessInventory(h)
		if err != nil || len(inv) == 0 {
			return false
		}
		invBefore = map[int]string{}
		for _, p := range inv {
			invBefore[p.PID] = p.Command
		}
		return true
	})
	ramBefore, err := s.mgr.Usage(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if ramBefore.MemoryBytes <= 0 {
		t.Fatal("VM reports no RAM before suspend")
	}

	if err := s.mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	consumer := eventservice.NewConsumer()
	suspended := eventsOfType(consumer.Poll(s.outbox), domain.EventSandboxSuspended)
	if len(suspended) != 1 || suspended[0].Payload["mode"] != "execution_state" {
		t.Fatalf("want execution_state suspend event: %v", suspended)
	}
	reclaimed, ok := suspended[0].Payload["ram_reclaimed_bytes"].(int64)
	if !ok || reclaimed <= 0 {
		t.Fatalf("snapshot-class suspend must report RAM reclaimed > 0: %v", suspended[0].Payload)
	}
	t.Logf("RAM reclaimed by snapshot suspend: %d bytes (VM RSS was %d)", reclaimed, ramBefore.MemoryBytes)
	if fcb.Alive(h) {
		t.Fatal("VMM still running after reclaiming checkpoint suspend")
	}

	report, err := s.mgr.Resume(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.NewEpoch != report.PriorEpoch {
		t.Fatalf("continuity resume changed epoch %d -> %d", report.PriorEpoch, report.NewEpoch)
	}
	if got := eventsOfType(consumer.Poll(s.outbox), domain.EventExecutionStateReset); len(got) != 0 {
		t.Fatalf("ExecutionStateReset emitted on continuity resume: %v", got)
	}
	// Full-VM snapshot restores every guest process with its original PID:
	// continuity stronger than STOP/CONT can offer.
	var invAfter map[int]string
	pollUntil(t, 15*time.Second, "guest inventory back after restore", func() bool {
		inv, err := fcb.ProcessInventory(h)
		if err != nil || len(inv) == 0 {
			return false
		}
		invAfter = map[int]string{}
		for _, p := range inv {
			invAfter[p.PID] = p.Command
		}
		return true
	})
	if len(invAfter) != len(invBefore) {
		t.Fatalf("guest PID set changed across snapshot resume: %v -> %v", invBefore, invAfter)
	}
	for pid, cmd := range invBefore {
		if invAfter[pid] != cmd {
			t.Fatalf("guest pid %d command changed: %q -> %q", pid, cmd, invAfter[pid])
		}
	}
	// Exec path is live in the restored VM and committed state survived.
	ex, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "cat committed.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if ex.State != domain.ExecutionCompleted {
		t.Fatalf("post-resume exec state = %s", ex.State)
	}
	files, err := s.mgr.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(files["committed.txt"]) != "data" {
		t.Fatalf("committed file wrong after resume: %q", files["committed.txt"])
	}
	if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
}

// Snapshot-class checkpoint suspend must release the sandbox's quota slot
// (FM9): the reclaim-class suspend terminates the VMM and drops the handle,
// so the suspended sandbox no longer counts as live — and resume restores
// continuity from the checkpoint with a freshly registered handle.
func TestFirecrackerCheckpointSuspendReclaimsQuota(t *testing.T) {
	s := newSystem(t, "firecracker")
	fcBackend(t, s)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 74)
	s.mgr.SetQuota(domain.Quota{TenantID: "tenant-1", MaxLiveSandboxes: 1})

	sb1, err := d.CreateSandbox("task-fc-quota-1")
	if err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, sb1.SandboxID)
	if _, err := d.ExecSync(sb1.SandboxID, domain.Operation{
		Command: "true",
		Writes:  map[string]string{"quota.txt": "sb1"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.mgr.Suspend(sb1.SandboxID); err != nil {
		t.Fatal(err)
	}
	consumer := eventservice.NewConsumer()
	suspended := eventsOfType(consumer.Poll(s.outbox), domain.EventSandboxSuspended)
	if len(suspended) != 1 || suspended[0].Payload["mode"] != "execution_state" {
		t.Fatalf("want execution_state (reclaiming) suspend: %v", suspended)
	}

	// The quota slot is reclaimed: a second sandbox materializes where a
	// RAM-retaining suspend would have denied it with QuotaExceeded.
	sb2, err := d.CreateSandbox("task-fc-quota-2")
	if err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, sb2.SandboxID)
	if got := eventsOfType(consumer.Poll(s.outbox), domain.EventQuotaExceeded); len(got) != 0 {
		t.Fatalf("QuotaExceeded emitted after reclaiming suspend: %v", got)
	}

	// Resume re-registers the handle via Restore: continuity retained,
	// workspace intact, and the sandbox is usable again.
	report, err := s.mgr.Resume(sb1.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.NewEpoch != report.PriorEpoch {
		t.Fatalf("continuity resume changed epoch %d -> %d", report.PriorEpoch, report.NewEpoch)
	}
	files, err := s.mgr.RuntimeFiles(sb1.SandboxID)
	if err != nil {
		t.Fatalf("RuntimeFiles after continuity resume: %v", err)
	}
	if files["quota.txt"] != "sb1" {
		t.Fatalf("workspace not intact after quota-reclaim resume: %v", files)
	}
}
