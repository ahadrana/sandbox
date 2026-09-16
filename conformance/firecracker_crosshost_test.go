// Cross-host restore with REAL microVMs (ADR-009, FC_TEST=1): two host
// agents on one node — separate backend roots, separate HTTP servers — with
// the fleet routing over the RPC clients. A checkpoint taken on agent A is
// pulled blob-by-blob by agent B and restored there: guest RAM (a
// background process, an uncommitted tmpfs file) genuinely survives across
// hosts and the execution epoch is preserved. Both backends run jailed:
// jail paths are chroot-relative constants, which is what makes a package
// written under root A restorable under root B (ADR-009 consequences).
package conformance

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/control-plane/scheduler"
	"github.com/agent-sandbox/platform/domain"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	firecrackerbackend "github.com/agent-sandbox/platform/runtime/firecracker-backend"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
	"github.com/agent-sandbox/platform/runtime/host-agent/rpc"
	"github.com/agent-sandbox/platform/workspace"
)

// jailedFCBackend builds a firecracker backend with the jailer forced on,
// skipping when the jailer cannot be used here (raw spawns record absolute
// host paths in the saved VMM state, so a raw package only restores into
// the same root layout — useless for a cross-root test).
func jailedFCBackend(t *testing.T) *firecrackerbackend.Backend {
	t.Helper()
	if reason := firecrackerUnavailable(); reason != "" {
		t.Skip(reason)
	}
	jailer := os.Getenv("FC_JAILER")
	if jailer == "" {
		jailer = "/usr/local/bin/jailer"
	}
	if _, err := os.Stat(jailer); err != nil {
		t.Skipf("jailer binary unavailable: %v", err)
	}
	artifacts := fcArtifacts()
	b, err := firecrackerbackend.New(firecrackerbackend.Config{
		Root:               t.TempDir(),
		KernelPath:         filepath.Join(artifacts, "vmlinux.bin"),
		RootfsPath:         filepath.Join(artifacts, "rootfs.ext4"),
		FirecrackerBin:     fcBin(),
		JailerBin:          jailer,
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

// crossHostAgents wires one jailed backend + host agent + HTTP server + RPC
// client, the two-agent single-node topology of ADR-009.
func crossHostAgents(t *testing.T, hostID string, ws hostagent.WorkspaceStore) (*firecrackerbackend.Backend, *rpc.Client, *httptest.Server) {
	t.Helper()
	b := jailedFCBackend(t)
	agent := hostagent.New(hostID, b, nil, ws, 1<<40, 4, 16)
	srv := httptest.NewServer(rpc.Handler(agent, "tok"))
	t.Cleanup(srv.Close)
	if status := b.JailerStatus(); status != "" {
		t.Skipf("jailer unusable on this host (%s); cross-root restore needs jailed VMMs", status)
	}
	return b, rpc.NewClient(srv.URL, "tok"), srv
}

// viewOverrideHost wraps a host with a doctored heartbeat view (and a
// SourceBaseURL passthrough) so the fleet's origin fast path is skipped
// deterministically: the facts guard no longer matches the origin.
type viewOverrideHost struct {
	hostagent.Host
	view    scheduler.HostView
	baseURL string
}

func (h *viewOverrideHost) View() scheduler.HostView { return h.view }
func (h *viewOverrideHost) SourceBaseURL() string    { return h.baseURL }

func TestFirecrackerCrossHostRestore(t *testing.T) {
	if reason := firecrackerUnavailable(); reason != "" {
		t.Skip(reason)
	}
	clock := domain.NewManualClock(time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	backendA, clientA, _ := crossHostAgents(t, "fc-host-a", ws)
	backendB, clientB, _ := crossHostAgents(t, "fc-host-b", ws)

	outbox := eventservice.NewOutbox()
	fleet := hostagent.NewFleet(clock, nil, ws)
	// The origin's view is doctored so its facts never match the checkpoint
	// guard: placement MUST fail over to fc-host-b, which pulls the package
	// from fc-host-a (still up, serving blobs).
	bogusView := clientA.View()
	bogusView.KernelRelease = "bogus-0.0.0"
	fleet.RegisterHost(&viewOverrideHost{Host: clientA, view: bogusView, baseURL: clientA.BaseURL})
	fleet.RegisterHost(clientB)
	mgr := sandboxmanager.New(clock, ids, ws, fleet, outbox, sandboxmanager.NewMemoryStore(), "cp-1")
	d := agentdriver.New(mgr, "tenant-1", "principal-1", 76)

	sb, _ := d.CreateSandbox("task-fc-crosshost")
	mustMaterialize(t, d, sb.SandboxID)
	// After the first boot, confirm the jailer actually engaged (not a
	// silent raw fallback, which cannot restore across roots).
	if status := backendA.JailerStatus(); status != "" {
		t.Skipf("jailer fell back to raw spawns (%s); cross-root restore needs jailed VMMs", status)
	}
	// RAM markers: a background process and an uncommitted /tmp file.
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "sleep 300 & echo ram-marker > /tmp/ram.txt & echo started",
	}); err != nil {
		t.Fatal(err)
	}
	info, err := mgr.GetSandbox(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	incID := *info.RuntimeIncarnationID
	h := backendinterface.Handle{IncarnationID: incID}
	origin, _, ok := fleet.PlacementOf(incID)
	if !ok || origin != "fc-host-a" {
		t.Fatalf("placement = %q, %v; want fc-host-a", origin, ok)
	}
	pollUntil(t, 15*time.Second, "background sleeper in guest inventory", func() bool {
		inv, err := backendA.ProcessInventory(h)
		if err != nil {
			return false
		}
		for _, p := range inv {
			if strings.Contains(p.Command, "sleep 300") {
				return true
			}
		}
		return false
	})

	if err := mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	if backendA.Alive(h) {
		t.Fatal("VMM still running after reclaiming checkpoint suspend")
	}
	if _, _, ok := fleet.PlacementOf(incID); ok {
		t.Fatal("placement retained after reclaiming suspend")
	}

	// Resume: the origin's doctored facts make it inadmissible, so fc-host-b
	// pulls the snapshot package from fc-host-a and restores there.
	report, err := mgr.Resume(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.NewEpoch != report.PriorEpoch {
		t.Fatalf("cross-host restore changed epoch %d -> %d", report.PriorEpoch, report.NewEpoch)
	}
	hostID, _, ok := fleet.PlacementOf(incID)
	if !ok || hostID != "fc-host-b" {
		t.Fatalf("restored placement = %q, %v; want fc-host-b", hostID, ok)
	}
	if !backendB.Alive(h) {
		t.Fatal("restored VMM not alive on fc-host-b")
	}
	// Guest RAM survived the host-to-host transfer: the sleeper is back and
	// the uncommitted tmpfs file is readable in the restored VM on B.
	pollUntil(t, 15*time.Second, "sleeper back after cross-host restore", func() bool {
		inv, err := backendB.ProcessInventory(h)
		if err != nil {
			return false
		}
		for _, p := range inv {
			if strings.Contains(p.Command, "sleep 300") {
				return true
			}
		}
		return false
	})
	ex, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "cat /tmp/ram.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if ex.State != domain.ExecutionCompleted {
		t.Fatalf("post-restore exec state = %s", ex.State)
	}
	if err := mgr.KillRuntime(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
}

// Origin-DOWN variant: the origin host cannot serve the package, so
// continuity restore is impossible (ADR-009) and the manager falls back to
// workspace-only recovery — epoch bump, ExecutionStateReset, committed
// workspace intact, never a false continuity (INV-009).
func TestFirecrackerCrossHostOriginDownFallback(t *testing.T) {
	if reason := firecrackerUnavailable(); reason != "" {
		t.Skip(reason)
	}
	clock := domain.NewManualClock(time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	_, clientA, srvA := crossHostAgents(t, "fc-host-a", ws)
	_, clientB, _ := crossHostAgents(t, "fc-host-b", ws)

	outbox := eventservice.NewOutbox()
	fleet := hostagent.NewFleet(clock, nil, ws)
	fleet.RegisterHost(clientA)
	fleet.RegisterHost(clientB)
	mgr := sandboxmanager.New(clock, ids, ws, fleet, outbox, sandboxmanager.NewMemoryStore(), "cp-1")
	d := agentdriver.New(mgr, "tenant-1", "principal-1", 77)

	sb, _ := d.CreateSandbox("task-fc-crosshost-down")
	mustMaterialize(t, d, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "true",
		Writes:  map[string]string{"committed.txt": "data"},
	}); err != nil {
		t.Fatal(err)
	}
	info, err := mgr.GetSandbox(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	incID := *info.RuntimeIncarnationID
	if origin, _, ok := fleet.PlacementOf(incID); !ok || origin != "fc-host-a" {
		t.Fatalf("placement = %q, %v; want fc-host-a", origin, ok)
	}
	if err := mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}

	// The origin dies: no package source, no continuity.
	srvA.Close()
	fleet.SimulateHostLoss("fc-host-a")

	report, err := mgr.Resume(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.NewEpoch != report.PriorEpoch+1 {
		t.Fatalf("workspace-only fallback epoch %d -> %d, want +1", report.PriorEpoch, report.NewEpoch)
	}
	consumer := eventservice.NewConsumer()
	if got := eventsOfType(consumer.Poll(outbox), domain.EventExecutionStateReset); len(got) != 1 {
		t.Fatalf("want one ExecutionStateReset on fallback: %v", got)
	}
	files, err := mgr.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if files["committed.txt"] != "data" {
		t.Fatalf("committed workspace not restored on fallback: %v", files)
	}
	if err := mgr.KillRuntime(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
}
