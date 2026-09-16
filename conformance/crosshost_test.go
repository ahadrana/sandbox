// Cross-host checkpoint restore (ADR-009): fleet placement failover to a
// guard-matching peer that pulls the snapshot package from the origin host,
// and the KVM-free manifest/blob round-trip between two host agents over
// the host-agent RPC.
package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-sandbox/platform/control-plane/scheduler"
	"github.com/agent-sandbox/platform/domain"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	fakebackend "github.com/agent-sandbox/platform/runtime/fake-backend"
	firecrackerbackend "github.com/agent-sandbox/platform/runtime/firecracker-backend"
	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
	"github.com/agent-sandbox/platform/runtime/host-agent/rpc"
	"github.com/agent-sandbox/platform/workspace"
)

// --- Fleet placement failover (fake backends; transfer scripted) ---

// restoreFromScript records RestoreFrom invocations and delegates to a plain
// Restore (the fake backend holds no package; the transfer itself is covered
// by the HTTP round-trip below and by the FC_TEST two-agent test).
type restoreFromScript struct {
	*hostagent.HostAgent
	calls   int
	lastSrc backendinterface.PackageSource
	err     error
	view    *scheduler.HostView
}

func (s *restoreFromScript) RestoreFrom(cp backendinterface.CheckpointData, src backendinterface.PackageSource) (backendinterface.Handle, error) {
	s.calls++
	s.lastSrc = src
	if s.err != nil {
		return backendinterface.Handle{}, s.err
	}
	return s.HostAgent.Restore(cp)
}

func (s *restoreFromScript) View() scheduler.HostView {
	if s.view != nil {
		return *s.view
	}
	return s.HostAgent.View()
}

func crossHostCheckpoint(origin, memBytes string) backendinterface.CheckpointData {
	return backendinterface.CheckpointData{
		IncarnationID: "inc-x",
		Metadata: map[string]string{
			"origin_host":  origin,
			"sandbox_id":   "sb-x",
			"memory_bytes": memBytes,
		},
	}
}

// The origin host is full: the restore fails over to a guard-matching peer,
// which is handed the ORIGIN host as its package source (ADR-009).
func TestFleetRestoreCrossHostFailover(t *testing.T) {
	clock := domain.NewManualClock(time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	ws := workspace.NewMemory(clock, domain.NewIDGen())
	fleet := hostagent.NewFleet(clock, nil, ws)
	// Origin can hold 64 bytes; the checkpoint needs 1024 — placement on the
	// origin fails on capacity.
	origin := hostagent.New("host-1", fakebackend.New(), nil, ws, 64, 4, 16)
	peer := &restoreFromScript{HostAgent: hostagent.New("host-2", fakebackend.New(), nil, ws, 1<<20, 4, 16)}
	fleet.RegisterHost(origin)
	fleet.RegisterHost(peer)

	cp := crossHostCheckpoint("host-1", "1024")
	h, err := fleet.Restore(cp)
	if err != nil {
		t.Fatal(err)
	}
	if peer.calls != 1 {
		t.Fatalf("peer RestoreFrom calls = %d, want 1", peer.calls)
	}
	srcAgent, ok := peer.lastSrc.(*hostagent.HostAgent)
	if !ok || srcAgent != origin {
		t.Fatalf("RestoreFrom source = %T %v, want the origin host agent", peer.lastSrc, peer.lastSrc)
	}
	hostID, fence, ok := fleet.PlacementOf(h.IncarnationID)
	if !ok || hostID != "host-2" {
		t.Fatalf("placement = %q, %v; want host-2", hostID, ok)
	}
	if fence != 1 {
		t.Fatalf("fence = %d, want 1", fence)
	}
	if got := peer.View().UsedSlots; got != 1 {
		t.Fatalf("peer slots = %d, want 1", got)
	}
	if got := origin.View().UsedSlots; got != 0 {
		t.Fatalf("origin slots = %d, want 0 (never placed)", got)
	}

	// Origin healthy with capacity: the fast path restores there with NO
	// transfer (ADR-008), even though a peer exists.
	origin2 := hostagent.New("host-a", fakebackend.New(), nil, ws, 1<<20, 4, 16)
	peer2 := &restoreFromScript{HostAgent: hostagent.New("host-b", fakebackend.New(), nil, ws, 1<<20, 4, 16)}
	fleet2 := hostagent.NewFleet(clock, nil, ws)
	fleet2.RegisterHost(origin2)
	fleet2.RegisterHost(peer2)
	cp2 := crossHostCheckpoint("host-a", "64")
	h2, err := fleet2.Restore(cp2)
	if err != nil {
		t.Fatal(err)
	}
	if peer2.calls != 0 {
		t.Fatalf("peer involved in an origin-capable restore: %d calls", peer2.calls)
	}
	if hostID, _, _ := fleet2.PlacementOf(h2.IncarnationID); hostID != "host-a" {
		t.Fatalf("origin-preferred placement = %q, want host-a", hostID)
	}
}

// No guard-matching peer (and a mismatched origin): honest typed failure —
// never a placement on a host that could only fail P0.4 validation.
func TestFleetRestoreCrossHostNoMatchingPeer(t *testing.T) {
	clock := domain.NewManualClock(time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	ws := workspace.NewMemory(clock, domain.NewIDGen())
	fleet := hostagent.NewFleet(clock, nil, ws)
	bogus := scheduler.HostView{HostID: "host-1", Healthy: true, CapacityMemory: 1 << 20, CapacitySlots: 4, KernelRelease: "bogus-0.0.0"}
	fleet.RegisterHost(&restoreFromScript{HostAgent: hostagent.New("host-1", fakebackend.New(), nil, ws, 1<<20, 4, 16), view: &bogus})
	bogus2 := bogus
	bogus2.HostID = "host-2"
	fleet.RegisterHost(&restoreFromScript{HostAgent: hostagent.New("host-2", fakebackend.New(), nil, ws, 1<<20, 4, 16), view: &bogus2})

	cp := crossHostCheckpoint("host-1", "64")
	cp.Metadata["kernel_release"] = "real-6.1"
	if _, err := fleet.Restore(cp); !errors.Is(err, supervisor.ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

// A failed transfer on the peer rolls back: pending placement dropped,
// best-effort terminate on the peer, no placement registered — a retry is
// clean (ADR-008 amendment semantics extended over the transfer, ADR-009).
func TestFleetRestoreCrossHostTransferFailureRollback(t *testing.T) {
	clock := domain.NewManualClock(time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	ws := workspace.NewMemory(clock, domain.NewIDGen())
	fleet := hostagent.NewFleet(clock, nil, ws)
	fleet.RegisterHost(hostagent.New("host-1", fakebackend.New(), nil, ws, 64, 4, 16))
	peer := &restoreFromScript{
		HostAgent: hostagent.New("host-2", fakebackend.New(), nil, ws, 1<<20, 4, 16),
		err:       errors.New("connection reset mid-stream"),
	}
	fleet.RegisterHost(peer)

	cp := crossHostCheckpoint("host-1", "1024")
	if _, err := fleet.Restore(cp); err == nil {
		t.Fatal("restore succeeded despite transfer failure")
	}
	if _, _, ok := fleet.PlacementOf(cp.IncarnationID); ok {
		t.Fatal("placement registered after failed transfer")
	}
	if got := peer.View().UsedSlots; got != 0 {
		t.Fatalf("peer slots leaked after rollback: %d", got)
	}
	// Retry succeeds once the transfer works.
	peer.err = nil
	if _, err := fleet.Restore(cp); err != nil {
		t.Fatalf("retry after failed transfer: %v", err)
	}
	if hostID, _, ok := fleet.PlacementOf(cp.IncarnationID); !ok || hostID != "host-2" {
		t.Fatalf("retry placement = %q, %v; want host-2", hostID, ok)
	}
}

// --- KVM-free manifest/blob round-trip over the host-agent RPC ---

// wireSnapshot crafts one full snapshot link dir under a backend root,
// returning the tip name. Facts are empty so nothing host-specific is
// validated (the FC_TEST test covers real packages).
func wireSnapshot(t *testing.T, root, inc string) (tip string, files map[string][]byte) {
	t.Helper()
	tip = "1000000000000000001"
	dir := filepath.Join(root, "snapshots", inc, tip)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	files = map[string][]byte{
		"mem.file":      bytes.Repeat([]byte{0x5A}, 64*1024),
		"vm.state":      []byte("vmstate"),
		"rootfs.ext4":   []byte("rootfs"),
		"workspace.img": []byte("workspace"),
	}
	sum := func(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
	meta := map[string]interface{}{
		"created_at":      time.Now(),
		"mem_sha256":      sum(files["mem.file"]),
		"vm_state_sha256": sum(files["vm.state"]),
	}
	metaBytes, _ := json.Marshal(meta)
	files["meta.json"] = metaBytes
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return tip, files
}

// Two host agents on one node (separate roots, separate HTTP servers): the
// destination pulls the package blob-by-blob from the origin over the RPC,
// byte-identical, with token auth and path safety enforced on the wire.
func TestSnapshotTransferHTTPRoundTrip(t *testing.T) {
	newAgent := func(hostID string) (*hostagent.HostAgent, string) {
		root := t.TempDir()
		b, err := firecrackerbackend.New(firecrackerbackend.Config{
			Root:           root,
			KernelPath:     "kernel",
			RootfsPath:     "rootfs",
			FirecrackerBin: "firecracker",
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { b.Close() })
		return hostagent.New(hostID, b, nil, nil, 1<<20, 4, 16), root
	}
	agentA, rootA := newAgent("host-a")
	agentB, rootB := newAgent("host-b")
	srvA := httptest.NewServer(rpc.Handler(agentA, "tok"))
	t.Cleanup(srvA.Close)
	srvB := httptest.NewServer(rpc.Handler(agentB, "tok"))
	t.Cleanup(srvB.Close)
	clientA := rpc.NewClient(srvA.URL, "tok")
	clientB := rpc.NewClient(srvB.URL, "tok")

	tip, files := wireSnapshot(t, rootA, "inc-1")

	// Manifest over the wire, then every blob, byte-identical.
	m, err := clientA.SnapshotPackageManifest("inc-1", tip)
	if err != nil {
		t.Fatal(err)
	}
	if m.Tip != tip || len(m.Files) != 5 {
		t.Fatalf("manifest = tip %q, %d files; want %q, 5", m.Tip, len(m.Files), tip)
	}
	for _, pf := range m.Files {
		rc, err := clientA.FetchPackageFile("inc-1", pf.Rel)
		if err != nil {
			t.Fatalf("fetch %s: %v", pf.Rel, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		want := files[filepath.Base(pf.Rel)]
		if !bytes.Equal(data, want) {
			t.Fatalf("blob %s content mismatch: %d bytes, want %d", pf.Rel, len(data), len(want))
		}
		if pf.SHA256 != fmt.Sprintf("%x", sha256.Sum256(want)) {
			t.Fatalf("blob %s manifest hash mismatch", pf.Rel)
		}
	}

	// Token auth covers the blob endpoint.
	noAuth := rpc.NewClient(srvA.URL, "wrong")
	if _, err := noAuth.FetchPackageFile("inc-1", tip+"/mem.file"); err == nil {
		t.Fatal("blob fetch with bad token succeeded")
	}
	// Traversal is refused on the wire.
	if _, err := clientA.FetchPackageFile("inc-1", "../../etc/passwd"); err == nil {
		t.Fatal("blob fetch with traversal rel succeeded")
	}

	// The destination agent pulls the package from the origin CLIENT (the
	// RPC client is the PackageSource) and installs it under its own root.
	dst := agentB.Backend().(backendinterface.PackageReceiver)
	snapDir, err := dst.ReceiveSnapshotPackage(m, func(rel string) (io.ReadCloser, error) {
		return clientA.FetchPackageFile("inc-1", rel)
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(rootB, "snapshots", "inc-1", tip); snapDir != want {
		t.Fatalf("installed at %q, want %q", snapDir, want)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(snapDir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("installed %s mismatch: %v", name, err)
		}
	}
	_ = clientB
}
