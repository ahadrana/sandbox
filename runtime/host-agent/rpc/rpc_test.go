package rpc

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agent-sandbox/platform/domain"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	fakebackend "github.com/agent-sandbox/platform/runtime/fake-backend"
	supervisor "github.com/agent-sandbox/platform/runtime/guest-supervisor"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
	localbackend "github.com/agent-sandbox/platform/runtime/local-backend"
	"github.com/agent-sandbox/platform/workspace"
)

// Loopback: the Client must faithfully translate the full Host surface —
// calls, results, and sentinel errors — against a real HostAgent.
func TestClientServerRoundTrip(t *testing.T) {
	backend, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clock := domain.NewManualClock(testNow)
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	agent := hostagent.New("host-rpc", backend, nil, ws, 1<<30, 4, 16)
	srv := httptest.NewServer(Handler(agent, "tok"))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	if got := c.HostID(); got != "host-rpc" {
		t.Fatalf("HostID = %q", got)
	}
	if c.Capabilities().IsolationClass != backendinterface.IsolationProcess {
		t.Fatal("capabilities did not round-trip")
	}

	wsID, gen := commitWS(t, ws, map[string]string{"a.txt": "alpha"})
	handle, err := c.Create(hostagent.CreateRequest{
		SandboxID: "sb-1", IncarnationID: "inc-rpc-1", Fence: 1, Epoch: 1,
		WorkspaceID: wsID, WorkspaceGeneration: gen, MemoryBytes: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Fence replay is idempotent; stale fences carry the sentinel.
	if _, err := c.Create(hostagent.CreateRequest{
		SandboxID: "sb-1", IncarnationID: "inc-rpc-2", Fence: 1, Epoch: 1,
		WorkspaceID: wsID, WorkspaceGeneration: gen,
	}); err != nil {
		t.Fatalf("same-fence replay: %v", err)
	}
	if _, err := c.Create(hostagent.CreateRequest{
		SandboxID: "sb-1", IncarnationID: "inc-rpc-3", Fence: 0, Epoch: 1,
		WorkspaceID: wsID, WorkspaceGeneration: gen,
	}); !errors.Is(err, hostagent.ErrStaleFence) {
		t.Fatalf("stale fence: err = %v", err)
	}

	if err := c.Start(handle); err != nil {
		t.Fatal(err)
	}
	if err := c.Exec(handle, "ex-1", domain.Operation{Command: "cat a.txt > b.txt"}); err != nil {
		t.Fatal(err)
	}
	res, err := c.WaitExecution(handle, "ex-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d", res.ExitCode)
	}
	files, err := c.WorkspaceFiles(handle)
	if err != nil {
		t.Fatal(err)
	}
	if files["b.txt"] != "alpha" {
		t.Fatalf("workspace round trip: %v", files)
	}
	st, err := c.Stats(handle)
	if err != nil {
		t.Fatal(err)
	}
	if st.ProcessCount < 0 {
		t.Fatalf("stats = %+v", st)
	}
	if _, err := c.WaitExecution(handle, "ex-nope"); !errors.Is(err, supervisor.ErrNotFound) {
		t.Fatalf("unknown exec: err = %v", err)
	}
	if err := c.Terminate(handle); err != nil {
		t.Fatal(err)
	}
	if c.Alive(handle) {
		t.Fatal("incarnation alive after Terminate")
	}
}

// A bad token is rejected before any dispatch.
func TestTokenRejected(t *testing.T) {
	backend, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	agent := hostagent.New("host-rpc", backend, nil, nil, 1<<30, 4, 16)
	srv := httptest.NewServer(Handler(agent, "tok"))
	defer srv.Close()
	c := NewClient(srv.URL, "wrong")
	if _, err := c.Create(hostagent.CreateRequest{SandboxID: "sb", IncarnationID: "i", Fence: 1}); err == nil {
		t.Fatal("bad token accepted")
	}
}

var testNow = time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

func commitWS(t *testing.T, ws *workspace.Memory, files map[string]string) (string, int64) {
	t.Helper()
	w, err := ws.Create("tenant-1", "")
	if err != nil {
		t.Fatal(err)
	}
	head, err := ws.GetHead(w.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	gen, err := ws.Commit(w.WorkspaceID, head.Generation, files, nil)
	if err != nil {
		t.Fatal(err)
	}
	return w.WorkspaceID, gen.Generation
}

// The restore op round-trips (ADR-008): a live STOP/CONT incarnation
// resumes in place, and a reclaimed incarnation is re-registered on the
// host from the self-describing checkpoint metadata.
func TestRestoreRoundTrip(t *testing.T) {
	backend, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clock := domain.NewManualClock(testNow)
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	agent := hostagent.New("host-rpc", backend, nil, ws, 1<<30, 4, 16)
	srv := httptest.NewServer(Handler(agent, "tok"))
	defer srv.Close()
	c := NewClient(srv.URL, "tok")

	wsID, gen := commitWS(t, ws, map[string]string{"a.txt": "alpha"})
	handle, err := c.Create(hostagent.CreateRequest{
		SandboxID: "sb-1", IncarnationID: "inc-rpc-1", Fence: 1, Epoch: 1,
		WorkspaceID: wsID, WorkspaceGeneration: gen, MemoryBytes: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(handle); err != nil {
		t.Fatal(err)
	}
	if err := c.Pause(handle); err != nil {
		t.Fatal(err)
	}
	cp, err := c.Snapshot(handle)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Metadata["sandbox_id"] != "sb-1" || cp.Metadata["memory_bytes"] != "64" {
		t.Fatalf("checkpoint not self-describing: %v", cp.Metadata)
	}
	restored, err := c.Restore(cp)
	if err != nil {
		t.Fatal(err)
	}
	if restored != handle {
		t.Fatalf("restored handle = %v, want %v", restored, handle)
	}
	if got := c.View().UsedSlots; got != 1 {
		t.Fatalf("slots after in-place restore = %d, want 1", got)
	}
	if err := c.Terminate(handle); err != nil {
		t.Fatal(err)
	}
}

// Reclaim path over the wire: after Terminate the host has forgotten the
// incarnation; Restore must re-register it (capacity, sandbox mapping) so
// subsequent routed calls succeed and a host re-registration does not
// scrub it as an orphan.
func TestRestoreReregistersReclaimedIncarnation(t *testing.T) {
	ws := workspace.NewMemory(domain.NewManualClock(testNow), domain.NewIDGen())
	agent := hostagent.New("host-rpc", fakebackend.New(), nil, ws, 1<<30, 4, 16)
	srv := httptest.NewServer(Handler(agent, "tok"))
	defer srv.Close()
	c := NewClient(srv.URL, "tok")

	wsID2, gen2 := commitWS(t, ws, map[string]string{})
	handle, err := c.Create(hostagent.CreateRequest{
		SandboxID: "sb-1", IncarnationID: "inc-rpc-1", Fence: 1, Epoch: 1, MemoryBytes: 64,
		WorkspaceID: wsID2, WorkspaceGeneration: gen2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(handle); err != nil {
		t.Fatal(err)
	}
	if err := c.Pause(handle); err != nil {
		t.Fatal(err)
	}
	cp, err := c.Snapshot(handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Terminate(handle); err != nil {
		t.Fatal(err)
	}
	if got := c.View().UsedSlots; got != 0 {
		t.Fatalf("slot not reclaimed: %d", got)
	}

	// A stale fence is rejected with the sentinel across the wire.
	md0 := map[string]string{}
	for k, v := range cp.Metadata {
		md0[k] = v
	}
	md0["fence"] = "0"
	stale := cp
	stale.Metadata = md0
	if _, err := c.Restore(stale); !errors.Is(err, hostagent.ErrStaleFence) {
		t.Fatalf("stale-fence restore: err = %v", err)
	}

	// Fresh fence (as the fleet would issue at restore placement).
	md := map[string]string{}
	for k, v := range cp.Metadata {
		md[k] = v
	}
	md["fence"] = "2"
	fresh := cp
	fresh.Metadata = md
	if _, err := c.Restore(fresh); err != nil {
		t.Fatal(err)
	}
	if got := c.View().UsedSlots; got != 1 {
		t.Fatalf("slots after routed restore = %d, want 1", got)
	}
	// The incarnation is known again: routed ops succeed.
	if !c.Alive(handle) {
		t.Fatal("restored incarnation not alive on host")
	}
}

// Publish/unpublish enforce route+fence over the wire (review H2), and a
// port conflict keeps its typed identity across serialization (review L3).
func TestPublishFenceAndConflictRoundTrip(t *testing.T) {
	backend, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ws := workspace.NewMemory(domain.NewManualClock(testNow), domain.NewIDGen())
	agent := hostagent.New("host-rpc", backend, nil, ws, 1<<30, 4, 16)
	agent.ProtectPorts(18080)
	srv := httptest.NewServer(Handler(agent, "tok"))
	defer srv.Close()
	c := NewClient(srv.URL, "tok")

	wsID, gen := commitWS(t, ws, map[string]string{})
	handle, err := c.Create(hostagent.CreateRequest{
		SandboxID: "sb-1", IncarnationID: "inc-pub-1", Fence: 1, Epoch: 1, MemoryBytes: 64,
		WorkspaceID: wsID, WorkspaceGeneration: gen,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Protected port with the RIGHT fence: typed conflict survives the wire.
	if err := c.PublishPort(handle, 9000, 18080, 1); !errors.Is(err, backendinterface.ErrPortConflict) {
		t.Fatalf("protected port over rpc: err = %v, want ErrPortConflict", err)
	}
	// Stale fence and unknown handle are typed too.
	if err := c.PublishPort(handle, 9000, 18081, 2); !errors.Is(err, hostagent.ErrStaleFence) {
		t.Fatalf("stale fence publish over rpc: err = %v", err)
	}
	if err := c.PublishPort(backendinterface.Handle{IncarnationID: "inc-nope"}, 9000, 18081, 1); !errors.Is(err, backendinterface.ErrNotFound) {
		t.Fatalf("unknown handle publish over rpc: err = %v", err)
	}
	if err := c.UnpublishPort(handle, 18081, 2); !errors.Is(err, hostagent.ErrStaleFence) {
		t.Fatalf("stale fence unpublish over rpc: err = %v", err)
	}
	// Right fence: unpublish is a no-op (local backend cannot publish).
	if err := c.UnpublishPort(handle, 18081, 1); err != nil {
		t.Fatalf("unpublish with current fence: %v", err)
	}
}

// Transport timeout plumbing (review M1): PostJSON keeps the sharp 15s
// default; PostJSONWithTimeout carries the caller's deadline, so the resume
// path can wait longer than a slow-but-healthy restore needs while lookups
// stay sharp.
func TestPostJSONTimeoutPlumbing(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()
	// A short caller timeout cuts the slow call off...
	if err := PostJSONWithTimeout(slow.URL, "", 50*time.Millisecond, nil, nil); err == nil {
		t.Fatal("short-timeout call against slow server succeeded")
	}
	// ...and a long one (the resume path's) lets it complete.
	if err := PostJSONWithTimeout(slow.URL, "", 5*time.Second, nil, nil); err != nil {
		t.Fatalf("long-timeout call against slow server: %v", err)
	}
	// The default wrapper still works against a fast server.
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer fast.Close()
	if err := PostJSON(fast.URL, "", nil, nil); err != nil {
		t.Fatalf("default PostJSON: %v", err)
	}
}

// Review L6: a restore request without a checkpoint is a typed bad-request
// error, never a nil-deref panic.
func TestRestoreNilCheckpointRejected(t *testing.T) {
	backend, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	agent := hostagent.New("host-rpc-nil", backend, nil, nil, 1<<30, 4, 16)
	srv := httptest.NewServer(Handler(agent, ""))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/rpc", "application/json", strings.NewReader(`{"op":"restore"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.OK || !strings.Contains(out.Error, "bad request") {
		t.Fatalf("nil-checkpoint restore = %+v, want bad-request error", out)
	}
	if strings.Contains(out.Error, "panic") {
		t.Fatalf("nil-checkpoint restore panicked: %q", out.Error)
	}
}
