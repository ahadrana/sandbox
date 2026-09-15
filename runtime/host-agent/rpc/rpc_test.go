package rpc

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agent-sandbox/platform/domain"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
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
