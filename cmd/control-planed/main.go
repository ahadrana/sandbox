// Command control-planed runs the sandbox control plane (ADR 005): the
// sandbox manager, scheduler, and fleet, tracking REMOTE host agents that
// register/heartbeat over HTTP and routing every fleet call to them via the
// host-agent RPC client. It also serves the public client API (INV-019: no
// Kubernetes objects anywhere in it).
//
// Dev topology: in-memory workspace/store/outbox (single process, state
// lost on restart), shared-token header auth only. AuthN/TLS is the
// gateway's concern (DESIGN §6.1); durable stores are the M3+ work.
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/domain"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
	"github.com/agent-sandbox/platform/runtime/host-agent/rpc"
	"github.com/agent-sandbox/platform/workspace"
)

const (
	heartbeatStaleAfter = 6 * time.Second
	tickInterval        = 1 * time.Second
)

// remoteHost is a registered remote host agent plus liveness bookkeeping.
type remoteHost struct {
	client   *rpc.Client
	url      string
	bootID   string
	lastSeen time.Time
}

type server struct {
	mgr   *sandboxmanager.Manager
	fleet *hostagent.Fleet
	ws    *workspace.Memory
	token string

	mu    sync.Mutex
	hosts map[string]*remoteHost
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	listen := envOr("LISTEN_ADDR", ":8080")
	token := os.Getenv("TOKEN") // shared dev token; empty disables the check
	clock := domain.NewManualClock(time.Now())
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	outbox := eventservice.NewOutbox()
	store := sandboxmanager.NewMemoryStore()
	fleet := hostagent.NewFleet(clock, nil, ws)
	mgr := sandboxmanager.New(clock, ids, ws, fleet, outbox, store, "control-plane-0")
	s := &server{mgr: mgr, fleet: fleet, ws: ws, token: token, hosts: map[string]*remoteHost{}}

	go s.tickLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	// Host-agent internal endpoints.
	mux.HandleFunc("/internal/heartbeat", s.guard(s.heartbeat))
	mux.HandleFunc("/internal/ws-materialize", s.guard(s.wsMaterialize))
	// Public client API (INV-019: sandbox domain objects only).
	mux.HandleFunc("/v1/sandboxes", s.guard(s.sandboxes))
	mux.HandleFunc("/v1/sandboxes/", s.guard(s.sandboxOp))
	mux.HandleFunc("/v1/hosts", s.guard(s.hostViews))

	log.Printf("control-planed listening on %s", listen)
	log.Fatal(http.ListenAndServe(listen, mux))
}

// tickLoop drives heartbeats/loss detection and manager reconciliation in
// real time (the in-process fleet relies on the same tick logic the tests
// drive manually).
func (s *server) tickLoop() {
	for range time.Tick(tickInterval) {
		s.mu.Lock()
		for id, h := range s.hosts {
			if time.Since(h.lastSeen) > heartbeatStaleAfter {
				s.fleet.SimulateHostLoss(id)
			}
		}
		s.mu.Unlock()
		if err := s.mgr.Tick(tickInterval); err != nil {
			log.Printf("tick: %v", err)
		}
	}
}

func (s *server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" && r.Header.Get(rpc.TokenHeader) != s.token {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// heartbeat registers (or refreshes) a remote host agent. First sight of a
// host ID wires an RPC client into the fleet with full placement/fencing;
// later beats only refresh liveness. A changed boot ID means the agent
// process restarted (pod reschedule): re-register through the fleet's
// orphan-scrubbing path so incarnations the new process doesn't know are
// declared lost.
func (s *server) heartbeat(w http.ResponseWriter, r *http.Request) {
	var beat struct {
		HostID string `json:"host_id"`
		URL    string `json:"url"`
		BootID string `json:"boot_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&beat); err != nil || beat.HostID == "" || beat.URL == "" {
		http.Error(w, "host_id and url required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	h, known := s.hosts[beat.HostID]
	reregister := !known || (beat.BootID != "" && h.bootID != "" && beat.BootID != h.bootID)
	if known {
		h.lastSeen = time.Now()
		h.url = beat.URL
		h.client.BaseURL = beat.URL
		if beat.BootID != "" {
			h.bootID = beat.BootID
		}
	}
	s.mu.Unlock()
	if reregister {
		client := rpc.NewClient(beat.URL, s.token)
		s.fleet.RegisterHost(client)
		s.mu.Lock()
		s.hosts[beat.HostID] = &remoteHost{client: client, url: beat.URL, bootID: beat.BootID, lastSeen: time.Now()}
		s.mu.Unlock()
		log.Printf("host registered: %s at %s (boot %s)", beat.HostID, beat.URL, beat.BootID)
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// wsMaterialize serves committed workspace generations to host agents (the
// durable-store stand-in for the host's artifact cache).
func (s *server) wsMaterialize(w http.ResponseWriter, r *http.Request) {
	wsID := r.URL.Query().Get("workspace_id")
	gen, err := strconv.ParseInt(r.URL.Query().Get("generation"), 10, 64)
	if err != nil || wsID == "" {
		http.Error(w, "workspace_id and generation required", http.StatusBadRequest)
		return
	}
	manifest, err := s.ws.Materialize(wsID, gen)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]interface{}{"manifest": manifest})
}

func (s *server) sandboxes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		TaskRef         string   `json:"task_ref"`
		Priority        int      `json:"priority"`
		Class           string   `json:"class"`
		StartupCommands []string `json:"startup_commands"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-dev", TaskRef: req.TaskRef,
		Priority: req.Priority, Class: req.Class, StartupCommands: req.StartupCommands,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, sb)
}

// sandboxOp routes /v1/sandboxes/{id}[/{op}].
func (s *server) sandboxOp(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/sandboxes/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	op := ""
	if len(parts) == 2 {
		op = parts[1]
	}
	switch {
	case op == "" && r.Method == http.MethodGet:
		sb, err := s.mgr.GetSandbox(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, sb)
	case op == "materialize" && r.Method == http.MethodPost:
		rep, err := s.mgr.Materialize(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, rep)
	case op == "exec" && r.Method == http.MethodPost:
		s.execSync(w, r, id)
	case op == "commit" && r.Method == http.MethodPost:
		gen, err := s.mgr.CommitWorkspace(api.CommitWorkspaceRequest{Version: api.SchemaVersionV1, SandboxID: id, TenantID: "tenant-dev"})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, gen)
	case op == "files" && r.Method == http.MethodGet:
		files, err := s.mgr.RuntimeFiles(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]interface{}{"files": files})
	case op == "terminate" && r.Method == http.MethodPost:
		if err := s.mgr.Terminate(id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	default:
		http.Error(w, "unknown sandbox op", http.StatusNotFound)
	}
}

// execSync mirrors the agent driver's synchronous exec: StartExecution then
// CompleteExecution (which blocks on the runtime through the fleet).
func (s *server) execSync(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Command string            `json:"command"`
		Writes  map[string]string `json:"writes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sb, err := s.mgr.GetSandbox(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	ex, err := s.mgr.StartExecution(api.StartExecutionRequest{
		Version: api.SchemaVersionV1, SandboxID: id, TenantID: "tenant-dev", PrincipalID: "principal-dev",
		IdempotencyKey: randKey(),
		Operation:      domain.Operation{Command: req.Command, Writes: req.Writes},
		ExpectedEpoch:  sb.ExecutionEpoch,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if ex.State != domain.ExecutionFailed {
		ex, err = s.mgr.CompleteExecution(ex.ExecutionID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	writeJSON(w, ex)
}

func (s *server) hostViews(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	type hostEntry struct {
		HostID   string      `json:"host_id"`
		URL      string      `json:"url"`
		LastSeen time.Time   `json:"last_seen"`
		View     interface{} `json:"view"`
	}
	out := []hostEntry{}
	for id, h := range s.hosts {
		out = append(out, hostEntry{HostID: id, URL: h.url, LastSeen: h.lastSeen, View: h.client.View()})
	}
	s.mu.Unlock()
	writeJSON(w, map[string]interface{}{"hosts": out, "capabilities": s.fleet.Capabilities()})
}

func randKey() string {
	var b [16]byte
	rand.Read(b[:])
	return fmt.Sprintf("cli-%x", b[:])
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
