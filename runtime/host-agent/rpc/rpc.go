// Package rpc exposes a hostagent.Host over HTTP/JSON: Handler wraps a host
// (host-agentd), Client implements hostagent.Host against a remote Handler
// (control-planed). The message shapes reuse the domain/api types verbatim
// — this is the initial dev transport (ADR 005): stdlib only, one shared
// token header, no TLS; real AuthN/TLS is the gateway's concern (DESIGN
// §6.1).
package rpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/agent-sandbox/platform/control-plane/scheduler"
	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/runtime/backend-interface"
	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
)

// TokenHeader carries the shared dev token on every request.
const TokenHeader = "X-Sandbox-Token"

// request is the single RPC envelope; only the fields relevant to Op are
// populated.
type request struct {
	Op          string                           `json:"op"`
	Handle      backendinterface.Handle          `json:"handle,omitempty"`
	Create      *hostagent.CreateRequest         `json:"create,omitempty"`
	Checkpoint  *backendinterface.CheckpointData `json:"checkpoint,omitempty"`
	ExecutionID string                           `json:"execution_id,omitempty"`
	Operation   *domain.Operation                `json:"operation,omitempty"`
	GuestPort   int                              `json:"guest_port,omitempty"`
	HostPort    int                              `json:"host_port,omitempty"`
}

// response carries the union of all op results.
type response struct {
	OK           bool                             `json:"ok"`
	Error        string                           `json:"error,omitempty"`
	Handle       backendinterface.Handle          `json:"handle,omitempty"`
	Checkpoint   *backendinterface.CheckpointData `json:"checkpoint,omitempty"`
	Stats        *backendinterface.Stats          `json:"stats,omitempty"`
	Result       *supervisor.Result               `json:"result,omitempty"`
	Int          int                              `json:"int,omitempty"`
	Bool         bool                             `json:"bool,omitempty"`
	Files        map[string]string                `json:"files,omitempty"`
	Processes    []supervisor.ProcessInfo         `json:"processes,omitempty"`
	View         *scheduler.HostView              `json:"view,omitempty"`
	Capabilities *backendinterface.Capabilities   `json:"capabilities,omitempty"`
	IDs          []string                         `json:"ids,omitempty"`
	HostID       string                           `json:"host_id,omitempty"`
}

// wireError renders err for the wire, preserving sentinel identity for the
// errors the fleet/scheduler branch on.
func wireError(err error) string {
	switch {
	case errors.Is(err, hostagent.ErrStaleFence):
		return "stale placement fence"
	case errors.Is(err, hostagent.ErrCapacity):
		return "host capacity exceeded"
	case errors.Is(err, backendinterface.ErrNotFound):
		return "not found"
	case errors.Is(err, backendinterface.ErrIllegalState):
		return "illegal state"
	case errors.Is(err, backendinterface.ErrRuntimeGone):
		return "runtime gone"
	case errors.Is(err, supervisor.ErrUnhealthy):
		return "runtime unhealthy"
	case errors.Is(err, supervisor.ErrNotFound):
		return "execution not found"
	}
	return err.Error()
}

// mapError reconstructs sentinel errors from wire strings.
func mapError(msg string) error {
	switch msg {
	case "stale placement fence":
		return hostagent.ErrStaleFence
	case "host capacity exceeded":
		return hostagent.ErrCapacity
	case "not found":
		return backendinterface.ErrNotFound
	case "illegal state":
		return backendinterface.ErrIllegalState
	case "runtime gone":
		return backendinterface.ErrRuntimeGone
	case "runtime unhealthy":
		return supervisor.ErrUnhealthy
	case "execution not found":
		return supervisor.ErrNotFound
	}
	return errors.New(msg)
}

// Handler serves one host over POST /rpc.
func Handler(h hostagent.Host, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/rpc", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if token != "" && r.Header.Get(TokenHeader) != token {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, dispatch(h, req))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func dispatch(h hostagent.Host, req request) (resp response) {
	defer func() {
		if rec := recover(); rec != nil {
			resp = response{Error: fmt.Sprintf("panic: %v", rec)}
		}
	}()
	fail := func(err error) response { return response{Error: wireError(err)} }
	switch req.Op {
	case "host_id":
		return response{OK: true, HostID: h.HostID()}
	case "incarnation_ids":
		return response{OK: true, IDs: h.IncarnationIDs()}
	case "create":
		handle, err := h.Create(*req.Create)
		if err != nil {
			return fail(err)
		}
		return response{OK: true, Handle: handle}
	case "terminate":
		if err := h.Terminate(req.Handle); err != nil {
			return fail(err)
		}
	case "view":
		v := h.View()
		return response{OK: true, View: &v}
	case "tick":
		h.Tick()
	case "capabilities":
		c := h.Capabilities()
		return response{OK: true, Capabilities: &c}
	case "start":
		if err := h.Start(req.Handle); err != nil {
			return fail(err)
		}
	case "pause":
		if err := h.Pause(req.Handle); err != nil {
			return fail(err)
		}
	case "resume":
		if err := h.Resume(req.Handle); err != nil {
			return fail(err)
		}
	case "snapshot":
		cp, err := h.Snapshot(req.Handle)
		if err != nil {
			return fail(err)
		}
		return response{OK: true, Checkpoint: &cp}
	case "restore":
		handle, err := h.Restore(*req.Checkpoint)
		if err != nil {
			return fail(err)
		}
		return response{OK: true, Handle: handle}
	case "publish_port":
		if err := h.PublishPort(req.Handle, req.GuestPort, req.HostPort); err != nil {
			return fail(err)
		}
	case "unpublish_port":
		if err := h.UnpublishPort(req.Handle, req.HostPort); err != nil {
			return fail(err)
		}
	case "stats":
		st, err := h.Stats(req.Handle)
		if err != nil {
			return fail(err)
		}
		return response{OK: true, Stats: &st}
	case "exec":
		if err := h.Exec(req.Handle, req.ExecutionID, *req.Operation); err != nil {
			return fail(err)
		}
	case "wait_execution":
		res, err := h.WaitExecution(req.Handle, req.ExecutionID)
		if err != nil {
			return fail(err)
		}
		return response{OK: true, Result: &res}
	case "live_non_baseline":
		return response{OK: true, Int: h.LiveNonBaselineDescendants(req.Handle)}
	case "process_inventory":
		inv, err := h.ProcessInventory(req.Handle)
		if err != nil {
			return fail(err)
		}
		return response{OK: true, Processes: inv}
	case "terminate_background":
		if err := h.TerminateBackground(req.Handle); err != nil {
			return fail(err)
		}
	case "live_descendants":
		return response{OK: true, Int: h.LiveDescendants(req.Handle)}
	case "workspace_files":
		files, err := h.WorkspaceFiles(req.Handle)
		if err != nil {
			return fail(err)
		}
		return response{OK: true, Files: files}
	case "dirty":
		return response{OK: true, Bool: h.Dirty(req.Handle)}
	case "mark_committed":
		h.MarkCommitted(req.Handle)
	case "kill_runtime":
		h.KillRuntime(req.Handle)
	case "alive":
		return response{OK: true, Bool: h.Alive(req.Handle)}
	default:
		return response{Error: "unknown op " + req.Op}
	}
	return response{OK: true}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// Client implements hostagent.Host against a remote host-agentd.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client // optional; WaitExecution can block, so no default timeout
}

// NewClient returns a Client for baseURL (e.g. "http://10.0.0.5:8080").
func NewClient(baseURL, token string) *Client {
	return &Client{BaseURL: baseURL, Token: token}
}

func (c *Client) call(req request) (response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return response{}, err
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 0}
		// Transport tuned for long-blocking Waits and many short calls.
		hc.Transport = &http.Transport{MaxIdleConnsPerHost: 32}
	}
	httpReq, err := http.NewRequest(http.MethodPost, c.BaseURL+"/rpc", bytes.NewReader(body))
	if err != nil {
		return response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		httpReq.Header.Set(TokenHeader, c.Token)
	}
	httpResp, err := hc.Do(httpReq)
	if err != nil {
		return response{}, fmt.Errorf("host rpc %s: %w", req.Op, err)
	}
	defer httpResp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<30))
	if err != nil {
		return response{}, err
	}
	if httpResp.StatusCode != http.StatusOK {
		return response{}, fmt.Errorf("host rpc %s: %s: %s", req.Op, httpResp.Status, bytes.TrimSpace(data))
	}
	var resp response
	if err := json.Unmarshal(data, &resp); err != nil {
		return response{}, err
	}
	if resp.Error != "" {
		return resp, mapError(resp.Error)
	}
	return resp, nil
}

func (c *Client) HostID() string {
	resp, err := c.call(request{Op: "host_id"})
	if err != nil {
		return ""
	}
	return resp.HostID
}

func (c *Client) IncarnationIDs() []string {
	resp, err := c.call(request{Op: "incarnation_ids"})
	if err != nil {
		return nil
	}
	return resp.IDs
}

func (c *Client) Create(req hostagent.CreateRequest) (backendinterface.Handle, error) {
	resp, err := c.call(request{Op: "create", Create: &req})
	return resp.Handle, err
}

func (c *Client) Terminate(h backendinterface.Handle) error {
	_, err := c.call(request{Op: "terminate", Handle: h})
	return err
}

func (c *Client) View() scheduler.HostView {
	resp, err := c.call(request{Op: "view"})
	if err != nil {
		return scheduler.HostView{}
	}
	return *resp.View
}

func (c *Client) Tick() { c.call(request{Op: "tick"}) }

func (c *Client) Capabilities() backendinterface.Capabilities {
	resp, err := c.call(request{Op: "capabilities"})
	if err != nil {
		return backendinterface.Capabilities{}
	}
	return *resp.Capabilities
}

func (c *Client) Start(h backendinterface.Handle) error {
	_, err := c.call(request{Op: "start", Handle: h})
	return err
}

func (c *Client) Pause(h backendinterface.Handle) error {
	_, err := c.call(request{Op: "pause", Handle: h})
	return err
}

func (c *Client) Resume(h backendinterface.Handle) error {
	_, err := c.call(request{Op: "resume", Handle: h})
	return err
}

func (c *Client) Snapshot(h backendinterface.Handle) (backendinterface.CheckpointData, error) {
	resp, err := c.call(request{Op: "snapshot", Handle: h})
	if err != nil {
		return backendinterface.CheckpointData{}, err
	}
	return *resp.Checkpoint, nil
}

func (c *Client) Restore(cp backendinterface.CheckpointData) (backendinterface.Handle, error) {
	resp, err := c.call(request{Op: "restore", Checkpoint: &cp})
	if err != nil {
		return backendinterface.Handle{}, err
	}
	return resp.Handle, nil
}

func (c *Client) PublishPort(h backendinterface.Handle, guestPort, hostPort int) error {
	_, err := c.call(request{Op: "publish_port", Handle: h, GuestPort: guestPort, HostPort: hostPort})
	return err
}

func (c *Client) UnpublishPort(h backendinterface.Handle, hostPort int) error {
	_, err := c.call(request{Op: "unpublish_port", Handle: h, HostPort: hostPort})
	return err
}

func (c *Client) Stats(h backendinterface.Handle) (backendinterface.Stats, error) {
	resp, err := c.call(request{Op: "stats", Handle: h})
	if err != nil {
		return backendinterface.Stats{}, err
	}
	return *resp.Stats, nil
}

func (c *Client) Exec(h backendinterface.Handle, executionID string, op domain.Operation) error {
	_, err := c.call(request{Op: "exec", Handle: h, ExecutionID: executionID, Operation: &op})
	return err
}

func (c *Client) WaitExecution(h backendinterface.Handle, executionID string) (supervisor.Result, error) {
	resp, err := c.call(request{Op: "wait_execution", Handle: h, ExecutionID: executionID})
	if err != nil {
		return supervisor.Result{}, err
	}
	return *resp.Result, nil
}

func (c *Client) LiveNonBaselineDescendants(h backendinterface.Handle) int {
	resp, err := c.call(request{Op: "live_non_baseline", Handle: h})
	if err != nil {
		return 0
	}
	return resp.Int
}

func (c *Client) ProcessInventory(h backendinterface.Handle) ([]supervisor.ProcessInfo, error) {
	resp, err := c.call(request{Op: "process_inventory", Handle: h})
	return resp.Processes, err
}

func (c *Client) TerminateBackground(h backendinterface.Handle) error {
	_, err := c.call(request{Op: "terminate_background", Handle: h})
	return err
}

func (c *Client) LiveDescendants(h backendinterface.Handle) int {
	resp, err := c.call(request{Op: "live_descendants", Handle: h})
	if err != nil {
		return 0
	}
	return resp.Int
}

func (c *Client) WorkspaceFiles(h backendinterface.Handle) (map[string]string, error) {
	resp, err := c.call(request{Op: "workspace_files", Handle: h})
	return resp.Files, err
}

func (c *Client) Dirty(h backendinterface.Handle) bool {
	resp, err := c.call(request{Op: "dirty", Handle: h})
	if err != nil {
		return false
	}
	return resp.Bool
}

func (c *Client) MarkCommitted(h backendinterface.Handle) {
	c.call(request{Op: "mark_committed", Handle: h})
}

func (c *Client) KillRuntime(h backendinterface.Handle) {
	c.call(request{Op: "kill_runtime", Handle: h})
}

func (c *Client) Alive(h backendinterface.Handle) bool {
	resp, err := c.call(request{Op: "alive", Handle: h})
	if err != nil {
		return false
	}
	return resp.Bool
}

var _ hostagent.Host = (*Client)(nil)

// PostJSON is a small helper for the daemons' own control-plane calls
// (registration/heartbeat, workspace materialize).
func PostJSON(url, token string, in, out interface{}) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set(TokenHeader, token)
	}
	hc := &http.Client{Timeout: 15 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(data))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
