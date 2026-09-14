package supervisor

import (
	"fmt"
	"io"
	"time"
)

// Conn is one established supervisor connection, ready for frame exchange.
type Conn interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
}

// DialFunc establishes a fresh connection to a supervisor daemon. One
// connection per call gives natural concurrency (a blocking Wait never
// starves Status) and transparent reconnect.
type DialFunc func() (Conn, error)

// Client is the host-side supervisor.API transport: it dials a supervisor
// daemon and exchanges one framed request/response per connection. The
// transport is supplied by the caller (Firecracker vsock, local unix
// socket); the protocol and semantics are identical either way.
type Client struct {
	dial    DialFunc
	timeout time.Duration
	// Alive reports whether the runtime process hosting the daemon is still
	// running; wired after spawn so a blocked Wait can notice a dead runtime
	// even when the connection never closes on its own.
	Alive func() bool
}

func NewClient(dial DialFunc, timeout time.Duration) *Client {
	return &Client{dial: dial, timeout: timeout}
}

// call performs one request/response round trip on a fresh connection.
// blocking ops (Wait) run without a deadline: the exchange ends when the
// daemon answers or the runtime dies (connection closes).
func (c *Client) call(req Request, blocking bool) (Response, error) {
	conn, err := c.dial()
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if !blocking {
		conn.SetDeadline(time.Now().Add(c.timeout))
	}
	if err := WriteFrame(conn, req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := ReadFrame(conn, &resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

func (c *Client) checked(resp Response, err error) error {
	if err != nil {
		return err
	}
	if !resp.OK {
		return MapError(resp.Error)
	}
	return nil
}

func (c *Client) Exec(req ExecRequest) error {
	resp, err := c.call(Request{
		Op:          OpExec,
		ExecutionID: req.ExecutionID,
		Command:     req.Command,
		Env:         req.Env,
		Baseline:    req.Baseline,
	}, false)
	return c.checked(resp, err)
}

func (c *Client) Status(executionID string) (StatusResponse, error) {
	resp, err := c.call(Request{Op: OpStatus, ExecutionID: executionID}, false)
	if err := c.checked(resp, err); err != nil {
		return StatusResponse{}, err
	}
	return resp.Status, nil
}

// Wait blocks until the daemon reports the execution's result. There is no
// absolute timeout — long-running commands are legitimate — so a liveness
// watchdog bounds the wait instead: every waitWatchdogInterval the runtime
// process liveness and a Health probe on a second connection are checked,
// and after waitWatchdogMaxFailures consecutive failures (or a dead runtime)
// the wait aborts with ErrUnhealthy. Without this a wedged supervisor (still
// holding the connection open but never answering) would block Wait — and
// any caller waiting on it — forever.
const (
	waitWatchdogInterval    = 5 * time.Second
	waitWatchdogMaxFailures = 3
)

func (c *Client) Wait(executionID string) (Result, error) {
	type waitOutcome struct {
		resp Response
		err  error
	}
	done := make(chan waitOutcome, 1)
	go func() {
		resp, err := c.call(Request{Op: OpWait, ExecutionID: executionID}, true)
		done <- waitOutcome{resp, err}
	}()
	ticker := time.NewTicker(waitWatchdogInterval)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case out := <-done:
			if err := c.checked(out.resp, out.err); err != nil {
				return Result{}, err
			}
			return out.resp.Result, nil
		case <-ticker.C:
			if c.Alive != nil && !c.Alive() {
				return Result{}, fmt.Errorf("%w: runtime process gone", ErrUnhealthy)
			}
			if err := c.Health(); err != nil {
				failures++
				if failures >= waitWatchdogMaxFailures {
					return Result{}, fmt.Errorf("%w: supervisor unresponsive after %d probes: %v", ErrUnhealthy, failures, err)
				}
			} else {
				failures = 0
			}
		}
	}
}

func (c *Client) Cancel(executionID string) error {
	resp, err := c.call(Request{Op: OpCancel, ExecutionID: executionID}, false)
	return c.checked(resp, err)
}

func (c *Client) ReadOutput(executionID string, stderr bool, offset int64, maxBytes int) (OutputChunk, error) {
	resp, err := c.call(Request{
		Op: OpReadOutput, ExecutionID: executionID,
		Stderr: stderr, Offset: offset, MaxBytes: maxBytes,
	}, false)
	if err := c.checked(resp, err); err != nil {
		return OutputChunk{}, err
	}
	return OutputChunk{Data: resp.Data, Offset: offset, EOF: resp.EOF}, nil
}

func (c *Client) ProcessInventory() ([]ProcessInfo, error) {
	inv, _, err := c.Inventory()
	return inv, err
}

// Inventory also returns the daemon's baseline process-group set.
func (c *Client) Inventory() ([]ProcessInfo, map[int]bool, error) {
	resp, err := c.call(Request{Op: OpProcessInventory}, false)
	if err := c.checked(resp, err); err != nil {
		return nil, nil, err
	}
	baseline := map[int]bool{}
	for _, pgid := range resp.BaselinePGIDs {
		baseline[pgid] = true
	}
	return resp.Processes, baseline, nil
}

func (c *Client) Health() error {
	resp, err := c.call(Request{Op: OpHealth}, false)
	return c.checked(resp, err)
}

func (c *Client) TerminateBackground() error {
	resp, err := c.call(Request{Op: OpTerminateBackground}, false)
	return c.checked(resp, err)
}

// UsageCPU returns the CPU seconds accumulated by finished executions.
func (c *Client) UsageCPU() (float64, error) {
	resp, err := c.call(Request{Op: OpUsage}, false)
	if err := c.checked(resp, err); err != nil {
		return 0, err
	}
	return resp.UsageCPU, nil
}

func (c *Client) WriteFile(path, content string) error {
	// The wire carries []byte (base64); string<->[]byte conversion is
	// lossless for arbitrary bytes, unlike JSON string marshaling.
	resp, err := c.call(Request{Op: OpWriteFile, Path: path, Content: []byte(content)}, false)
	return c.checked(resp, err)
}

func (c *Client) WorkspaceFiles() (map[string]string, error) {
	resp, err := c.call(Request{Op: OpWorkspaceFiles}, false)
	if err := c.checked(resp, err); err != nil {
		return nil, err
	}
	files := make(map[string]string, len(resp.Files))
	for k, v := range resp.Files {
		files[k] = string(v)
	}
	return files, nil
}
