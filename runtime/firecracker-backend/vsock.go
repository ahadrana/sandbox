package firecrackerbackend

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

// vsockSupervisor is the host-side supervisor.API transport: it dials the
// Firecracker vsock unix socket, performs the `CONNECT <port>` handshake,
// and exchanges one framed request/response per connection. A fresh
// connection per call gives natural concurrency (a blocking Wait never
// starves Status) and transparent reconnect after snapshot restore.
type vsockSupervisor struct {
	udsPath string
	port    uint32
	timeout time.Duration
	// alive reports whether the VMM process is still running; wired by the
	// backend after spawn so a blocked Wait can notice a dead runtime even
	// when the vsock connection never closes on its own.
	alive func() bool
}

func newVsockSupervisor(udsPath string, port uint32, timeout time.Duration) *vsockSupervisor {
	return &vsockSupervisor{udsPath: udsPath, port: port, timeout: timeout}
}

// call performs one request/response round trip on a fresh connection.
// blocking ops (Wait) run without a deadline: the exchange ends when the
// guest answers or the VM dies (connection closes).
func (s *vsockSupervisor) call(req supervisor.Request, blocking bool) (supervisor.Response, error) {
	conn, err := net.DialTimeout("unix", s.udsPath, s.timeout)
	if err != nil {
		return supervisor.Response{}, fmt.Errorf("vsock dial: %w", err)
	}
	defer conn.Close()
	if !blocking {
		conn.SetDeadline(time.Now().Add(s.timeout))
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", s.port); err != nil {
		return supervisor.Response{}, fmt.Errorf("vsock connect: %w", err)
	}
	// Firecracker answers "OK <port>\n" once the guest side accepts.
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return supervisor.Response{}, fmt.Errorf("vsock handshake: %w", err)
	}
	if !strings.HasPrefix(line, "OK") {
		return supervisor.Response{}, fmt.Errorf("vsock handshake refused: %s", strings.TrimSpace(line))
	}
	stream := &prefixReader{r: br, conn: conn}
	if err := supervisor.WriteFrame(stream, req); err != nil {
		return supervisor.Response{}, err
	}
	var resp supervisor.Response
	if err := supervisor.ReadFrame(stream, &resp); err != nil {
		return supervisor.Response{}, err
	}
	return resp, nil
}

// prefixReader presents a bufio.Reader over conn as an io.ReadWriter.
type prefixReader struct {
	r    *bufio.Reader
	conn net.Conn
}

func (p *prefixReader) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *prefixReader) Write(b []byte) (int, error) { return p.conn.Write(b) }

func (s *vsockSupervisor) checked(resp supervisor.Response, err error) error {
	if err != nil {
		return err
	}
	if !resp.OK {
		return supervisor.MapError(resp.Error)
	}
	return nil
}

func (s *vsockSupervisor) Exec(req supervisor.ExecRequest) error {
	resp, err := s.call(supervisor.Request{
		Op:          supervisor.OpExec,
		ExecutionID: req.ExecutionID,
		Command:     req.Command,
		Env:         req.Env,
		Baseline:    req.Baseline,
	}, false)
	return s.checked(resp, err)
}

func (s *vsockSupervisor) Status(executionID string) (supervisor.StatusResponse, error) {
	resp, err := s.call(supervisor.Request{Op: supervisor.OpStatus, ExecutionID: executionID}, false)
	if err := s.checked(resp, err); err != nil {
		return supervisor.StatusResponse{}, err
	}
	return resp.Status, nil
}

// Wait blocks until the guest reports the execution's result. There is no
// absolute timeout — long-running commands are legitimate — so a liveness
// watchdog bounds the wait instead: every waitWatchdogInterval the VMM
// process liveness and a Health probe on a second connection are checked,
// and after waitWatchdogMaxFailures consecutive failures (or a dead VMM)
// the wait aborts with supervisor.ErrUnhealthy. Without this a wedged guest
// supervisor (still holding the vsock connection open but never answering)
// would block Wait — and any caller waiting on it — forever.
const (
	waitWatchdogInterval    = 5 * time.Second
	waitWatchdogMaxFailures = 3
)

func (s *vsockSupervisor) Wait(executionID string) (supervisor.Result, error) {
	type waitOutcome struct {
		resp supervisor.Response
		err  error
	}
	done := make(chan waitOutcome, 1)
	go func() {
		resp, err := s.call(supervisor.Request{Op: supervisor.OpWait, ExecutionID: executionID}, true)
		done <- waitOutcome{resp, err}
	}()
	ticker := time.NewTicker(waitWatchdogInterval)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case out := <-done:
			if err := s.checked(out.resp, out.err); err != nil {
				return supervisor.Result{}, err
			}
			return out.resp.Result, nil
		case <-ticker.C:
			if s.alive != nil && !s.alive() {
				return supervisor.Result{}, fmt.Errorf("%w: runtime process gone", supervisor.ErrUnhealthy)
			}
			if err := s.Health(); err != nil {
				failures++
				if failures >= waitWatchdogMaxFailures {
					return supervisor.Result{}, fmt.Errorf("%w: guest supervisor unresponsive after %d probes: %v", supervisor.ErrUnhealthy, failures, err)
				}
			} else {
				failures = 0
			}
		}
	}
}

func (s *vsockSupervisor) Cancel(executionID string) error {
	resp, err := s.call(supervisor.Request{Op: supervisor.OpCancel, ExecutionID: executionID}, false)
	return s.checked(resp, err)
}

func (s *vsockSupervisor) ReadOutput(executionID string, stderr bool, offset int64, maxBytes int) (supervisor.OutputChunk, error) {
	resp, err := s.call(supervisor.Request{
		Op: supervisor.OpReadOutput, ExecutionID: executionID,
		Stderr: stderr, Offset: offset, MaxBytes: maxBytes,
	}, false)
	if err := s.checked(resp, err); err != nil {
		return supervisor.OutputChunk{}, err
	}
	return supervisor.OutputChunk{Data: resp.Data, Offset: offset, EOF: resp.EOF}, nil
}

func (s *vsockSupervisor) ProcessInventory() ([]supervisor.ProcessInfo, error) {
	inv, _, err := s.inventory()
	return inv, err
}

// inventory also returns the guest's baseline process-group set.
func (s *vsockSupervisor) inventory() ([]supervisor.ProcessInfo, map[int]bool, error) {
	resp, err := s.call(supervisor.Request{Op: supervisor.OpProcessInventory}, false)
	if err := s.checked(resp, err); err != nil {
		return nil, nil, err
	}
	baseline := map[int]bool{}
	for _, pgid := range resp.BaselinePGIDs {
		baseline[pgid] = true
	}
	return resp.Processes, baseline, nil
}

func (s *vsockSupervisor) Health() error {
	resp, err := s.call(supervisor.Request{Op: supervisor.OpHealth}, false)
	return s.checked(resp, err)
}

func (s *vsockSupervisor) TerminateBackground() error {
	resp, err := s.call(supervisor.Request{Op: supervisor.OpTerminateBackground}, false)
	return s.checked(resp, err)
}

func (s *vsockSupervisor) WriteFile(path, content string) error {
	// The wire carries []byte (base64); string<->[]byte conversion is
	// lossless for arbitrary bytes, unlike JSON string marshaling.
	resp, err := s.call(supervisor.Request{Op: supervisor.OpWriteFile, Path: path, Content: []byte(content)}, false)
	return s.checked(resp, err)
}

func (s *vsockSupervisor) WorkspaceFiles() (map[string]string, error) {
	resp, err := s.call(supervisor.Request{Op: supervisor.OpWorkspaceFiles}, false)
	if err := s.checked(resp, err); err != nil {
		return nil, err
	}
	files := make(map[string]string, len(resp.Files))
	for k, v := range resp.Files {
		files[k] = string(v)
	}
	return files, nil
}
