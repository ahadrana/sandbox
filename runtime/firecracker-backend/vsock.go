package firecrackerbackend

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

// vsockDial returns the supervisor.Client dial func for the Firecracker
// transport: dial the VM's vsock unix socket and perform the
// `CONNECT <port>` handshake; the returned connection is then a plain frame
// stream. A fresh connection per call gives natural concurrency (a blocking
// Wait never starves Status) and transparent reconnect after snapshot
// restore.
func vsockDial(udsPath string, port uint32, timeout time.Duration) supervisor.DialFunc {
	return func() (supervisor.Conn, error) {
		conn, err := net.DialTimeout("unix", udsPath, timeout)
		if err != nil {
			return nil, fmt.Errorf("vsock dial: %w", err)
		}
		// Bound the handshake itself (a wedged VMM can accept but never
		// answer); cleared before returning so blocking ops run deadline-free.
		conn.SetDeadline(time.Now().Add(timeout))
		defer conn.SetDeadline(time.Time{})
		if _, err := fmt.Fprintf(conn, "CONNECT %d\n", port); err != nil {
			conn.Close()
			return nil, fmt.Errorf("vsock connect: %w", err)
		}
		// Firecracker answers "OK <port>\n" once the guest side accepts.
		br := bufio.NewReader(conn)
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("vsock handshake: %w", err)
		}
		if !strings.HasPrefix(line, "OK") {
			conn.Close()
			return nil, fmt.Errorf("vsock handshake refused: %s", strings.TrimSpace(line))
		}
		return &prefixConn{r: br, conn: conn}, nil
	}
}

// prefixConn presents a bufio.Reader over conn as a supervisor.Conn.
type prefixConn struct {
	r    *bufio.Reader
	conn net.Conn
}

func (p *prefixConn) Read(b []byte) (int, error)    { return p.r.Read(b) }
func (p *prefixConn) Write(b []byte) (int, error)   { return p.conn.Write(b) }
func (p *prefixConn) Close() error                  { return p.conn.Close() }
func (p *prefixConn) SetDeadline(t time.Time) error { return p.conn.SetDeadline(t) }
