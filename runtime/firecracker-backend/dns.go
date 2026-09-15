package firecrackerbackend

// Learning DNS proxy (CubeSandbox P0.2 borrow, userspace — no eBPF).
//
// Each networked incarnation runs one proxy on its TAP host address :53
// (the guest's resolv.conf points there). Every query's name is gated
// through network.EvaluateEgress — the same normalization and
// metadata/cluster always-deny rules as the rest of the platform. Allowed
// queries are forwarded upstream (the host resolver, or
// Config.DNSUpstream); A answers are learned as (IP, TTL) /32 allow
// entries for THIS incarnation only and installed into its egress chain in
// coalesced atomic batches (P0.5), then reaped on TTL expiry. Denied names
// get NXDOMAIN and an audit line. Truncated upstream UDP answers are
// retried over TCP; upstream failure yields SERVFAIL.
//
// Honest limit (documented in doc.go): a guest hardcoding its own
// resolver bypasses name learning — under default-deny that DNS traffic is
// dropped like any other non-policy egress (fail-closed by omission), and
// hostname-allowed destinations stay unreachable by IP unless the policy
// also lists the IP/CIDR statically.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/agent-sandbox/platform/network"
)

const (
	dnsRcodeNXDOMAIN = 3
	dnsTypeA         = 1
	dnsTypeAAAA      = 28
	dnsClassIN       = 1
	// dnsUDPPacketSize caps accepted query/response sizes (no EDNS needed
	// for A/AAAA learning).
	dnsUDPPacketSize   = 4096
	dnsUpstreamTimeout = 3 * time.Second
)

// dnsProxy is one incarnation's learning resolver.
type dnsProxy struct {
	ns       *netState
	upstream string // host:port
	udp      *net.UDPConn
	tcp      net.Listener
	quit     chan struct{}
	wg       sync.WaitGroup
}

// dnsListenPort is the proxy's listen port (53); tests override it for
// unprivileged loopback binds.
var dnsListenPort = 53

// newDNSProxy binds UDP+TCP :53 on the incarnation's TAP host address and
// starts serving. upstream is "host" or "host:port"; empty means the first
// nameserver in /etc/resolv.conf, falling back to 8.8.8.8.
func newDNSProxy(ns *netState, upstream string) (*dnsProxy, error) {
	if upstream == "" {
		upstream = hostResolver()
	}
	if _, _, err := net.SplitHostPort(upstream); err != nil {
		upstream = net.JoinHostPort(upstream, "53")
	}
	addr := &net.UDPAddr{IP: net.ParseIP(ns.hostIP), Port: dnsListenPort}
	udp, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dns proxy udp %s:%d: %w", ns.hostIP, dnsListenPort, err)
	}
	tcp, err := net.Listen("tcp", net.JoinHostPort(ns.hostIP, fmt.Sprint(dnsListenPort)))
	if err != nil {
		udp.Close()
		return nil, fmt.Errorf("dns proxy tcp %s:%d: %w", ns.hostIP, dnsListenPort, err)
	}
	p := &dnsProxy{ns: ns, upstream: upstream, udp: udp, tcp: tcp, quit: make(chan struct{})}
	p.wg.Add(2)
	go p.serveUDP()
	go p.serveTCP()
	return p, nil
}

// hostResolver reads the first nameserver from /etc/resolv.conf.
func hostResolver() string {
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "nameserver" {
				return fields[1]
			}
		}
	}
	return "8.8.8.8"
}

func (p *dnsProxy) close() {
	select {
	case <-p.quit:
	default:
		close(p.quit)
	}
	p.udp.Close()
	p.tcp.Close()
	p.wg.Wait()
}

func (p *dnsProxy) serveUDP() {
	defer p.wg.Done()
	buf := make([]byte, dnsUDPPacketSize)
	for {
		n, src, err := p.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		go func() {
			resp := p.handle(query)
			if resp != nil {
				p.udp.WriteToUDP(resp, src)
			}
		}()
	}
}

func (p *dnsProxy) serveTCP() {
	defer p.wg.Done()
	for {
		conn, err := p.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(dnsUpstreamTimeout + 2*time.Second))
			var lenBuf [2]byte
			if _, err := readFull(conn, lenBuf[:]); err != nil {
				return
			}
			qlen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if qlen <= 0 || qlen > dnsUDPPacketSize {
				return
			}
			query := make([]byte, qlen)
			if _, err := readFull(conn, query); err != nil {
				return
			}
			resp := p.handle(query)
			if resp == nil {
				return
			}
			binary.BigEndian.PutUint16(lenBuf[:], uint16(len(resp)))
			conn.Write(lenBuf[:])
			conn.Write(resp)
		}()
	}
}

// readFull reads exactly len(b) bytes (io.ReadFull without the io import
// ceremony for a *net.TCPConn/UDPConn mix).
func readFull(conn net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := conn.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// handle gates one raw DNS query through the egress policy and returns the
// raw response (nil: drop silently on unparseable input).
func (p *dnsProxy) handle(query []byte) []byte {
	q, qEnd, err := parseDNSQuestion(query)
	if err != nil {
		return nil
	}
	p.ns.mu.Lock()
	pol := p.ns.policy
	p.ns.mu.Unlock()
	decision := network.EvaluateEgress(pol, q.name, time.Now())
	if !decision.Allowed {
		p.ns.mu.Lock()
		p.ns.dnsDenied++
		p.ns.mu.Unlock()
		fmt.Fprintf(os.Stderr, "firecrackerbackend: dns deny %s (slot %d): %s\n", q.name, p.ns.slot, decision.Reason)
		return dnsErrorResponse(query, qEnd, dnsRcodeNXDOMAIN)
	}
	resp, err := p.forward(query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "firecrackerbackend: dns upstream %s for %s: %v\n", p.upstream, q.name, err)
		return dnsErrorResponse(query, qEnd, 2) // SERVFAIL
	}
	for _, a := range extractARecords(resp) {
		learnIP(p.ns, a.ip, a.ttl)
	}
	return resp
}

// forward relays the raw query upstream over UDP, retrying over TCP when
// the answer is truncated.
func (p *dnsProxy) forward(query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", p.upstream, dnsUpstreamTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dnsUpstreamTimeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, dnsUDPPacketSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	resp := buf[:n]
	if n >= 4 && resp[3]&0x02 != 0 { // TC bit: retry over TCP
		return p.forwardTCP(query)
	}
	return resp, nil
}

func (p *dnsProxy) forwardTCP(query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", p.upstream, dnsUpstreamTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dnsUpstreamTimeout))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(query)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	if _, err := readFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := readFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// dnsQuestion is the parsed first question of a query.
type dnsQuestion struct {
	name   string // dotted, lowercased, no trailing dot
	qtype  uint16
	qclass uint16
}

// parseDNSQuestion validates the header and parses the first question,
// returning it plus the offset just past it. Compression pointers are not
// valid in a query's QNAME and are rejected.
func parseDNSQuestion(b []byte) (dnsQuestion, int, error) {
	var q dnsQuestion
	if len(b) < 13 {
		return q, 0, fmt.Errorf("short DNS message")
	}
	if binary.BigEndian.Uint16(b[4:6]) == 0 {
		return q, 0, fmt.Errorf("no question section")
	}
	off := 12
	var labels []string
	for {
		if off >= len(b) {
			return q, 0, fmt.Errorf("truncated QNAME")
		}
		l := int(b[off])
		if l&0xC0 != 0 {
			return q, 0, fmt.Errorf("compression pointer in query QNAME")
		}
		off++
		if l == 0 {
			break
		}
		if off+l > len(b) {
			return q, 0, fmt.Errorf("truncated label")
		}
		labels = append(labels, strings.ToLower(string(b[off:off+l])))
		off += l
	}
	if off+4 > len(b) {
		return q, 0, fmt.Errorf("truncated question")
	}
	q.name = strings.Join(labels, ".")
	q.qtype = binary.BigEndian.Uint16(b[off : off+2])
	q.qclass = binary.BigEndian.Uint16(b[off+2 : off+4])
	return q, off + 4, nil
}

// dnsErrorResponse renders a response with the given rcode: header copied
// from the query (QR set, RA set, rcode applied), question section
// preserved, all other sections emptied.
func dnsErrorResponse(query []byte, questionEnd int, rcode uint16) []byte {
	resp := make([]byte, questionEnd)
	copy(resp, query)
	flags := binary.BigEndian.Uint16(query[2:4])
	flags &^= 0xF // clear rcode
	flags |= 0x8000 | 0x0080 | rcode
	binary.BigEndian.PutUint16(resp[2:4], flags)
	// ANCOUNT/NSCOUNT/ARCOUNT = 0; QDCOUNT preserved.
	for i := 6; i < 12; i += 2 {
		binary.BigEndian.PutUint16(resp[i:i+2], 0)
	}
	return resp
}

// learnedA is one A answer extracted from an upstream response.
type learnedA struct {
	ip  string
	ttl uint32
}

// skipDNSName returns the offset past a possibly compressed name.
func skipDNSName(b []byte, off int) (int, error) {
	for {
		if off >= len(b) {
			return 0, fmt.Errorf("truncated name")
		}
		l := int(b[off])
		if l&0xC0 == 0xC0 {
			if off+2 > len(b) {
				return 0, fmt.Errorf("truncated pointer")
			}
			return off + 2, nil
		}
		off++
		if l == 0 {
			return off, nil
		}
		off += l
	}
}

// extractARecords pulls every A answer (owner name ignored: CNAME-chain
// targets are learned deliberately — they are the addresses the resolver
// actually handed out for the gated name).
func extractARecords(b []byte) []learnedA {
	if len(b) < 12 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		next, err := skipDNSName(b, off)
		if err != nil {
			return nil
		}
		off = next + 4
	}
	var out []learnedA
	for i := 0; i < an; i++ {
		next, err := skipDNSName(b, off)
		if err != nil || next+10 > len(b) {
			return out
		}
		typ := binary.BigEndian.Uint16(b[next : next+2])
		ttl := binary.BigEndian.Uint32(b[next+4 : next+8])
		rdlen := int(binary.BigEndian.Uint16(b[next+8 : next+10]))
		rdata := next + 10
		if rdata+rdlen > len(b) {
			return out
		}
		if typ == dnsTypeA && rdlen == 4 {
			out = append(out, learnedA{ip: net.IP(b[rdata : rdata+4]).String(), ttl: ttl})
		}
		off = rdata + rdlen
	}
	return out
}
