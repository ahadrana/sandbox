package firecrackerbackend

// Unit tests for the DNS wire codec, the learned-entry set, and the proxy
// gate/forward/learn path against a fake upstream. These run WITHOUT
// FC_TEST (no microVM, no iptables): the proxy's handle path never touches
// the chain — learnIP only records; the sync loop installs it.

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/agent-sandbox/platform/network"
)

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// buildQuery renders a minimal A/IN query for name.
func buildQuery(id uint16, name string) []byte {
	var b []byte
	b = appendU16(b, id)
	b = appendU16(b, 0x0100)          // RD
	b = appendU16(b, 1)               // QDCOUNT
	b = append(b, make([]byte, 6)...) // AN/NS/AR = 0
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = appendU16(b, dnsTypeA)
	b = appendU16(b, dnsClassIN)
	return b
}

// buildResponse renders a NOERROR answer with one A record (name as a
// compression pointer to the question's offset 12).
func buildResponse(query []byte, ip net.IP, ttl uint32) []byte {
	resp := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180) // QR|RD|RA, NOERROR
	binary.BigEndian.PutUint16(resp[6:8], 1)      // ANCOUNT
	resp = append(resp, 0xC0, 0x0C)               // name -> question
	resp = appendU16(resp, dnsTypeA)
	resp = appendU16(resp, dnsClassIN)
	resp = appendU32(resp, ttl)
	resp = appendU16(resp, 4)
	resp = append(resp, ip.To4()...)
	return resp
}

func TestParseDNSQuestion(t *testing.T) {
	q, end, err := parseDNSQuestion(buildQuery(0x1234, "Example.COM"))
	if err != nil {
		t.Fatal(err)
	}
	if q.name != "example.com" || q.qtype != dnsTypeA || q.qclass != dnsClassIN {
		t.Fatalf("question = %+v", q)
	}
	if end != len(buildQuery(0x1234, "Example.COM")) {
		t.Fatalf("question end = %d", end)
	}
	// Truncated and compressed-input queries are rejected.
	if _, _, err := parseDNSQuestion([]byte{0, 1}); err == nil {
		t.Fatal("short message parsed")
	}
	bad := buildQuery(1, "example.com")
	bad[12] = 0xC0
	if _, _, err := parseDNSQuestion(bad); err == nil {
		t.Fatal("compression pointer in query QNAME accepted")
	}
}

func TestDNSErrorResponse(t *testing.T) {
	query := buildQuery(0xBEEF, "denied.example")
	resp := dnsErrorResponse(query, len(query), dnsRcodeNXDOMAIN)
	if id := binary.BigEndian.Uint16(resp[0:2]); id != 0xBEEF {
		t.Fatalf("id = %#x", id)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 || flags&0xF != dnsRcodeNXDOMAIN {
		t.Fatalf("flags = %#x", flags)
	}
	if an := binary.BigEndian.Uint16(resp[6:8]); an != 0 {
		t.Fatalf("ancount = %d", an)
	}
	q, _, err := parseDNSQuestion(resp)
	if err != nil || q.name != "denied.example" {
		t.Fatalf("question not preserved: %v %+v", err, q)
	}
}

func TestExtractARecords(t *testing.T) {
	query := buildQuery(7, "example.com")
	resp := buildResponse(query, net.ParseIP("93.184.216.34"), 2)
	got := extractARecords(resp)
	if len(got) != 1 || got[0].ip != "93.184.216.34" || got[0].ttl != 2 {
		t.Fatalf("extracted = %+v", got)
	}
	if got := extractARecords([]byte{1, 2, 3}); got != nil {
		t.Fatalf("garbage parsed: %+v", got)
	}
}

// newTestNetState builds a proxy-ready netState with no host plumbing.
func newTestNetState(pol network.EgressPolicy) *netState {
	return &netState{
		slot:       5000,
		hostIP:     "127.0.0.1",
		policy:     pol,
		generation: 1,
		learned:    map[string]learnedEntry{},
		minTTL:     5 * time.Second,
		maxLearned: 4,
		now:        time.Now,
	}
}

func TestLearnIPClampCapPrune(t *testing.T) {
	ns := newTestNetState(network.EgressPolicy{DefaultAllow: true})
	now := time.Now()
	ns.now = func() time.Time { return now }

	// Sub-floor TTL clamps to minTTL.
	learnIP(ns, "10.0.0.1", 1)
	if got := ns.learned["10.0.0.1"].expires.Sub(now); got != 5*time.Second {
		t.Fatalf("clamped ttl = %v", got)
	}
	// Refresh keeps a single entry.
	learnIP(ns, "10.0.0.1", 60)
	if len(ns.learned) != 1 {
		t.Fatalf("refresh duplicated entry: %d", len(ns.learned))
	}
	// Cap evicts the oldest insertion.
	for _, ip := range []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"} {
		learnIP(ns, ip, 60)
	}
	if len(ns.learned) != ns.maxLearned {
		t.Fatalf("learned set = %d, want cap %d", len(ns.learned), ns.maxLearned)
	}
	if _, ok := ns.learned["10.0.0.1"]; ok {
		t.Fatal("oldest entry not evicted at cap")
	}
	// Expired entries are pruned by the sync loop's reap pass (simulate).
	now = now.Add(61 * time.Second)
	for ip, e := range ns.learned {
		if !ns.now().Before(e.expires) {
			delete(ns.learned, ip)
		}
	}
	if len(ns.learned) != 0 {
		t.Fatalf("expired entries not pruned: %d", len(ns.learned))
	}
}

// fakeUpstream answers every query with a fixed A record; it records how
// many queries it saw.
type fakeUpstream struct {
	addr string
	ip   net.IP
	ttl  uint32
	seen chan struct{}
}

func startFakeUpstream(t *testing.T, ip string, ttl uint32) *fakeUpstream {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	fu := &fakeUpstream{addr: conn.LocalAddr().String(), ip: net.ParseIP(ip), ttl: ttl, seen: make(chan struct{}, 16)}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			fu.seen <- struct{}{}
			conn.WriteToUDP(buildResponse(append([]byte(nil), buf[:n]...), fu.ip, fu.ttl), src)
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return fu
}

func TestDNSProxyGateForwardLearn(t *testing.T) {
	defer func(old int) { dnsListenPort = old }(dnsListenPort)
	dnsListenPort = 0
	up := startFakeUpstream(t, "203.0.113.7", 30)
	pol := network.EgressPolicy{DefaultAllow: false, Allow: []string{"example.com"}}
	ns := newTestNetState(pol)
	proxy, err := newDNSProxy(ns, up.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	server := &dnsClient{addr: proxy.udp.LocalAddr().String()}

	// Allowed name: forwarded upstream, answer relayed, /32 learned.
	resp, err := server.query(t, buildQuery(1, "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if flags := binary.BigEndian.Uint16(resp[2:4]); flags&0xF != 0 {
		t.Fatalf("rcode = %d", flags&0xF)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		ns.mu.Lock()
		n := len(ns.learned)
		ns.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("answer A record not learned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ns.mu.Lock()
	e, ok := ns.learned["203.0.113.7"]
	ns.mu.Unlock()
	if !ok {
		t.Fatalf("learned = %v", ns.learned)
	}
	if got := time.Until(e.expires); got < 29*time.Second {
		t.Fatalf("learned ttl = %v, want ~30s", got)
	}

	// Denied name: NXDOMAIN, never forwarded, counted.
	time.Sleep(50 * time.Millisecond) // let the allowed query's upstream marker land
	for {
		select {
		case <-up.seen:
		default:
			goto drained
		}
	}
drained:
	resp, err = server.query(t, buildQuery(2, "evil.example"))
	if err != nil {
		t.Fatal(err)
	}
	if flags := binary.BigEndian.Uint16(resp[2:4]); flags&0xF != dnsRcodeNXDOMAIN {
		t.Fatalf("rcode = %d, want NXDOMAIN", flags&0xF)
	}
	select {
	case <-up.seen:
		t.Fatal("denied query reached upstream")
	case <-time.After(200 * time.Millisecond):
	}
	ns.mu.Lock()
	denied := ns.dnsDenied
	ns.mu.Unlock()
	if denied != 1 {
		t.Fatalf("dnsDenied = %d", denied)
	}

	// Metadata/cluster names are always denied, even under default-allow.
	ns.mu.Lock()
	ns.policy = network.EgressPolicy{DefaultAllow: true}
	ns.mu.Unlock()
	resp, err = server.query(t, buildQuery(3, "kubernetes.default.svc"))
	if err != nil {
		t.Fatal(err)
	}
	if flags := binary.BigEndian.Uint16(resp[2:4]); flags&0xF != dnsRcodeNXDOMAIN {
		t.Fatalf("metadata name rcode = %d", flags&0xF)
	}
}

func TestDNSProxyUpstreamFailureSERVFAIL(t *testing.T) {
	defer func(old int) { dnsListenPort = old }(dnsListenPort)
	dnsListenPort = 0
	ns := newTestNetState(network.EgressPolicy{DefaultAllow: true})
	// Nothing listens on this port.
	proxy, err := newDNSProxy(ns, "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	client := &dnsClient{addr: proxy.udp.LocalAddr().String()}
	resp, err := client.query(t, buildQuery(9, "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if flags := binary.BigEndian.Uint16(resp[2:4]); flags&0xF != 2 {
		t.Fatalf("rcode = %d, want SERVFAIL", flags&0xF)
	}
}

func TestDNSProxyTCP(t *testing.T) {
	defer func(old int) { dnsListenPort = old }(dnsListenPort)
	dnsListenPort = 0
	up := startFakeUpstream(t, "203.0.113.9", 30)
	ns := newTestNetState(network.EgressPolicy{DefaultAllow: true})
	proxy, err := newDNSProxy(ns, up.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	conn, err := net.DialTimeout("tcp", proxy.tcp.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	query := buildQuery(5, "example.com")
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(query)))
	if _, err := conn.Write(append(lenBuf[:], query...)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := readFull(conn, lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := readFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if flags := binary.BigEndian.Uint16(resp[2:4]); flags&0xF != 0 {
		t.Fatalf("tcp rcode = %d", flags&0xF)
	}
}

// dnsClient is a minimal UDP DNS client for tests.
type dnsClient struct{ addr string }

func (c *dnsClient) query(t *testing.T, query []byte) ([]byte, error) {
	t.Helper()
	conn, err := net.DialTimeout("udp", c.addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
