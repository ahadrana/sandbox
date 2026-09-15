package resumeproxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/network"
	fakebackend "github.com/agent-sandbox/platform/runtime/fake-backend"
	"github.com/agent-sandbox/platform/workspace"
)

// stubRouter returns programmable verdicts and counts calls.
type stubRouter struct {
	mu    sync.Mutex
	calls int
	dec   network.RouteDecision
}

func (s *stubRouter) Route(bindingID string) network.RouteDecision {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.dec
}

func (s *stubRouter) set(d network.RouteDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dec = d
}

func (s *stubRouter) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func backendServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "upstream-ok")
	}))
	t.Cleanup(s.Close)
	return s
}

func doReq(t *testing.T, p *Proxy) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "http://gw/", nil)
	req.Header.Set("X-Endpoint-Binding", "b1")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
}

// ADR-007: N concurrent requests to a suspended sandbox share ONE resume.
func TestSingleFlightUnderConcurrency(t *testing.T) {
	up := backendServer(t)
	rt := &stubRouter{dec: network.RouteDecision{Reason: "sandbox not live", SandboxID: "sb1", Port: 8080}}
	var resumeCalls int32
	release := make(chan struct{})
	p := New(Config{
		Router: rt,
		Resume: func(id string) error {
			atomic.AddInt32(&resumeCalls, 1)
			<-release // hold the flight open so waiters pile up
			// After "resume", the sandbox routes live.
			rt.set(network.RouteDecision{Allowed: true, SandboxID: "sb1", Port: 8080})
			return nil
		},
		Upstream: func(id string, port int) (string, error) {
			return up.Listener.Addr().String(), nil
		},
		MaxResumeAttempts: 1,
	})
	const n = 16
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = doReq(t, p).Code
		}(i)
	}
	// Let every waiter attach to the flight, then release the resume.
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	if got := atomic.LoadInt32(&resumeCalls); got != 1 {
		t.Fatalf("resume calls = %d, want exactly 1 (single-flight)", got)
	}
	for i, c := range codes {
		if c != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, c)
		}
	}
	m := p.Metrics()
	if m.ResumeTriggered != 1 || m.ResumeShared != n-1 {
		t.Fatalf("metrics: triggered=%d shared=%d, want 1/%d", m.ResumeTriggered, m.ResumeShared, n-1)
	}
}

// ADR-007 hot path: a cached-live binding forwards with zero control-plane
// calls (no Route, no Resume).
func TestPassThroughHotPath(t *testing.T) {
	up := backendServer(t)
	rt := &stubRouter{dec: network.RouteDecision{Allowed: true, SandboxID: "sb1", Port: 8080}}
	var resumeCalls int32
	p := New(Config{
		Router: rt,
		Resume: func(id string) error { atomic.AddInt32(&resumeCalls, 1); return nil },
		Upstream: func(id string, port int) (string, error) {
			return up.Listener.Addr().String(), nil
		},
	})
	if rec := doReq(t, p); rec.Code != http.StatusOK {
		t.Fatalf("first request = %d", rec.Code)
	}
	if rt.count() != 1 {
		t.Fatalf("route calls after first request = %d, want 1", rt.count())
	}
	for i := 0; i < 5; i++ {
		if rec := doReq(t, p); rec.Code != http.StatusOK {
			t.Fatalf("hot request %d = %d", i, rec.Code)
		}
	}
	if rt.count() != 1 {
		t.Fatalf("hot path made control-plane route calls: %d", rt.count())
	}
	if atomic.LoadInt32(&resumeCalls) != 0 {
		t.Fatal("hot path triggered a resume")
	}
	m := p.Metrics()
	if m.PassThrough != 5 {
		t.Fatalf("PassThrough = %d, want 5", m.PassThrough)
	}
}

// ADR-007: resume failure is bounded (attempt budget), then the negative
// cache fails fast without new control-plane calls.
func TestResumeFailureBounded(t *testing.T) {
	rt := &stubRouter{dec: network.RouteDecision{Reason: "sandbox not live", SandboxID: "sb1", Port: 8080}}
	var resumeCalls int32
	p := New(Config{
		Router: rt,
		Resume: func(id string) error {
			atomic.AddInt32(&resumeCalls, 1)
			return errors.New("restore failed")
		},
		Upstream:          func(id string, port int) (string, error) { return "", nil },
		MaxResumeAttempts: 2,
		NegativeTTL:       time.Minute,
	})
	if rec := doReq(t, p); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if got := atomic.LoadInt32(&resumeCalls); got != 2 {
		t.Fatalf("resume attempts = %d, want bounded 2", got)
	}
	// Within the negative TTL: fail fast, no new resume, no new route.
	routes := rt.count()
	if rec := doReq(t, p); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("negative-cache status = %d, want 503", rec.Code)
	}
	if atomic.LoadInt32(&resumeCalls) != 2 {
		t.Fatal("negative cache did not suppress further resumes")
	}
	if rt.count() != routes {
		t.Fatal("negative-cache hit made a control-plane route call")
	}
	m := p.Metrics()
	if m.NegativeHits != 1 || m.ResumeFailed != 1 {
		t.Fatalf("metrics = %+v", m)
	}
}

// ADR-007: a waiter past ResumeTimeout gets 504 while the flight
// continues; the next request joins the SAME flight (no second resume).
func TestResumeTimeout(t *testing.T) {
	up := backendServer(t)
	rt := &stubRouter{dec: network.RouteDecision{Reason: "sandbox not live", SandboxID: "sb1", Port: 8080}}
	release := make(chan struct{})
	var resumeCalls int32
	p := New(Config{
		Router: rt,
		Resume: func(id string) error {
			atomic.AddInt32(&resumeCalls, 1)
			<-release
			rt.set(network.RouteDecision{Allowed: true, SandboxID: "sb1", Port: 8080})
			return nil
		},
		Upstream:          func(id string, port int) (string, error) { return up.Listener.Addr().String(), nil },
		MaxResumeAttempts: 1,
		ResumeTimeout:     100 * time.Millisecond,
	})
	if rec := doReq(t, p); rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", rec.Code)
	}
	// Flight still running; a second request attaches to it and, released
	// well within its own timeout budget, rides the same resume to 200.
	done := make(chan int, 1)
	go func() { done <- doReq(t, p).Code }()
	time.Sleep(20 * time.Millisecond)
	close(release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("post-timeout request = %d, want 200", code)
	}
	if got := atomic.LoadInt32(&resumeCalls); got != 1 {
		t.Fatalf("resume calls = %d, want 1 shared across timeout", got)
	}
	if p.Metrics().ResumeTimeouts != 1 {
		t.Fatalf("ResumeTimeouts = %d, want 1", p.Metrics().ResumeTimeouts)
	}
}

// ADR-007: the live cache expires; the next request re-routes.
func TestEndpointCacheExpiry(t *testing.T) {
	up := backendServer(t)
	rt := &stubRouter{dec: network.RouteDecision{Allowed: true, SandboxID: "sb1", Port: 8080}}
	now := time.Now()
	clock := &manualNow{t: now}
	p := New(Config{
		Router:   rt,
		Resume:   func(id string) error { return nil },
		Upstream: func(id string, port int) (string, error) { return up.Listener.Addr().String(), nil },
		CacheTTL: time.Second,
		Now:      clock.Now,
	})
	doReq(t, p)
	doReq(t, p)
	if rt.count() != 1 {
		t.Fatalf("route calls within TTL = %d, want 1", rt.count())
	}
	clock.advance(2 * time.Second)
	doReq(t, p)
	if rt.count() != 2 {
		t.Fatalf("route calls after TTL expiry = %d, want 2", rt.count())
	}
}

type manualNow struct {
	mu sync.Mutex
	t  time.Time
}

func (m *manualNow) Now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.t
}

func (m *manualNow) advance(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t = m.t.Add(d)
}

// ADR-007 end-to-end with the real manager + fake backend (conformance
// harness style): a request to a suspended sandbox's binding triggers one
// resume through Manager.Resume, the binding reactivates, and the request
// forwards.
func TestManagerIntegration(t *testing.T) {
	clock := domain.NewManualClock(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	outbox := eventservice.NewOutbox()
	store := sandboxmanager.NewMemoryStore()
	rt := fakebackend.New()
	mgr := sandboxmanager.New(clock, ids, ws, rt, outbox, store, "host-1")

	sb, err := mgr.CreateSandbox(api.CreateSandboxRequest{Version: api.SchemaVersionV1, TenantID: "t1", TaskRef: "task-proxy"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Materialize(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	b, err := mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
		Version:    api.SchemaVersionV1,
		SandboxID:  sb.SandboxID,
		TenantID:   "t1",
		TargetPort: 8080,
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	// The gateway now denies: binding SUSPENDED / sandbox not live.
	gw := network.NewGateway(mgr)
	if d := gw.Route(b.BindingID); d.Allowed {
		t.Fatalf("suspended binding still routable: %+v", d)
	}

	up := backendServer(t)
	var resumeCalls int32
	p := New(Config{
		Router: gw,
		Resume: func(id string) error {
			atomic.AddInt32(&resumeCalls, 1)
			_, err := mgr.Resume(id)
			return err
		},
		Upstream:          func(id string, port int) (string, error) { return up.Listener.Addr().String(), nil },
		MaxResumeAttempts: 1,
	})
	req := httptest.NewRequest("GET", "http://gw/", nil)
	req.Header.Set("X-Endpoint-Binding", b.BindingID)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body)
	}
	if atomic.LoadInt32(&resumeCalls) != 1 {
		t.Fatalf("resume calls = %d, want 1", resumeCalls)
	}
	// ADR-007 manager fix: the binding is ACTIVE again and routable.
	if d := gw.Route(b.BindingID); !d.Allowed {
		t.Fatalf("binding not reactivated after resume: %+v", d)
	}
	got := mgr.ListEndpointBindings(sb.SandboxID)
	if len(got) != 1 || got[0].State != domain.EndpointActive {
		t.Fatalf("binding state = %+v, want ACTIVE", got)
	}
}

// --- Hostname-based binding resolution (ADR-007 naming hook) ---

func doHostReq(t *testing.T, p *Proxy, host string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "http://"+host+"/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
}

// nameLookup returns a counting LookupBinding over a static name->binding
// table.
func nameLookup(table map[string]string) (func(string) (string, bool), *int32) {
	var calls int32
	return func(name string) (string, bool) {
		atomic.AddInt32(&calls, 1)
		id, ok := table[name]
		return id, ok
	}, &calls
}

// A request whose Host is "<logical-name>.<EndpointDomain>" resolves the
// binding by name and triggers the same single-flight resume as an
// explicit header.
func TestHostBasedResumeTrigger(t *testing.T) {
	up := backendServer(t)
	rt := &stubRouter{dec: network.RouteDecision{Reason: "sandbox not live", SandboxID: "sb1", Port: 8080}}
	lookup, lookupCalls := nameLookup(map[string]string{"ep1": "b1"})
	var resumeCalls int32
	p := New(Config{
		Router:         rt,
		EndpointDomain: "endpoints.test",
		LookupBinding:  lookup,
		Resume: func(id string) error {
			atomic.AddInt32(&resumeCalls, 1)
			rt.set(network.RouteDecision{Allowed: true, SandboxID: "sb1", Port: 8080})
			return nil
		},
		Upstream:          func(id string, port int) (string, error) { return up.Listener.Addr().String(), nil },
		MaxResumeAttempts: 1,
	})
	if rec := doHostReq(t, p, "ep1.endpoints.test"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body)
	}
	if got := atomic.LoadInt32(&resumeCalls); got != 1 {
		t.Fatalf("resume calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(lookupCalls); got != 1 {
		t.Fatalf("name lookups = %d, want 1", got)
	}
}

// The explicit X-Endpoint-Binding header always wins over the hostname:
// the name is never resolved and the router sees the header's binding.
func TestHeaderBeatsHost(t *testing.T) {
	up := backendServer(t)
	rt := &stubRouter{dec: network.RouteDecision{Allowed: true, SandboxID: "sb1", Port: 8080}}
	lookup, lookupCalls := nameLookup(map[string]string{"ep1": "b-host"})
	p := New(Config{
		Router:         rt,
		EndpointDomain: "endpoints.test",
		LookupBinding:  lookup,
		Resume:         func(id string) error { return nil },
		Upstream:       func(id string, port int) (string, error) { return up.Listener.Addr().String(), nil },
	})
	req := httptest.NewRequest("GET", "http://ep1.endpoints.test/", nil)
	req.Header.Set("X-Endpoint-Binding", "b-header")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := atomic.LoadInt32(lookupCalls); got != 0 {
		t.Fatalf("name lookups = %d, want 0 (header wins)", got)
	}
}

// An unknown endpoint name fails closed with 404 and never reaches the
// router (matching the gateway's "unknown binding" deny).
func TestUnknownHostFailClosed(t *testing.T) {
	rt := &stubRouter{dec: network.RouteDecision{Allowed: true, SandboxID: "sb1", Port: 8080}}
	lookup, _ := nameLookup(map[string]string{"ep1": "b1"})
	p := New(Config{
		Router:         rt,
		EndpointDomain: "endpoints.test",
		LookupBinding:  lookup,
		Resume:         func(id string) error { return nil },
		Upstream:       func(id string, port int) (string, error) { return "", nil },
	})
	if rec := doHostReq(t, p, "nope.endpoints.test"); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if rt.count() != 0 {
		t.Fatalf("router called %d times for unknown name, want 0", rt.count())
	}
	// A host outside the endpoint domain with no header is a plain 400.
	if rec := doHostReq(t, p, "example.com"); rec.Code != http.StatusBadRequest {
		t.Fatalf("non-endpoint host status = %d, want 400", rec.Code)
	}
	if p.Metrics().UnknownNames != 1 {
		t.Fatalf("UnknownNames = %d, want 1", p.Metrics().UnknownNames)
	}
}

// Positive name resolutions are cached with the live-cache TTL
// discipline: N requests within the TTL make exactly one LookupBinding
// call.
func TestCachedResolutionPurity(t *testing.T) {
	up := backendServer(t)
	rt := &stubRouter{dec: network.RouteDecision{Allowed: true, SandboxID: "sb1", Port: 8080}}
	lookup, lookupCalls := nameLookup(map[string]string{"ep1": "b1"})
	clock := &manualNow{t: time.Now()}
	p := New(Config{
		Router:         rt,
		EndpointDomain: "endpoints.test",
		LookupBinding:  lookup,
		Resume:         func(id string) error { return nil },
		Upstream:       func(id string, port int) (string, error) { return up.Listener.Addr().String(), nil },
		CacheTTL:       time.Second,
		Now:            clock.Now,
	})
	for i := 0; i < 5; i++ {
		if rec := doHostReq(t, p, "ep1.endpoints.test"); rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d", i, rec.Code)
		}
	}
	if got := atomic.LoadInt32(lookupCalls); got != 1 {
		t.Fatalf("name lookups within TTL = %d, want 1", got)
	}
	clock.advance(2 * time.Second)
	if rec := doHostReq(t, p, "ep1.endpoints.test"); rec.Code != http.StatusOK {
		t.Fatalf("post-expiry request = %d", rec.Code)
	}
	if got := atomic.LoadInt32(lookupCalls); got != 2 {
		t.Fatalf("name lookups after TTL expiry = %d, want 2", got)
	}
}
