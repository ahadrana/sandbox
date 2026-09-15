// Package resumeproxy is the ingress resume-proxy (ADR-007): an HTTP
// reverse proxy in front of the endpoint data path that makes suspended
// sandboxes transparently addressable. Requests identify the endpoint
// binding either explicitly (X-Endpoint-Binding header) or by hostname
// ("<logical-name>.<EndpointDomain>", resolved to a binding via
// LookupBinding); the header always wins. The proxy routes the binding
// through network.Gateway, forwards directly when
// the sandbox is live (cached — the hot path makes no control-plane
// calls), and single-flights a Manager resume when it is suspended,
// forwarding once running. Resume failures are bounded (attempt budget +
// per-binding negative cache) so a failing sandbox never stampedes the
// control plane. stdlib-only, Go 1.18-compatible.
package resumeproxy

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/agent-sandbox/platform/network"
)

// Router resolves a binding to a routing verdict (*network.Gateway).
type Router interface {
	Route(bindingID string) network.RouteDecision
}

// Resumer resumes one sandbox (Manager.Resume adapted to an error).
type Resumer func(sandboxID string) error

// Upstream resolves the dial address (host:port) of a LIVE sandbox
// endpoint. Called only after the gateway allowed the route.
type Upstream func(sandboxID string, port int) (string, error)

// Config configures a Proxy; zero values use the documented defaults.
type Config struct {
	Router   Router
	Resume   Resumer
	Upstream Upstream
	// BindingHeader carries the endpoint binding ID
	// (default "X-Endpoint-Binding"); when set it always wins over
	// hostname resolution.
	BindingHeader string
	// EndpointDomain, when set, enables hostname-based binding
	// resolution: a request whose Host is "<logical-name>.<EndpointDomain>"
	// resolves its binding by logical name via LookupBinding.
	EndpointDomain string
	// LookupBinding resolves a logical endpoint name to a binding ID
	// (required when EndpointDomain is set). Positive resolutions are
	// cached for CacheTTL; unknown names fail closed with 404.
	LookupBinding func(logicalName string) (string, bool)
	// CacheTTL is how long a verified-live binding forwards without any
	// control-plane call (default 2s).
	CacheTTL time.Duration
	// NegativeTTL is how long a binding whose resume just failed fails
	// fast with 503 (default 5s).
	NegativeTTL time.Duration
	// ResumeTimeout bounds one waiter's patience (default 60s); the
	// shared flight continues past it.
	ResumeTimeout time.Duration
	// MaxResumeAttempts bounds Resume calls inside one flight (default 2).
	MaxResumeAttempts int
	// Audit, when set, records resume triggers and failures.
	Audit *network.AuditLog
	// Now overrides the clock (tests); default time.Now.
	Now func() time.Time
}

func (c Config) withDefaults() Config {
	if c.BindingHeader == "" {
		c.BindingHeader = "X-Endpoint-Binding"
	}
	if c.CacheTTL == 0 {
		c.CacheTTL = 2 * time.Second
	}
	if c.NegativeTTL == 0 {
		c.NegativeTTL = 5 * time.Second
	}
	if c.ResumeTimeout == 0 {
		c.ResumeTimeout = 60 * time.Second
	}
	if c.MaxResumeAttempts <= 0 {
		c.MaxResumeAttempts = 2
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// Metrics is a point-in-time snapshot of proxy counters.
type Metrics struct {
	Requests        int
	PassThrough     int // forwarded via the live cache, no control-plane call
	RouteLookups    int
	ResumeTriggered int // flights started
	ResumeShared    int // waiters attached to an in-flight resume
	ResumeSucceeded int
	ResumeFailed    int
	ResumeTimeouts  int
	NegativeHits    int
	UpstreamErrors  int
	NameResolutions int // LookupBinding calls (hostname resolutions)
	UnknownNames    int // hostname lookups that resolved to no binding (404)
}

// flight is one in-flight resume shared by every waiter on that sandbox.
type flight struct {
	done chan struct{}
	err  error
}

// Proxy is an http.Handler implementing ADR-007.
type Proxy struct {
	cfg      Config
	mu       sync.Mutex
	live     map[string]time.Time // bindingID -> forward-until
	negative map[string]time.Time // bindingID -> fail-fast-until
	flights  map[string]*flight   // sandboxID -> shared resume
	// cachedTarget remembers the route verdict behind a live-cache entry
	// (the cache stores the target, not the address: upstream address
	// resolution still happens per request).
	cachedTarget map[string]target
	// resolved caches logicalName -> bindingID for CacheTTL (same TTL
	// discipline as the live cache: positive entries only).
	resolved map[string]resolvedName
	metrics  Metrics
}

type resolvedName struct {
	bindingID string
	until     time.Time
}

type target struct {
	sandboxID string
	port      int
}

// New creates a Proxy. Router, Resume and Upstream are required.
func New(cfg Config) *Proxy {
	c := cfg.withDefaults()
	return &Proxy{
		cfg:          c,
		live:         map[string]time.Time{},
		negative:     map[string]time.Time{},
		flights:      map[string]*flight{},
		cachedTarget: map[string]target{},
		resolved:     map[string]resolvedName{},
	}
}

// Metrics returns a copy of the current counters.
func (p *Proxy) Metrics() Metrics {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.metrics
}

// SandboxIDHeader is set on forwarded requests so the upstream can
// correlate without re-resolving the binding.
const SandboxIDHeader = "X-Sandbox-ID"

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.metrics.Requests++
	p.mu.Unlock()
	bindingID, status := p.bindingFor(r)
	if bindingID == "" {
		if status == http.StatusNotFound {
			http.Error(w, "unknown endpoint name", status)
		} else {
			http.Error(w, "missing "+p.cfg.BindingHeader, http.StatusBadRequest)
		}
		return
	}
	now := p.cfg.Now()

	p.mu.Lock()
	if until, ok := p.negative[bindingID]; ok && now.Before(until) {
		p.metrics.NegativeHits++
		p.mu.Unlock()
		http.Error(w, "sandbox resume recently failed", http.StatusServiceUnavailable)
		return
	}
	if until, ok := p.live[bindingID]; ok && now.Before(until) {
		p.metrics.PassThrough++
		p.mu.Unlock()
		p.forwardCached(w, r, bindingID)
		return
	}
	p.mu.Unlock()

	dec := p.route(bindingID)
	if !dec.Allowed {
		if !resumable(dec) {
			http.Error(w, "route denied: "+dec.Reason, http.StatusForbidden)
			return
		}
		var err error
		dec, err = p.resumeAndReroute(bindingID, dec.SandboxID)
		if err != nil {
			p.failResume(bindingID, dec.SandboxID, err)
			status := http.StatusServiceUnavailable
			if err == errResumeTimeout {
				status = http.StatusGatewayTimeout
			}
			http.Error(w, "sandbox resume: "+err.Error(), status)
			return
		}
	}
	p.mu.Lock()
	p.live[bindingID] = p.cfg.Now().Add(p.cfg.CacheTTL)
	p.cachedTarget[bindingID] = target{sandboxID: dec.SandboxID, port: dec.Port}
	p.mu.Unlock()
	p.forward(w, r, bindingID, dec)
}

// bindingFor identifies the request's endpoint binding: the explicit
// header wins; otherwise a Host of "<logical-name>.<EndpointDomain>"
// resolves through LookupBinding (positive resolutions cached for
// CacheTTL). Returns ("", status) on failure: 404 for an unknown name
// (fail-closed, matching the gateway's "unknown binding" deny), 400 when
// neither identification is present.
func (p *Proxy) bindingFor(r *http.Request) (string, int) {
	if id := r.Header.Get(p.cfg.BindingHeader); id != "" {
		return id, 0
	}
	name, ok := p.hostLogicalName(r.Host)
	if !ok {
		return "", http.StatusBadRequest
	}
	now := p.cfg.Now()
	p.mu.Lock()
	if e, hit := p.resolved[name]; hit && now.Before(e.until) {
		p.mu.Unlock()
		return e.bindingID, 0
	}
	p.metrics.NameResolutions++
	p.mu.Unlock()
	id, found := p.cfg.LookupBinding(name)
	if !found {
		p.mu.Lock()
		p.metrics.UnknownNames++
		p.mu.Unlock()
		return "", http.StatusNotFound
	}
	p.mu.Lock()
	p.resolved[name] = resolvedName{bindingID: id, until: now.Add(p.cfg.CacheTTL)}
	p.mu.Unlock()
	return id, 0
}

// hostLogicalName extracts the leftmost label when hostport is
// "<logical-name>.<EndpointDomain>"; anything else (including deeper
// subdomains) is not an endpoint hostname.
func (p *Proxy) hostLogicalName(hostport string) (string, bool) {
	if p.cfg.EndpointDomain == "" || p.cfg.LookupBinding == nil {
		return "", false
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	suffix := "." + strings.ToLower(p.cfg.EndpointDomain)
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	name := strings.TrimSuffix(host, suffix)
	if name == "" || strings.Contains(name, ".") {
		return "", false
	}
	return name, true
}

// route wraps Router.Route with metrics.
func (p *Proxy) route(bindingID string) network.RouteDecision {
	p.mu.Lock()
	p.metrics.RouteLookups++
	p.mu.Unlock()
	return p.cfg.Router.Route(bindingID)
}

// resumable reports whether a deny verdict means "suspended, worth a
// resume" as opposed to a hard fail-closed deny (ADR-007: only traffic to
// a not-live sandbox may trigger materialization).
func resumable(dec network.RouteDecision) bool {
	return strings.Contains(dec.Reason, "sandbox not live") ||
		strings.Contains(dec.Reason, "SUSPENDED")
}

var errResumeTimeout = fmt.Errorf("resume wait timed out")

// resumeAndReroute joins (or starts) the single resume flight for
// sandboxID, waits up to ResumeTimeout, then re-routes the binding.
func (p *Proxy) resumeAndReroute(bindingID, sandboxID string) (network.RouteDecision, error) {
	p.mu.Lock()
	f, ok := p.flights[sandboxID]
	if ok {
		p.metrics.ResumeShared++
		p.mu.Unlock()
	} else {
		f = &flight{done: make(chan struct{})}
		p.flights[sandboxID] = f
		p.metrics.ResumeTriggered++
		p.mu.Unlock()
		p.audit("resume_trigger", sandboxID, fmt.Sprintf("binding %s", bindingID))
		go p.runFlight(sandboxID, f)
	}
	timer := time.NewTimer(p.cfg.ResumeTimeout)
	defer timer.Stop()
	select {
	case <-f.done:
	case <-timer.C:
		p.mu.Lock()
		p.metrics.ResumeTimeouts++
		p.mu.Unlock()
		return network.RouteDecision{}, errResumeTimeout
	}
	if f.err != nil {
		return network.RouteDecision{SandboxID: sandboxID}, f.err
	}
	p.mu.Lock()
	p.metrics.ResumeSucceeded++
	p.mu.Unlock()
	dec := p.route(bindingID)
	if !dec.Allowed {
		return dec, fmt.Errorf("still unroutable after resume: %s", dec.Reason)
	}
	return dec, nil
}

// runFlight performs the bounded resume attempts and publishes the result.
func (p *Proxy) runFlight(sandboxID string, f *flight) {
	var err error
	for attempt := 1; attempt <= p.cfg.MaxResumeAttempts; attempt++ {
		if err = p.cfg.Resume(sandboxID); err == nil {
			break
		}
	}
	p.mu.Lock()
	f.err = err
	delete(p.flights, sandboxID)
	if err != nil {
		p.metrics.ResumeFailed++
	}
	p.mu.Unlock()
	close(f.done)
}

// failResume records a resume failure: negative-cache the binding so
// follow-up traffic fails fast without touching the control plane.
func (p *Proxy) failResume(bindingID, sandboxID string, err error) {
	if err != errResumeTimeout {
		p.mu.Lock()
		p.negative[bindingID] = p.cfg.Now().Add(p.cfg.NegativeTTL)
		p.mu.Unlock()
		p.audit("resume_failed", sandboxID, fmt.Sprintf("binding %s: %v", bindingID, err))
	}
}

// forward proxies the request to the resolved upstream of a live route.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, bindingID string, dec network.RouteDecision) {
	addr, err := p.cfg.Upstream(dec.SandboxID, dec.Port)
	if err != nil {
		p.mu.Lock()
		p.metrics.UpstreamErrors++
		p.mu.Unlock()
		http.Error(w, "upstream resolve: "+err.Error(), http.StatusBadGateway)
		return
	}
	r.Header.Set(SandboxIDHeader, dec.SandboxID)
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = addr
			req.Host = r.Host
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			// A cached-live sandbox that died within the TTL window fails
			// here: drop the cache entry so the NEXT request re-routes.
			p.mu.Lock()
			p.metrics.UpstreamErrors++
			delete(p.live, bindingID)
			delete(p.cachedTarget, bindingID)
			p.mu.Unlock()
			http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// forwardCached re-resolves the upstream for a cache-hit binding. The
// cache deliberately stores the sandbox/port (set at route time), not the
// address, so an upstream re-resolution stays possible per request.
func (p *Proxy) forwardCached(w http.ResponseWriter, r *http.Request, bindingID string) {
	p.mu.Lock()
	t, ok := p.cachedTarget[bindingID]
	p.mu.Unlock()
	if !ok {
		// Cache entry lost (evicted by an upstream error); re-route.
		http.Error(w, "endpoint cache invalidated", http.StatusServiceUnavailable)
		return
	}
	p.forward(w, r, bindingID, network.RouteDecision{Allowed: true, SandboxID: t.sandboxID, Port: t.port})
}

func (p *Proxy) audit(kind, subject, detail string) {
	if p.cfg.Audit != nil {
		p.cfg.Audit.Record(kind, subject, detail, p.cfg.Now())
	}
}
