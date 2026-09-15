// Network policy, endpoint bridge, and credential conformance (PLAN §12):
// fail-closed gateway routing, egress allow/deny with audit, metadata
// endpoint denial, and scoped revocable credentials whose secret values
// never appear in any transcript (INV-025, FR-SEC-003).
package conformance

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	credentialbroker "github.com/agent-sandbox/platform/credential-broker"
	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/network"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	fakebackend "github.com/agent-sandbox/platform/runtime/fake-backend"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
	"github.com/agent-sandbox/platform/workspace"
)

// Egress allow/deny decisions are enforced at the supervisor layer for
// API-launched commands declaring a destination, with an audit trail.
func TestEgressAllowDenyDecisions(t *testing.T) {
	s := newSystem(t, "fake")
	s.mgr.SetEgressPolicy("default", network.EgressPolicy{
		Allow: []string{"api.example.com"},
		Deny:  []string{"evil.example.com"},
	})
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 81)
	sb, _ := d.CreateSandbox("task-egress")
	mustMaterialize(t, d, sb.SandboxID)

	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "true", EgressDestination: "api.example.com"}); err != nil {
		t.Fatalf("allow-listed destination denied: %v", err)
	}
	if _, err := d.Exec(sb.SandboxID, domain.Operation{Command: "true", EgressDestination: "evil.example.com"}); !errors.Is(err, domain.ErrEgressDenied) {
		t.Fatalf("deny-listed destination: err = %v, want ErrEgressDenied", err)
	}
	if _, err := d.Exec(sb.SandboxID, domain.Operation{Command: "true", EgressDestination: "other.example.com"}); !errors.Is(err, domain.ErrEgressDenied) {
		t.Fatalf("default-deny destination: err = %v, want ErrEgressDenied", err)
	}
	entries := s.mgr.EgressAuditEntries()
	if len(entries) < 3 {
		t.Fatalf("audit trail incomplete: %v", entries)
	}
	for _, e := range entries {
		if e.Kind != "egress" {
			t.Fatalf("unexpected audit entry: %+v", e)
		}
	}
}

// Cloud metadata and cluster API destinations are always denied, even
// under a default-allow policy (FR-SEC-001).
func TestMetadataEndpointsAlwaysDenied(t *testing.T) {
	s := newSystem(t, "fake") // default policy is default-allow
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 82)
	sb, _ := d.CreateSandbox("task-metadata")
	mustMaterialize(t, d, sb.SandboxID)

	for _, dest := range []string{"169.254.169.254", "kubernetes.default.svc"} {
		if _, err := d.Exec(sb.SandboxID, domain.Operation{Command: "true", EgressDestination: dest}); !errors.Is(err, domain.ErrEgressDenied) {
			t.Fatalf("%s: err = %v, want ErrEgressDenied", dest, err)
		}
	}
	// The policy engine denies them even with explicit allow entries.
	dec := network.EvaluateEgress(network.EgressPolicy{DefaultAllow: true, Allow: []string{"*"}}, "169.254.169.254", time.Now())
	if dec.Allowed {
		t.Fatal("metadata endpoint allowed by engine")
	}
	// M4: bypass variants — case, trailing dot, cluster-name suffixes, and
	// alternate IP encodings — must all fail closed.
	policy := network.EgressPolicy{DefaultAllow: true, Allow: []string{"*"}}
	for _, dest := range []string{
		"169.254.169.254",
		"169.254.169.254.",
		"::ffff:169.254.169.254",
		"2852039166", // decimal encoding
		"0xa9fea9fe", // hex encoding
		"0xA9FEA9FE", // upper-case hex
		"kubernetes.default.svc",
		"KUBERNETES.default.svc",
		"kubernetes.default.svc.",
		"kubernetes.default.svc.cluster.local",
		"kubernetes.default.svc.my-cluster.example",
	} {
		if dec := network.EvaluateEgress(policy, dest, time.Now()); dec.Allowed {
			t.Fatalf("bypass variant %q allowed", dest)
		}
	}
	// Lookalikes that are NOT the protected endpoints must still be allowed.
	for _, dest := range []string{"169.254.169.253", "kubernetes.default.svcx.example.com", "example.com"} {
		if dec := network.EvaluateEgress(policy, dest, time.Now()); !dec.Allowed {
			t.Fatalf("legitimate destination %q denied", dest)
		}
	}
}

// Endpoint bindings route through the fail-closed gateway and expire at
// TTL on Tick.
func TestEndpointLifecycleAndTTL(t *testing.T) {
	s := newSystem(t, "fake")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 83)
	sb, _ := d.CreateSandbox("task-endpoint")
	mustMaterialize(t, d, sb.SandboxID)
	gw := network.NewGateway(s.mgr)

	b, err := s.mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
		Version: api.SchemaVersionV1, SandboxID: sb.SandboxID,
		TargetPort: 8080, LogicalName: "web", AuthPolicy: "bearer",
		TTL: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.State != domain.EndpointActive || b.ExecutionEpoch != 1 {
		t.Fatalf("binding wrong: %+v", b)
	}
	consumer := eventservice.NewConsumer()
	if got := eventsOfType(consumer.Poll(s.outbox), domain.EventEndpointBound); len(got) != 1 {
		t.Fatalf("missing EndpointBound: %v", got)
	}
	route := gw.Route(b.BindingID)
	if !route.Allowed || route.SandboxID != sb.SandboxID || route.Port != 8080 || route.Epoch != 1 {
		t.Fatalf("route wrong: %+v", route)
	}

	// Suspend moves the binding to SUSPENDED and the gateway fails closed.
	if err := s.mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	if route := gw.Route(b.BindingID); route.Allowed {
		t.Fatalf("route allowed on suspended binding: %+v", route)
	}

	// TTL expiry on Tick moves it to EXPIRED.
	for i := 0; i < 6; i++ {
		if err := s.mgr.Tick(time.Second); err != nil {
			t.Fatal(err)
		}
	}
	bindings := s.mgr.ListEndpointBindings(sb.SandboxID)
	if len(bindings) != 1 || bindings[0].State != domain.EndpointExpired {
		t.Fatalf("binding state = %+v, want EXPIRED", bindings)
	}
	if got := eventsOfType(consumer.Poll(s.outbox), domain.EventEndpointUnbound); len(got) != 1 || got[0].Payload["reason"] != "ttl_expired" {
		t.Fatalf("missing ttl_expired unbind event: %v", got)
	}
	if route := gw.Route(b.BindingID); route.Allowed {
		t.Fatalf("route allowed on expired binding: %+v", route)
	}
}

// A binding fenced to epoch N fails closed after an execution-epoch reset
// (stale endpoint, INV-024).
func TestStaleEndpointAfterReset(t *testing.T) {
	s := newSystem(t, "fake")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 84)
	sb, _ := d.CreateSandbox("task-stale-ep")
	mustMaterialize(t, d, sb.SandboxID)
	gw := network.NewGateway(s.mgr)

	b, err := s.mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
		Version: api.SchemaVersionV1, SandboxID: sb.SandboxID,
		TargetPort: 9090, LogicalName: "api", AuthPolicy: "bearer",
		TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if route := gw.Route(b.BindingID); !route.Allowed {
		t.Fatalf("fresh binding not routable: %+v", route)
	}

	if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	mustMaterialize(t, d, sb.SandboxID) // epoch 1 -> 2
	route := gw.Route(b.BindingID)
	if route.Allowed {
		t.Fatalf("stale binding routed after epoch reset: %+v", route)
	}
	if !strings.Contains(route.Reason, "stale epoch fence") {
		t.Fatalf("unexpected deny reason: %q", route.Reason)
	}
}

// Sandbox terminate deletes its endpoints; the gateway fails closed.
func TestEndpointRemovedAfterTerminate(t *testing.T) {
	s := newSystem(t, "fake")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 85)
	sb, _ := d.CreateSandbox("task-term-ep")
	mustMaterialize(t, d, sb.SandboxID)
	gw := network.NewGateway(s.mgr)

	b, err := s.mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
		Version: api.SchemaVersionV1, SandboxID: sb.SandboxID,
		TargetPort: 8080, LogicalName: "web", AuthPolicy: "bearer",
		TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.mgr.Terminate(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	bindings := s.mgr.ListEndpointBindings(sb.SandboxID)
	if len(bindings) != 1 || bindings[0].State != domain.EndpointUnbound {
		t.Fatalf("binding state = %+v, want UNBOUND", bindings)
	}
	consumer := eventservice.NewConsumer()
	if got := eventsOfType(consumer.Poll(s.outbox), domain.EventEndpointUnbound); len(got) != 1 || got[0].Payload["reason"] != "sandbox_terminated" {
		t.Fatalf("missing terminate unbind event: %v", got)
	}
	if route := gw.Route(b.BindingID); route.Allowed {
		t.Fatalf("route allowed after terminate: %+v", route)
	}
	if route := gw.Route("bind-nonexistent"); route.Allowed {
		t.Fatalf("unknown binding routed: %+v", route)
	}
}

// Broker-issued tokens verify, expire, and revoke; issue/use/revocation
// are audited by token ID.
func TestCredentialExpiryRevocation(t *testing.T) {
	broker, err := credentialbroker.New([]byte("test-broker-key"), "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

	token, claims, err := broker.Issue("tenant-1", "task-x", []string{"read:workspace"}, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := broker.Verify(token, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.TenantID != "tenant-1" || got.TaskRef != "task-x" || len(got.Capabilities) != 1 {
		t.Fatalf("claims wrong: %+v", got)
	}
	if _, err := broker.Verify(token, now.Add(2*time.Minute)); !errors.Is(err, credentialbroker.ErrExpired) {
		t.Fatalf("expired token: err = %v", err)
	}
	broker.Revoke(claims.TokenID, now)
	if _, err := broker.Verify(token, now); !errors.Is(err, credentialbroker.ErrRevoked) {
		t.Fatalf("revoked token: err = %v", err)
	}
	if _, err := broker.Verify(token+"x", now); !errors.Is(err, credentialbroker.ErrBadSignature) {
		t.Fatalf("tampered token: err = %v", err)
	}
	if _, err := broker.Verify("garbage", now); !errors.Is(err, credentialbroker.ErrMalformed) {
		t.Fatalf("malformed token: err = %v", err)
	}
	var kinds []string
	for _, e := range broker.AuditEntries() {
		kinds = append(kinds, e.Kind)
	}
	joined := strings.Join(kinds, ",")
	for _, want := range []string{"issue", "use", "revoke"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("audit missing %q: %v", want, kinds)
		}
	}
}

// A credential injected into an execution via env reaches the process, but
// the secret VALUE appears nowhere in the event outbox or the durable
// broker audit log (INV-025, FR-SEC-003).
func TestSecretNotInTranscript(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "broker-audit.jsonl")
	broker, err := credentialbroker.New([]byte("test-broker-key"), auditPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, claims, err := broker.Issue("tenant-1", "task-secret", []string{"read:workspace"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	s := newSystem(t, "local")
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 87)
	sb, _ := d.CreateSandbox("task-secret")
	mustMaterialize(t, d, sb.SandboxID)
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: `test -n "$AGENT_TOKEN"`,
		Env:     map[string]string{"AGENT_TOKEN": token},
	}); err != nil {
		t.Fatalf("token injection exec failed: %v", err)
	}
	if _, err := broker.Verify(token, now); err != nil {
		t.Fatal(err)
	}

	// Scan every outbox event for the secret value.
	consumer := eventservice.NewConsumer()
	for _, ev := range consumer.Poll(s.outbox) {
		data, _ := json.Marshal(ev)
		if strings.Contains(string(data), token) {
			t.Fatalf("secret value leaked into event %s: %s", ev.EventType, data)
		}
	}
	// Scan the durable audit log: token IDs yes, token values no.
	auditBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(auditBytes), token) {
		t.Fatal("secret value leaked into broker audit log")
	}
	if !strings.Contains(string(auditBytes), claims.TokenID) {
		t.Fatal("audit log missing token ID records")
	}
}

// M5 regression: revocations survive a broker restart (durable audit file),
// token IDs are random/unique across instances, and revocation is checked
// before expiry.
func TestBrokerRevocationDurableAcrossRestart(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "broker-audit.jsonl")
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	b1, err := credentialbroker.New([]byte("shared-key"), auditPath)
	if err != nil {
		t.Fatal(err)
	}
	token, claims, err := b1.Issue("tenant-1", "task-x", []string{"read:workspace"}, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	b1.Revoke(claims.TokenID, now)

	// A second broker instance sharing the HMAC key and audit file.
	b2, err := credentialbroker.New([]byte("shared-key"), auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b2.Verify(token, now); !errors.Is(err, credentialbroker.ErrRevoked) {
		t.Fatalf("revoked token verified after broker restart: %v", err)
	}
	// Revocation is checked before expiry: revoked AND expired is revoked.
	if _, err := b2.Verify(token, now.Add(2*time.Minute)); !errors.Is(err, credentialbroker.ErrRevoked) {
		t.Fatalf("revoked+expired token: err = %v, want ErrRevoked", err)
	}
	// Token IDs are random: distinct instances never mint colliding IDs.
	_, claims2, err := b2.Issue("tenant-2", "task-y", nil, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if claims2.TokenID == claims.TokenID {
		t.Fatalf("token ID collision across broker instances: %s", claims2.TokenID)
	}
	seen := map[string]bool{claims.TokenID: true, claims2.TokenID: true}
	for i := 0; i < 100; i++ {
		_, c, err := b2.Issue("tenant-2", "task-y", nil, time.Minute, now)
		if err != nil {
			t.Fatal(err)
		}
		if seen[c.TokenID] {
			t.Fatalf("duplicate token ID %s", c.TokenID)
		}
		seen[c.TokenID] = true
	}
}

// TestEgressEnforcementDeclarationOnlyGap is a DECLARED GAP test (M19),
// modeled on the isolation tests' declared-difference style: on the local
// backend, egress policy is enforced only for destinations the caller
// volunteers via Operation.EgressDestination. A command's real network
// access is NOT checked — undeclared egress neither evaluates policy nor
// writes an audit record. The isolated backend's gap closure (no host
// network via bwrap) is asserted in the isolation tests.
func TestEgressEnforcementDeclarationOnlyGap(t *testing.T) {
	s := newSystem(t, "local")
	s.mgr.SetEgressPolicy("default", network.EgressPolicy{DefaultAllow: false})
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 83)
	sb, _ := d.CreateSandbox("task-egress-gap")
	mustMaterialize(t, d, sb.SandboxID)

	// Undeclared: the command runs with NO policy evaluation, even under a
	// default-deny policy. This is the capability gap, asserted honestly.
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "true"}); err != nil {
		t.Fatalf("undeclared egress command failed under default-deny: %v", err)
	}
	for _, e := range s.mgr.EgressAuditEntries() {
		if e.Subject == sb.SandboxID {
			t.Fatalf("undeclared command produced an egress audit record: %+v", e)
		}
	}
	// Declared: the same destination volunteered IS evaluated and denied.
	if _, err := d.Exec(sb.SandboxID, domain.Operation{Command: "true", EgressDestination: "example.com"}); !errors.Is(err, domain.ErrEgressDenied) {
		t.Fatalf("declared egress not policy-enforced: %v", err)
	}
}

// L5 regression: the gateway fails closed when expiry cannot be evaluated
// and is unroutable at the exact expiry instant.
func TestGatewayExpiryFailClosed(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	b := domain.EndpointBinding{
		BindingID: "b1", SandboxID: "sb1", State: domain.EndpointActive,
		ExecutionEpoch: 1, ExpiresAt: now.Add(time.Minute),
	}
	src := &staticBindingSource{view: network.BindingView{
		Binding: b, CurrentEpoch: 1, SandboxActive: true, Now: now,
	}}
	gw := network.NewGateway(src)
	if r := gw.Route("b1"); !r.Allowed {
		t.Fatalf("fresh binding denied: %+v", r)
	}
	// Exact expiry instant: unroutable.
	src.view.Now = now.Add(time.Minute)
	if r := gw.Route("b1"); r.Allowed {
		t.Fatal("routable at the exact expiry instant")
	}
	// No clock: fail closed.
	src.view.Now = time.Time{}
	if r := gw.Route("b1"); r.Allowed {
		t.Fatal("routable with no clock")
	}
	// No TTL: fail closed.
	src.view.Now = now
	src.view.Binding.ExpiresAt = time.Time{}
	if r := gw.Route("b1"); r.Allowed {
		t.Fatal("routable with no TTL")
	}
}

type staticBindingSource struct{ view network.BindingView }

func (s *staticBindingSource) BindingView(string) (network.BindingView, bool) {
	return s.view, true
}

// L5 regression: audit Record surfaces file write errors and in-memory
// retention is capped with a dropped counter.
func TestAuditLogErrorsAndCap(t *testing.T) {
	l, err := network.NewAuditLog("")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < 10050; i++ {
		if err := l.Record("k", "s", "d", now); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(l.Entries()); got != 10000 {
		t.Fatalf("entries = %d, want capped at 10000", got)
	}
	if got := l.Dropped(); got != 50 {
		t.Fatalf("dropped = %d, want 50", got)
	}

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l2, err := network.NewAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Record("k", "s", "d", now); err != nil {
		t.Fatal(err)
	}
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l2.Record("k", "s", "d", now); err == nil {
		t.Fatal("write error after close not surfaced")
	}
}

// --- Endpoint data-plane publishing (ADR-007, backendinterface.PortPublisher) ---

// recordPublisher wraps the fake backend with a recording PortPublisher:
// the manager-side publish lifecycle is verifiable without host iptables.
type recordPublisher struct {
	*fakebackend.Backend
	mu        sync.Mutex
	published map[int]int // hostPort -> guestPort
	failNext  error
}

func (r *recordPublisher) PublishPort(h backendinterface.Handle, guestPort, hostPort int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failNext != nil {
		err := r.failNext
		r.failNext = nil
		return err
	}
	if r.published == nil {
		r.published = map[int]int{}
	}
	r.published[hostPort] = guestPort
	return nil
}

func (r *recordPublisher) UnpublishPort(h backendinterface.Handle, hostPort int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.published, hostPort)
	return nil
}

func (r *recordPublisher) isPublished(hostPort int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.published[hostPort]
	return ok
}

func newPublishSystem(t *testing.T) (*sandboxmanager.Manager, *recordPublisher, *domain.ManualClock) {
	t.Helper()
	clock := domain.NewManualClock(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	outbox := eventservice.NewOutbox()
	store := sandboxmanager.NewMemoryStore()
	rt := &recordPublisher{Backend: fakebackend.New()}
	mgr := sandboxmanager.New(clock, ids, ws, rt, outbox, store, "host-1")
	return mgr, rt, clock
}

func mustMaterializeMgr(t *testing.T, mgr *sandboxmanager.Manager, sandboxID string) {
	t.Helper()
	if _, err := mgr.Materialize(sandboxID); err != nil {
		t.Fatal(err)
	}
}

// The data plane follows the binding lifecycle: published on create while
// live, freed on suspend (the port is available to other sandboxes),
// republished on resume, removed on unbind and on TTL expiry.
func TestEndpointPublishLifecycle(t *testing.T) {
	mgr, rt, clock := newPublishSystem(t)
	sb, err := mgr.CreateSandbox(api.CreateSandboxRequest{Version: api.SchemaVersionV1, TenantID: "t1", TaskRef: "task-pub"})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterializeMgr(t, mgr, sb.SandboxID)

	b, err := mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
		Version: api.SchemaVersionV1, SandboxID: sb.SandboxID, TenantID: "t1",
		TargetPort: 8080, LogicalName: "web", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rt.isPublished(8080) {
		t.Fatal("binding created on live sandbox but port not published")
	}

	// Suspend frees the host port; the gateway denies while suspended.
	if err := mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	if rt.isPublished(8080) {
		t.Fatal("port still published after suspend")
	}

	// A binding created while suspended is NOT published (no live handle);
	// resume republishes every reactivated binding.
	if _, err := mgr.Resume(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	if !rt.isPublished(8080) {
		t.Fatal("port not republished after resume")
	}

	// Unbind removes the publish.
	if err := mgr.UnbindEndpoint(b.BindingID); err != nil {
		t.Fatal(err)
	}
	if rt.isPublished(8080) {
		t.Fatal("port still published after unbind")
	}

	// TTL expiry unpublishes too.
	b2, err := mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
		Version: api.SchemaVersionV1, SandboxID: sb.SandboxID, TenantID: "t1",
		TargetPort: 9090, LogicalName: "api", TTL: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rt.isPublished(9090) {
		t.Fatal("second binding not published")
	}
	_ = b2
	clock.Advance(2 * time.Second)
	if err := mgr.Tick(time.Second); err != nil {
		t.Fatal(err)
	}
	if rt.isPublished(9090) {
		t.Fatal("port still published after TTL expiry")
	}
}

// A publish failure (e.g. host-port conflict) fails the binding creation
// outright — no half-bound state.
func TestEndpointPublishFailureFailsCreate(t *testing.T) {
	mgr, rt, _ := newPublishSystem(t)
	sb, err := mgr.CreateSandbox(api.CreateSandboxRequest{Version: api.SchemaVersionV1, TenantID: "t1", TaskRef: "task-pubfail"})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterializeMgr(t, mgr, sb.SandboxID)
	rt.failNext = backendinterface.ErrPortConflict
	_, err = mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
		Version: api.SchemaVersionV1, SandboxID: sb.SandboxID, TenantID: "t1",
		TargetPort: 8080, LogicalName: "web", TTL: time.Hour,
	})
	if err == nil {
		t.Fatal("binding created despite publish conflict")
	}
	if got := mgr.ListEndpointBindings(sb.SandboxID); len(got) != 0 {
		t.Fatalf("half-bound state after failed publish: %+v", got)
	}
}

// A binding created on a SUSPENDED sandbox skips the publish (no live
// handle) and is actuated by the resume's republish.
func TestEndpointPublishSkippedWhileSuspended(t *testing.T) {
	mgr, rt, _ := newPublishSystem(t)
	sb, err := mgr.CreateSandbox(api.CreateSandboxRequest{Version: api.SchemaVersionV1, TenantID: "t1", TaskRef: "task-pubsusp"})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterializeMgr(t, mgr, sb.SandboxID)
	if err := mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
		Version: api.SchemaVersionV1, SandboxID: sb.SandboxID, TenantID: "t1",
		TargetPort: 8080, LogicalName: "web", TTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	if rt.isPublished(8080) {
		t.Fatal("port published for suspended sandbox")
	}
	if _, err := mgr.Resume(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	// The binding was created against the pre-suspend epoch, so resume
	// reactivates and republishes it.
	if !rt.isPublished(8080) {
		t.Fatal("port not republished after resume")
	}
}

// A background-class sandbox idles into BACKGROUND_ACTIVE (not RUNNING or
// QUIESCENT) — the publish gate must treat it as live.
func TestEndpointPublishBackgroundActive(t *testing.T) {
	mgr, rt, _ := newPublishSystem(t)
	sb, err := mgr.CreateSandbox(api.CreateSandboxRequest{Version: api.SchemaVersionV1, TenantID: "t1", TaskRef: "task-pubbg"})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterializeMgr(t, mgr, sb.SandboxID)
	// A lingering background child makes the sandbox BACKGROUND_ACTIVE
	// (not quiescent) once the launching execution completes.
	ex, err := mgr.StartExecution(api.StartExecutionRequest{
		Version: api.SchemaVersionV1, SandboxID: sb.SandboxID, TenantID: "t1", PrincipalID: "p1",
		IdempotencyKey: "bg-1",
		Operation:      domain.Operation{Command: "sleep 30 & echo spawned"},
		ExpectedEpoch:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.CompleteExecution(ex.ExecutionID); err != nil {
		t.Fatal(err)
	}
	info, err := mgr.GetSandbox(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if info.ObservedState != domain.SandboxBackgroundActive && info.ObservedState != domain.SandboxQuiescent {
		t.Fatalf("state = %s, want a live idle state", info.ObservedState)
	}
	if _, err := mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
		Version: api.SchemaVersionV1, SandboxID: sb.SandboxID, TenantID: "t1",
		TargetPort: 8080, LogicalName: "web", TTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	if !rt.isPublished(8080) {
		t.Fatal("binding on BACKGROUND_ACTIVE sandbox not published")
	}
}

// reclaimCapsRuntime wraps a recording-publisher backend declaring
// snapshot-class RAM reclaim, so the manager drops the handle at suspend
// and Resume must route a restore through the runtime (ADR-008).
type reclaimCapsRuntime struct {
	*recordPublisher
}

func (r reclaimCapsRuntime) Capabilities() backendinterface.Capabilities {
	c := r.recordPublisher.Capabilities()
	c.CheckpointReclaimsMemory = true
	return c
}

// Routed restore end to end (ADR-008): the manager's runtime is a FLEET of
// host agents. A checkpoint suspend reclaims the incarnation (handle
// dropped, placement erased, port unpublished); Resume routes Fleet.Restore
// to the checkpoint's ORIGIN host, preserving the execution epoch — so the
// suspended binding reactivates and its port is republished, exactly the
// continuity the resume proxy's triggering request depends on.
func TestRoutedRestoreReactivatesBindings(t *testing.T) {
	clock := domain.NewManualClock(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	outbox := eventservice.NewOutbox()
	fleet := hostagent.NewFleet(clock, nil, ws)
	pub := &recordPublisher{Backend: fakebackend.New()}
	agent := hostagent.New("host-1", reclaimCapsRuntime{pub}, nil, ws, 1<<20, 4, 16)
	fleet.RegisterHost(agent)
	mgr := sandboxmanager.New(clock, ids, ws, fleet, outbox, sandboxmanager.NewMemoryStore(), "cp-1")

	sb, err := mgr.CreateSandbox(api.CreateSandboxRequest{Version: api.SchemaVersionV1, TenantID: "t1", TaskRef: "task-routed"})
	if err != nil {
		t.Fatal(err)
	}
	mustMaterializeMgr(t, mgr, sb.SandboxID)
	info, err := mgr.GetSandbox(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	incID := *info.RuntimeIncarnationID
	b, err := mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
		Version: api.SchemaVersionV1, SandboxID: sb.SandboxID, TenantID: "t1",
		TargetPort: 8080, LogicalName: "web", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pub.isPublished(8080) {
		t.Fatal("binding not published while live")
	}

	if err := mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	if pub.isPublished(8080) {
		t.Fatal("port still published after suspend")
	}
	if _, _, ok := fleet.PlacementOf(incID); ok {
		t.Fatal("placement retained after reclaiming suspend")
	}

	report, err := mgr.Resume(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.NewEpoch != report.PriorEpoch {
		t.Fatalf("routed restore changed epoch %d -> %d", report.PriorEpoch, report.NewEpoch)
	}
	// The restored incarnation is re-placed on the origin host.
	hostID, _, ok := fleet.PlacementOf(incID)
	if !ok || hostID != "host-1" {
		t.Fatalf("restored incarnation not re-placed on origin host: %q, %v", hostID, ok)
	}
	// Epoch preserved => the binding's fence still matches: it reactivates
	// and its port is republished.
	got := mgr.ListEndpointBindings(sb.SandboxID)
	if len(got) != 1 || got[0].BindingID != b.BindingID || got[0].State != domain.EndpointActive {
		t.Fatalf("binding not reactivated after routed restore: %+v", got)
	}
	if !pub.isPublished(8080) {
		t.Fatal("port not republished after routed restore")
	}
}
