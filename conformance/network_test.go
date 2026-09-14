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
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	credentialbroker "github.com/agent-sandbox/platform/credential-broker"
	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/network"
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
