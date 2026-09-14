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
