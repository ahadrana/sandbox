package sandboxlab

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/agent-sandbox/platform/api"
	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/runtime/backend-interface"
	fakebackend "github.com/agent-sandbox/platform/runtime/fake-backend"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
)

// The meta-tests in this file are the phase-3 gate: an invariant engine
// that cannot catch a PLANTED violation is theater. Each test injects a
// fault or doctors observable state and asserts the correct checker fires
// with the correct invariant ID.

func violationsFor(rep Report, id string) []Violation {
	for _, e := range rep.Entries {
		if e.ID == id {
			return e.Failures
		}
	}
	return nil
}

// (a) Double-registration / fencing breach: a sandbox's incarnation is
// re-created directly on a second host, bypassing the fleet's fenced
// placement. The fleet still believes host-1 owns it; host-2 now runs
// compute the fleet never placed. The ownership/accounting checker
// (INV-013, covering INV-016's "no unowned compute") must catch it.
func TestEngineCatchesDoubleRegisteredIncarnation(t *testing.T) {
	sf := New(Config{Seed: 1, Hosts: hostSpecs(2, 4, 1<<20, factsA, Latencies{})})
	sb, err := sf.Mgr.CreateSandbox(api.CreateSandboxRequest{Version: api.SchemaVersionV1, TenantID: "t1", TaskRef: "victim"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sf.Mgr.Materialize(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	info, _ := sf.Mgr.GetSandbox(sb.SandboxID)
	incID := *info.RuntimeIncarnationID

	other := "host-2"
	if h, _ := sf.Mgr.HostOf(sb.SandboxID); h == "host-2" {
		other = "host-1"
	}
	// Plant: steal the incarnation onto the peer behind the fleet's back.
	ws, gen := info.WorkspaceID, info.WorkspaceGeneration
	if _, err := sf.Hosts[other].HostAgent.Create(hostagent.CreateRequest{
		SandboxID: sb.SandboxID, IncarnationID: incID, Fence: 1, Epoch: 1,
		WorkspaceID: ws, WorkspaceGeneration: gen, MemoryBytes: 128,
	}); err != nil {
		t.Fatalf("plant failed: %v", err)
	}

	rep := sf.InvariantReport()
	viol := violationsFor(rep, "INV-013")
	if len(viol) == 0 {
		t.Fatalf("engine missed a double-registered incarnation:\n%s", rep)
	}
	found := false
	for _, v := range viol {
		if strings.Contains(v.Detail, "double-registered") || strings.Contains(v.Detail, "fleet-invisible") {
			found = true
		}
	}
	if !found {
		t.Fatalf("INV-013 fired but not for the plant: %+v", viol)
	}
	// The violation is a typed trace event too (phase-5 rendering seam).
	var inTrace bool
	for _, line := range sf.Kernel.Trace() {
		if strings.Contains(line, "INVARIANT_VIOLATION INV-013") {
			inTrace = true
		}
	}
	if !inTrace {
		t.Fatal("violation not recorded as a trace event")
	}
}

// (b) Dropped reset event: run the real host-loss → workspace-only fallback
// flow (which emits ExecutionStateReset correctly), then replay a DOCTORED
// event stream — reset events filtered out — through a fresh engine. The
// INV-008 checker must fire: continuation after loss with no reset.
func TestEngineCatchesDroppedResetEvent(t *testing.T) {
	sf := New(Config{Seed: 3, Hosts: hostSpecs(2, 10, 1<<20, factsA, Latencies{}), TickCadence: 100 * time.Millisecond})
	sb, err := sf.Mgr.CreateSandbox(api.CreateSandboxRequest{Version: api.SchemaVersionV1, TenantID: "t1", TaskRef: "doomed"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sf.Mgr.Materialize(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	// Runtime lost while RUNNING (SandboxFailed), then rematerialized from
	// the durable workspace — the real stream emits ExecutionStateReset
	// before the SandboxMaterialized continuation.
	if err := sf.Mgr.KillRuntime(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := sf.Mgr.Materialize(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	// Sanity: the REAL stream passes INV-008.
	if viol := violationsFor(sf.InvariantReport(), "INV-008"); len(viol) != 0 {
		t.Fatalf("real stream flagged: %+v", viol)
	}

	// Doctor: drop every ExecutionStateReset event.
	raw, _ := sf.Outbox.Replay(0)
	var doctored []domain.Event
	for _, ev := range raw {
		if ev.EventType == domain.EventExecutionStateReset {
			continue
		}
		doctored = append(doctored, ev)
	}
	sf2 := New(Config{Seed: 99, Hosts: hostSpecs(1, 2, 1<<20, factsA, Latencies{})})
	sf2.Engine.Feed(doctored)
	rep := sf2.InvariantReport()
	viol := violationsFor(rep, "INV-008")
	if len(viol) == 0 {
		t.Fatalf("engine missed a dropped reset event:\n%s", rep)
	}
	if !strings.Contains(viol[0].Detail, sb.SandboxID) {
		t.Fatalf("INV-008 violation does not name the victim sandbox: %+v", viol[0])
	}
}

// (c) Oversubscribed host: plant a host that rebooted and re-adopted three
// live incarnations into a one-slot capacity (hostagent.New's adoption path
// charges capacity without enforcing it — crash recovery of an
// overcommitted host). The INV-013/016 accounting checker must flag the
// oversubscription.
func TestEngineCatchesOversubscribedHost(t *testing.T) {
	sf := New(Config{Seed: 5, Hosts: hostSpecs(1, 4, 1<<20, factsA, Latencies{})})

	// Plant: a backend already running 3 incarnations, adopted by a host
	// agent with 1 slot.
	b := fakebackend.New()
	for i := 0; i < 3; i++ {
		if _, err := b.Create(backendinterface.Spec{
			SandboxID: fmt.Sprintf("rogue-%d", i), IncarnationID: fmt.Sprintf("rogue-inc-%d", i),
			MemoryBytes: 128,
		}); err != nil {
			t.Fatal(err)
		}
	}
	caps := b.Capabilities()
	caps.CheckpointReclaimsMemory = true
	agent := hostagent.New("host-rogue", capsBackend{b, caps}, nil, sf.WS, 1<<20, 1, 64)
	// Not registered with the fleet (registration would scrub the orphans);
	// the engine observes host accounting directly.
	sf.Hosts["host-rogue"] = &SimHost{HostAgent: agent, k: sf.Kernel, facts: factsA, Restores: map[string]int{}}

	rep := sf.InvariantReport()
	viol := violationsFor(rep, "INV-013")
	if len(viol) == 0 {
		t.Fatalf("engine missed the overcommitted host:\n%s", rep)
	}
	found := false
	for _, v := range viol {
		if strings.Contains(v.Detail, "oversubscribed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("INV-013 fired but not for oversubscription: %+v", viol)
	}
}

// TestInvariantCoverage: a rich scenario (dormant population, execs with
// idempotency keys, commits, a binding, suspend/resume continuity, host
// loss with fallback) must leave almost every continuous checker EXERCISED
// — an engine whose checkers never see evidence is also theater.
func TestInvariantCoverage(t *testing.T) {
	sf := New(Config{Seed: 21, Hosts: hostSpecs(2, 8, 1<<20, factsA, Latencies{}), TickCadence: 100 * time.Millisecond})

	// 40 dormant sandboxes (INV-002, INV-029: dormant ≫ live).
	for i := 0; i < 40; i++ {
		if _, err := sf.Mgr.CreateSandbox(api.CreateSandboxRequest{Version: api.SchemaVersionV1, TenantID: "t1", TaskRef: "dormant"}); err != nil {
			t.Fatal(err)
		}
	}
	// Two live: one exercises exec/commit/binding/suspend/resume; the other
	// loses its host and rematerializes (INV-001/008/009).
	mk := func(task string) string {
		sb, err := sf.Mgr.CreateSandbox(api.CreateSandboxRequest{Version: api.SchemaVersionV1, TenantID: "t1", TaskRef: task})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sf.Mgr.Materialize(sb.SandboxID); err != nil {
			t.Fatal(err)
		}
		return sb.SandboxID
	}
	a, b := mk("live-a"), mk("live-b")

	if _, err := sf.Mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
		SandboxID: a, TenantID: "t1", TargetPort: 8080, LogicalName: "web", TTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	ex, err := sf.Mgr.StartExecution(api.StartExecutionRequest{
		Version: api.SchemaVersionV1, SandboxID: a, TenantID: "t1", PrincipalID: "p1",
		IdempotencyKey: "key-1", Operation: domain.Operation{Command: "true", Writes: map[string]string{"/f": "x"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sf.Mgr.CompleteExecution(ex.ExecutionID); err != nil {
		t.Fatal(err)
	}
	if err := sf.Mgr.Suspend(a); err != nil {
		t.Fatal(err)
	}
	if _, err := sf.Mgr.Resume(a); err != nil {
		t.Fatal(err)
	}

	hostB, _ := sf.Mgr.HostOf(b)
	sf.KillHost(hostB)
	sf.Kernel.RunUntil(10 * time.Second)
	if _, err := sf.Mgr.Materialize(b); err != nil {
		t.Fatal(err)
	}

	rep := assertClean(t, sf)
	_, _, notExercised, _ := rep.Counts()
	for _, e := range rep.Entries {
		if e.Status == StatusNotExercised {
			t.Logf("not exercised: %s %s", e.ID, e.Title)
		}
	}
	// INV-012 (quiescence) needs a background-class sandbox; everything else
	// continuous or scenario-asserted must have seen evidence.
	if notExercised > 1 {
		t.Fatalf("coverage too thin: %d not-exercised:\n%s", notExercised, rep)
	}
}
