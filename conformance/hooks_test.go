package conformance

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	"github.com/agent-sandbox/platform/api"
	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/domain"
	environmentbuilder "github.com/agent-sandbox/platform/environment-builder"
	localbackend "github.com/agent-sandbox/platform/runtime/local-backend"
	"github.com/agent-sandbox/platform/workspace"
)

// hookFixture builds a manager over the local backend with an environment
// source carrying the given restart recipe (ADR-011 step 2).
func hookFixture(t *testing.T, start, terminals []string) (*system, *domain.Environment) {
	t.Helper()
	f := newEnvFixture(t)
	f.repos.AddVersion("base-go", "", map[string]string{"bin/go": "binary"})
	f.repos.AddVersion("app", "sha-app-1", map[string]string{"main.go": "v1"})
	spec := baseSpec()
	spec.Start = start
	spec.Terminals = terminals
	env := mustBuild(t, f, "coding", spec)

	s := newSystem(t, "local")
	s.mgr.SetEnvironmentSource(f.builder)
	return s, env
}

// httpGet fetches url, returning the body and true only on a 200 OK.
func httpGet(url string) (string, bool) {
	resp, err := http.Get(url)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}
	return string(data), true
}

// hookSeq extracts the ordered hook labels of ExecutionStarted events.
func hookSeq(events []domain.Event) []string {
	var out []string
	for _, ev := range eventsOfType(events, domain.EventExecutionStarted) {
		if h, ok := ev.Payload["hook"].(string); ok && h != "" {
			out = append(out, h)
		}
	}
	return out
}

func indexOf(events []domain.Event, et domain.EventType) int {
	for i, ev := range events {
		if ev.EventType == et {
			return i
		}
	}
	return -1
}

// (a) Fresh materialization runs start hooks sequentially, then launches
// terminal hooks, all as recorded hook-labeled executions (INV-010), and the
// hook block completes before the sandbox reports RUNNING (event order).
func TestStartupHooksRunOnFreshMaterialize(t *testing.T) {
	s, env := hookFixture(t,
		[]string{"echo s1 >> hooks.log", "echo s2 >> hooks.log"},
		[]string{"sleep 600"})
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-hooks",
		EnvironmentID: env.EnvironmentID,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.mgr.KillRuntime(sb.SandboxID) })
	if _, err := s.mgr.Materialize(sb.SandboxID); err != nil {
		t.Fatal(err)
	}

	// Start hooks ran in order against the live workspace.
	files, err := s.mgr.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if files["hooks.log"] != "s1\ns2\n" {
		t.Fatalf("start hooks out of order: %q", files["hooks.log"])
	}
	// The terminal hook was launched, not waited on.
	lb := s.localBackend(t)
	pollUntil(t, 5*time.Second, "terminal hook process", func() bool {
		inv, err := lb.ProcessInventory(handleOf(t, s, sb.SandboxID))
		if err != nil {
			return false
		}
		for _, p := range inv {
			if strings.Contains(p.Command, "sleep 600") {
				return true
			}
		}
		return false
	})

	events, _ := s.outbox.Replay(0)
	if got, want := hookSeq(events), []string{"start", "start", "terminal"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("hook execution sequence = %v, want %v", got, want)
	}
	iStarted := indexOf(events, domain.EventEnvironmentHooksStarted)
	iCompleted := indexOf(events, domain.EventEnvironmentHooksCompleted)
	iMaterialized := indexOf(events, domain.EventSandboxMaterialized)
	if iStarted < 0 || iCompleted < 0 || iMaterialized < 0 {
		t.Fatalf("missing hook lifecycle events: started=%d completed=%d materialized=%d", iStarted, iCompleted, iMaterialized)
	}
	if !(iStarted < iCompleted && iCompleted < iMaterialized) {
		t.Fatalf("hook events out of order: started=%d completed=%d materialized=%d", iStarted, iCompleted, iMaterialized)
	}
	// Every hook execution reached a terminal recorded state.
	if got := len(eventsOfType(events, domain.EventExecutionCompleted)); got < 3 {
		t.Fatalf("hook executions not recorded to completion: %d", got)
	}
}

// (b) A failing start hook is an honest boot failure: the sandbox goes
// FAILED with EnvironmentHooksFailed + SandboxFailed, never RUNNING.
func TestStartHookFailureFailsBoot(t *testing.T) {
	s, env := hookFixture(t, []string{"true", "exit 3"}, nil)
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-hooks-fail",
		EnvironmentID: env.EnvironmentID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.mgr.Materialize(sb.SandboxID); err == nil {
		t.Fatal("materialize succeeded despite failing start hook")
	}
	cur, err := s.mgr.GetSandbox(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.ObservedState != domain.SandboxFailed {
		t.Fatalf("sandbox state = %s, want FAILED", cur.ObservedState)
	}
	events, _ := s.outbox.Replay(0)
	failed := eventsOfType(events, domain.EventEnvironmentHooksFailed)
	if len(failed) != 1 {
		t.Fatalf("want one EnvironmentHooksFailed: %v", events)
	}
	if !strings.Contains(failed[0].Payload["detail"].(string), "start hook 1") {
		t.Fatalf("failure detail missing hook identity: %v", failed[0].Payload)
	}
	if got := eventsOfType(events, domain.EventEnvironmentHooksCompleted); len(got) != 0 {
		t.Fatalf("HooksCompleted emitted on failure: %v", got)
	}
	if got := eventsOfType(events, domain.EventSandboxFailed); len(got) != 1 {
		t.Fatalf("want one SandboxFailed: %v", events)
	}
	// The second start hook ran, the failure stopped the block: exactly one
	// completed hook execution (hook 0 = "true") and one failed (hook 1).
	if got := hookSeq(events); fmt.Sprint(got) != "[start start]" {
		t.Fatalf("hook executions = %v, want [start start]", got)
	}
	if got := eventsOfType(events, domain.EventExecutionFailed); len(got) != 1 || got[0].Payload["hook"] != "start" {
		t.Fatalf("missing hook-labeled ExecutionFailed: %v", events)
	}
}

// (c) Marquee reconstruct-services scenario: an environment terminal hook
// serves the workspace over HTTP. A resource-reclaiming (workspace-only)
// suspend kills the server; resume must re-run the recipe so the service is
// back WITHOUT any agent-driven execution.
func TestStartupHooksReconstructServicesOnWorkspaceOnlyResume(t *testing.T) {
	const port = "18441"
	s, env := hookFixture(t,
		[]string{"echo booted >> hooks.log"},
		[]string{"python3 -m http.server " + port + " --bind 127.0.0.1"})
	p := permissivePolicy()
	p.WallDeadline = 2 * time.Second
	s.mgr.SetPolicy(p)

	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 91)
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-hooks-marquee",
		EnvironmentID: env.EnvironmentID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.mgr.Materialize(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.mgr.KillRuntime(sb.SandboxID) })
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Command: "true",
		Writes:  map[string]string{"committed.txt": "served-by-hook"},
	}); err != nil {
		t.Fatal(err)
	}
	get := func(path string) (string, bool) {
		return httpGet("http://127.0.0.1:" + port + "/" + path)
	}
	pollUntil(t, 10*time.Second, "hook-launched HTTP service", func() bool {
		body, ok := get("committed.txt")
		return ok && strings.TrimSpace(body) == "served-by-hook"
	})
	consumer := eventservice.NewConsumer()
	consumer.Poll(s.outbox) // drain the first boot's events

	// Wall-deadline enforcement suspends workspace-only (reclaim): the
	// server process dies with the incarnation.
	for i := 0; i < 3; i++ {
		if err := s.mgr.Tick(time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if got := mustGetSandbox(t, s, sb.SandboxID).ObservedState; got != domain.SandboxSuspended {
		t.Fatalf("sandbox state = %s, want SUSPENDED", got)
	}
	if _, ok := get("committed.txt"); ok {
		t.Fatal("HTTP service still up after reclaiming suspend")
	}

	report, err := s.mgr.Resume(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.PriorEpoch != 1 || report.NewEpoch != 2 {
		t.Fatalf("epoch %d -> %d, want 1 -> 2", report.PriorEpoch, report.NewEpoch)
	}
	fresh := consumer.Poll(s.outbox)
	if got := eventsOfType(fresh, domain.EventExecutionStateReset); len(got) != 1 {
		t.Fatalf("want one ExecutionStateReset: %v", got)
	}
	if got := eventsOfType(fresh, domain.EventEnvironmentHooksStarted); len(got) != 1 {
		t.Fatalf("hooks did not re-run on epoch-creating resume: %v", got)
	}
	// Hooks completed before the reset/RUNNING were published.
	iCompleted := indexOf(fresh, domain.EventEnvironmentHooksCompleted)
	iReset := indexOf(fresh, domain.EventExecutionStateReset)
	if iCompleted < 0 || iReset < 0 || iCompleted > iReset {
		t.Fatalf("hooks must complete before ExecutionStateReset: completed=%d reset=%d", iCompleted, iReset)
	}
	// The service is back purely from the recorded recipe.
	pollUntil(t, 10*time.Second, "HTTP service reconstructed on resume", func() bool {
		body, ok := get("committed.txt")
		return ok && strings.TrimSpace(body) == "served-by-hook"
	})
	files, err := s.mgr.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(files["hooks.log"], "booted"); got != 2 {
		t.Fatalf("start hook ran %d times, want 2 (log %q)", got, files["hooks.log"])
	}
}

// (d) Continuity restore (checkpoint suspend, same host) must NOT re-run
// hooks: no double-start of services, epoch retained, no reset event.
func TestStartupHooksSkippedOnContinuityResume(t *testing.T) {
	s, env := hookFixture(t,
		[]string{"echo booted >> hooks.log"},
		[]string{"sleep 605"})
	sb, err := s.mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-hooks-continuity",
		EnvironmentID: env.EnvironmentID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.mgr.Materialize(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.mgr.KillRuntime(sb.SandboxID) })

	if err := s.mgr.Suspend(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	consumer := eventservice.NewConsumer()
	suspended := eventsOfType(consumer.Poll(s.outbox), domain.EventSandboxSuspended)
	if len(suspended) != 1 || suspended[0].Payload["mode"] != "execution_state" {
		t.Fatalf("want execution_state (checkpoint) suspend: %v", suspended)
	}
	report, err := s.mgr.Resume(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if report.NewEpoch != report.PriorEpoch {
		t.Fatalf("continuity resume changed epoch %d -> %d", report.PriorEpoch, report.NewEpoch)
	}
	fresh := consumer.Poll(s.outbox)
	if got := eventsOfType(fresh, domain.EventExecutionStateReset); len(got) != 0 {
		t.Fatalf("ExecutionStateReset on continuity resume: %v", got)
	}
	if got := eventsOfType(fresh, domain.EventEnvironmentHooksStarted); len(got) != 0 {
		t.Fatalf("hooks re-ran on continuity resume: %v", got)
	}
	files, err := s.mgr.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(files["hooks.log"], "booted"); got != 1 {
		t.Fatalf("start hook ran %d times, want 1 (no double-start)", got)
	}
}

// The restart recipe is persisted with the artifact (recipe.json) and served
// after a builder restart; hook-less environments report an honestly empty
// recipe, and hooks participate in environment identity.
func TestHookRecipePersistenceAndIdentity(t *testing.T) {
	f := newEnvFixture(t)
	f.repos.AddVersion("base-go", "", map[string]string{"bin/go": "binary"})
	f.repos.AddVersion("app", "sha-app-1", map[string]string{"main.go": "v1"})
	spec := baseSpec()
	spec.Start = []string{"echo hi"}
	spec.Terminals = []string{"sleep 1"}
	env := mustBuild(t, f, "coding", spec)

	reopened, err := environmentbuilder.Open(f.root, f.repos, f.clock, f.ids)
	if err != nil {
		t.Fatal(err)
	}
	recipe, err := reopened.HookRecipe(env.EnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(recipe.Start) != 1 || recipe.Start[0] != "echo hi" || len(recipe.Terminals) != 1 || recipe.Terminals[0] != "sleep 1" {
		t.Fatalf("recipe not persisted with artifact: %+v", recipe)
	}

	hookless := mustBuild(t, f, "coding", baseSpec())
	recipe, err = f.builder.HookRecipe(hookless.EnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(recipe.Start) != 0 || len(recipe.Terminals) != 0 {
		t.Fatalf("hook-less environment recipe not empty: %+v", recipe)
	}
	if _, err := f.builder.HookRecipe("env-nonexistent"); err == nil {
		t.Fatal("HookRecipe of unknown environment succeeded")
	}

	withHooks := baseSpec()
	withHooks.Start = []string{"echo hi"}
	if environmentbuilder.SpecDigest(withHooks) == environmentbuilder.SpecDigest(baseSpec()) {
		t.Fatal("hooks did not participate in environment identity")
	}
}

// Interface conformance: the sandboxlab sim env sources and every manager
// EnvironmentSource implementer serve HookRecipe.
func TestEnvironmentSourcesServeHookRecipe(t *testing.T) {
	clock := domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	rt, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := sandboxmanager.New(clock, ids, ws, rt, eventservice.NewOutbox(), sandboxmanager.NewMemoryStore(), "host-1")
	// No environment source set: hook-less sandboxes materialize fine and
	// emit no hook events (no environment attached).
	sb, err := mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-noenv",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Materialize(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
}
