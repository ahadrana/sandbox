package conformance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/domain"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	fakebackend "github.com/agent-sandbox/platform/runtime/fake-backend"
	supervisor "github.com/agent-sandbox/platform/runtime/guest-supervisor"
	isolatedbackend "github.com/agent-sandbox/platform/runtime/isolated-backend"
	localbackend "github.com/agent-sandbox/platform/runtime/local-backend"
)

// newIsolatedSystem builds a system on the isolated (bubblewrap) backend,
// skipping when confinement is unavailable.
func newIsolatedSystem(t *testing.T) *system {
	t.Helper()
	if !isolatedbackend.Available() {
		t.Skip("isolated backend unavailable (no bwrap/userns)")
	}
	s := newSystem(t, "local") // reuse wiring, then swap the backend
	rt, err := isolatedbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.rt = rt
	s.mgr = sandboxmanager.New(s.clock, s.ids, s.ws, s.rt, s.outbox, s.store, "host-1")
	s.backend = "isolated"
	return s
}

// Every backend declares its capabilities; differences are declared, not
// silent (PLAN §9 gate).
func TestBackendCapabilityDeclarations(t *testing.T) {
	fake := newSystem(t, "fake")
	if got := fake.rt.Capabilities().IsolationClass; got != backendinterface.IsolationProcess {
		t.Fatalf("fake isolation = %s", got)
	}
	local, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	caps := local.Capabilities()
	if caps.IsolationClass != backendinterface.IsolationProcess || caps.SupportsSnapshot {
		t.Fatalf("local caps wrong: %+v", caps)
	}
	if !isolatedbackend.Available() {
		t.Skip("isolated backend unavailable")
	}
	iso, err := isolatedbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	icaps := iso.Capabilities()
	if icaps.IsolationClass != backendinterface.IsolationNamespace {
		t.Fatalf("isolated class = %s", icaps.IsolationClass)
	}
	if !icaps.NetworkIsolated || !icaps.HostCredentialFree {
		t.Fatalf("isolated caps incomplete: %+v", icaps)
	}
}

// The guest environment carries no host/control-plane credentials and no
// ambient host variables (FR-SEC-001, INV-018).
func TestIsolatedNoHostCredentials(t *testing.T) {
	s := newIsolatedSystem(t)
	rt := s.rt.(*localbackend.Backend)
	if rt.Capabilities().IsolationClass != backendinterface.IsolationNamespace {
		t.Skip("not the isolated backend")
	}
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 139)
	sb, _ := d.CreateSandbox("task-sec")
	mustMaterialize(t, d, sb.SandboxID)
	ex, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "env"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(strings.TrimPrefix(*ex.StdoutRef, "file://"))
	if err != nil {
		t.Fatal(err)
	}
	env := string(data)
	for _, forbidden := range []string{"KUBERNETES_SERVICE_HOST", "SERVICE_ACCOUNT", "KUBE_", "AWS_ACCESS_KEY", "HOME=/home"} {
		if strings.Contains(env, forbidden) {
			t.Fatalf("guest environment leaks %q:\n%s", forbidden, env)
		}
	}
	if !strings.Contains(env, "AGENT_SANDBOX_INCARNATION=") {
		t.Fatal("ownership marker missing in guest")
	}
}

// Sandbox processes cannot read host files outside their workspace root.
func TestIsolatedCannotReadHostFiles(t *testing.T) {
	if !isolatedbackend.Available() {
		t.Skip("isolated backend unavailable")
	}
	probe := func(t *testing.T, s *system, cmd string) int {
		d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 149)
		sb, _ := d.CreateSandbox("task-probe")
		mustMaterialize(t, d, sb.SandboxID)
		ex, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: cmd})
		if err != nil {
			t.Fatal(err)
		}
		return *ex.ExitCode
	}

	iso := newIsolatedSystem(t)
	if code := probe(t, iso, "cat /etc/hostname"); code == 0 {
		t.Fatal("isolated guest read /etc/hostname")
	}
	if code := probe(t, iso, "cat /etc/shadow"); code == 0 {
		t.Fatal("isolated guest read /etc/shadow")
	}
	if code := probe(t, iso, "ls /home"); code == 0 {
		t.Fatal("isolated guest listed /home")
	}
	// Contrast: the plain local backend CAN read these (declared difference).
	local := newSystem(t, "local")
	if code := probe(t, local, "cat /etc/hostname"); code != 0 {
		t.Fatal("local backend unexpectedly confined")
	}
}

// The isolated backend satisfies the same functional conformance surface as
// the local backend where capabilities allow (INV-026).
func TestIsolatedBackendConformanceSample(t *testing.T) {
	if !isolatedbackend.Available() {
		t.Skip("isolated backend unavailable")
	}
	s := newIsolatedSystem(t)
	d := agentdriver.New(s.mgr, "tenant-1", "principal-1", 151)
	sb, _ := d.CreateSandbox("task-iso-loop")
	mustMaterialize(t, d, sb.SandboxID)
	content := "isolated-committed-bytes"
	if _, err := d.ExecSync(sb.SandboxID, domain.Operation{
		Writes: map[string]string{"main.go": content},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.mgr.KillRuntime(sb.SandboxID); err != nil {
		t.Fatal(err)
	}
	report := mustMaterialize(t, d, sb.SandboxID)
	if report.NewEpoch != 2 {
		t.Fatalf("epoch = %d after reset", report.NewEpoch)
	}
	files, err := s.mgr.RuntimeFiles(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if files["main.go"] != content {
		t.Fatal("committed bytes missing on isolated backend")
	}
	// Command execution is genuinely confined to the workspace view.
	ex, err := d.ExecSync(sb.SandboxID, domain.Operation{Command: "pwd && cat main.go"})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(strings.TrimPrefix(*ex.StdoutRef, "file://"))
	if !strings.Contains(string(out), content) {
		t.Fatalf("guest cannot read its own workspace file: %q", out)
	}
}

// H7 regression: a background execution name containing "../" must be
// rejected at the supervisor boundary with a clean error, and no output
// file may be created outside the output directory.
func TestBackgroundNamePathTraversalRejected(t *testing.T) {
	root := t.TempDir()
	lb, err := localbackend.New(root)
	if err != nil {
		t.Fatal(err)
	}
	h, err := lb.Create(backendinterface.Spec{
		SandboxID:     "sb-sec",
		IncarnationID: "inc-sec",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := lb.Start(h); err != nil {
		t.Fatal(err)
	}
	// "x/../../escape" makes filepath.Join collapse out of the output
	// directory into the incarnation dir: without validation the file
	// create would succeed outside outDir.
	err = lb.Exec(h, "ex-sec", domain.Operation{
		Command:         "true",
		SpawnBackground: []domain.BackgroundSpec{{Name: "x/../../escape", Ticks: 1}},
	})
	if err == nil {
		t.Fatal("traversal execution ID accepted")
	}
	var escaped []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.Contains(info.Name(), "escape") {
			escaped = append(escaped, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(escaped) > 0 {
		t.Fatalf("files created by traversal ID: %v", escaped)
	}
}

// M11 regression: WaitExecution on an unknown execution ID returns
// ErrNotFound, never a fabricated success (backend contract parity).
func TestWaitExecutionUnknownIDNotFound(t *testing.T) {
	lb, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h, err := lb.Create(backendinterface.Spec{SandboxID: "sb-w", IncarnationID: "inc-w"})
	if err != nil {
		t.Fatal(err)
	}
	if err := lb.Start(h); err != nil {
		t.Fatal(err)
	}
	_, err = lb.WaitExecution(h, "ex-never-started")
	if !errors.Is(err, supervisor.ErrNotFound) {
		t.Fatalf("WaitExecution unknown ID: err = %v, want ErrNotFound", err)
	}
}

// M12 regression: a command that fails to START leaves no leaked exec entry:
// Wait returns ErrNotFound (never hangs) and a retry with the same execution
// ID is a fresh attempt.
func TestExecStartFailureNoLeak(t *testing.T) {
	lb, err := localbackend.New(t.TempDir(), localbackend.WithCommandWrapper(
		func(argv, env []string, wsDir string) ([]string, []string) {
			if strings.Contains(argv[2], "start-fails") {
				return []string{"/nonexistent/binary"}, env
			}
			return argv, env
		}))
	if err != nil {
		t.Fatal(err)
	}
	h, err := lb.Create(backendinterface.Spec{SandboxID: "sb-s", IncarnationID: "inc-s"})
	if err != nil {
		t.Fatal(err)
	}
	if err := lb.Start(h); err != nil {
		t.Fatal(err)
	}
	if err := lb.Exec(h, "ex-retry", domain.Operation{Command: "start-fails"}); err == nil {
		t.Fatal("expected start failure")
	}
	done := make(chan error, 1)
	go func() {
		_, err := lb.WaitExecution(h, "ex-retry")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, supervisor.ErrNotFound) {
			t.Fatalf("Wait after start failure: err = %v, want ErrNotFound", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait hung after start failure (leaked exec entry)")
	}
	// Retry with the same ID succeeds.
	if err := lb.Exec(h, "ex-retry", domain.Operation{Command: "true"}); err != nil {
		t.Fatalf("retry with same ID: %v", err)
	}
	res, err := lb.WaitExecution(h, "ex-retry")
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("retry exit code = %d", res.ExitCode)
	}
}

// M13 regression: dirty-flag updates are race-free against concurrent
// Dirty/MarkCommitted, and a completed Exec with writes always leaves the
// incarnation dirty (durability is never claimed for an in-flight write).
func TestExecDirtyFlagRace(t *testing.T) {
	lb, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h, err := lb.Create(backendinterface.Spec{SandboxID: "sb-d", IncarnationID: "inc-d"})
	if err != nil {
		t.Fatal(err)
	}
	if err := lb.Start(h); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = lb.Dirty(h)
				lb.MarkCommitted(h)
			}
		}
	}()
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("ex-dirty-%d", i)
		if err := lb.Exec(h, id, domain.Operation{Writes: map[string]string{"f.txt": "data"}}); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if err := lb.Exec(h, "ex-dirty-final", domain.Operation{Writes: map[string]string{"final.txt": "x"}}); err != nil {
		t.Fatal(err)
	}
	if !lb.Dirty(h) {
		t.Fatal("incarnation not dirty after Exec with writes returned")
	}
}

// M16 regression: backend contract parity (INV-026) — both backends reject
// Exec while paused and reject Snapshot on a non-paused incarnation.
func TestBackendPausedContractParity(t *testing.T) {
	backends := map[string]func(t *testing.T) sandboxmanager.Runtime{
		"fake": func(t *testing.T) sandboxmanager.Runtime { return fakebackend.New() },
		"local": func(t *testing.T) sandboxmanager.Runtime {
			lb, err := localbackend.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			return lb
		},
	}
	for name, mk := range backends {
		t.Run(name, func(t *testing.T) {
			rt := mk(t)
			h, err := rt.Create(backendinterface.Spec{SandboxID: "sb-p", IncarnationID: "inc-p"})
			if err != nil {
				t.Fatal(err)
			}
			if err := rt.Start(h); err != nil {
				t.Fatal(err)
			}
			// Snapshot on a running (non-paused) incarnation is illegal.
			if _, err := rt.Snapshot(h); !errors.Is(err, backendinterface.ErrIllegalState) {
				t.Fatalf("Snapshot while running: err = %v, want ErrIllegalState", err)
			}
			if err := rt.Pause(h); err != nil {
				t.Fatal(err)
			}
			// Exec while paused is illegal.
			if err := rt.Exec(h, "ex-paused", domain.Operation{Command: "true"}); !errors.Is(err, backendinterface.ErrIllegalState) {
				t.Fatalf("Exec while paused: err = %v, want ErrIllegalState", err)
			}
			// Snapshot while paused is legal.
			if _, err := rt.Snapshot(h); err != nil {
				t.Fatalf("Snapshot while paused: %v", err)
			}
			if err := rt.Resume(h); err != nil {
				t.Fatal(err)
			}
			if err := rt.Exec(h, "ex-resumed", domain.Operation{Command: "true"}); err != nil {
				t.Fatalf("Exec after resume: %v", err)
			}
		})
	}
}
