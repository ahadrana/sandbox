package conformance

import (
	"os"
	"strings"
	"testing"

	agentdriver "github.com/agent-sandbox/platform/agent-driver"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/domain"
	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
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
