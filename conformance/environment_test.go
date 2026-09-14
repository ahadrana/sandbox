package conformance

import (
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

type envFixture struct {
	builder *environmentbuilder.Builder
	repos   *environmentbuilder.LocalRepoSource
	clock   *domain.ManualClock
	ids     *domain.IDGen
}

func newEnvFixture(t *testing.T) *envFixture {
	t.Helper()
	clock := domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	repos := environmentbuilder.NewLocalRepoSource(t.TempDir())
	b, err := environmentbuilder.Open(t.TempDir(), repos, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	return &envFixture{builder: b, repos: repos, clock: clock, ids: ids}
}

func baseSpec() environmentbuilder.EnvironmentSpec {
	return environmentbuilder.EnvironmentSpec{
		BaseRuntimeRef: "base-go",
		RepoInputs:     []domain.RepoInput{{RepoURL: "app", SHA: "sha-app-1"}},
		InstallCommand: "echo installed > install.marker",
		Config:         map[string]string{"go": "1.22"},
	}
}

func mustBuild(t *testing.T, f *envFixture, family string, spec environmentbuilder.EnvironmentSpec) *domain.Environment {
	t.Helper()
	env, err := f.builder.StartBuild(family, spec)
	if err != nil {
		t.Fatal(err)
	}
	if env.Status != domain.EnvironmentBuilding {
		t.Fatalf("status = %s, want BUILDING", env.Status)
	}
	if err := f.builder.CompleteBuild(env.EnvironmentID); err != nil {
		t.Fatalf("complete build: %v", err)
	}
	env, err = f.builder.Get(env.EnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestEnvironmentIdentityDigest(t *testing.T) {
	spec := baseSpec()
	d0 := environmentbuilder.SpecDigest(spec)
	if d0 != environmentbuilder.SpecDigest(baseSpec()) {
		t.Fatal("identical inputs produced different digests")
	}
	variants := map[string]func(s *environmentbuilder.EnvironmentSpec){
		"repo SHA":        func(s *environmentbuilder.EnvironmentSpec) { s.RepoInputs[0].SHA = "sha-app-2" },
		"install command": func(s *environmentbuilder.EnvironmentSpec) { s.InstallCommand = "echo other > install.marker" },
		"config":          func(s *environmentbuilder.EnvironmentSpec) { s.Config["go"] = "1.23" },
		"base ref":        func(s *environmentbuilder.EnvironmentSpec) { s.BaseRuntimeRef = "base-go-2" },
	}
	for name, mutate := range variants {
		s := baseSpec()
		mutate(&s)
		if environmentbuilder.SpecDigest(s) == d0 {
			t.Fatalf("digest unchanged after changing %s", name)
		}
	}
	// Key order in config and repo order must not affect identity.
	s := baseSpec()
	s.Config["extra"] = "x"
	s2 := baseSpec()
	if environmentbuilder.SpecDigest(s) == environmentbuilder.SpecDigest(s2) {
		t.Fatal("adding a config key did not change the digest")
	}
}

// A failed build never replaces the last-known-good ACTIVE default
// (INV-021, FR-ENV-003).
func TestBrokenBuildNeverReplacesActive(t *testing.T) {
	f := newEnvFixture(t)
	if err := f.repos.AddVersion("base-go", "", map[string]string{"bin/go": "binary"}); err != nil {
		t.Fatal(err)
	}
	if err := f.repos.AddVersion("app", "sha-app-1", map[string]string{"main.go": "v1"}); err != nil {
		t.Fatal(err)
	}
	good := mustBuild(t, f, "coding", baseSpec())
	if good.Status != domain.EnvironmentActive {
		t.Fatalf("good build status = %s", good.Status)
	}

	bad := baseSpec()
	bad.RepoInputs[0].SHA = "sha-app-2"
	bad.InstallCommand = "exit 1"
	if err := f.repos.AddVersion("app", "sha-app-2", map[string]string{"main.go": "broken"}); err != nil {
		t.Fatal(err)
	}
	env, err := f.builder.StartBuild("coding", bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.builder.CompleteBuild(env.EnvironmentID); err == nil {
		t.Fatal("expected build failure")
	}
	env, _ = f.builder.Get(env.EnvironmentID)
	if env.Status != domain.EnvironmentFailed {
		t.Fatalf("bad build status = %s", env.Status)
	}
	if env.LogRef == "" {
		t.Fatal("failed build has no log ref")
	}
	active, err := f.builder.Active("coding")
	if err != nil {
		t.Fatal(err)
	}
	if active.EnvironmentID != good.EnvironmentID {
		t.Fatalf("FAILED build replaced the ACTIVE default: %s", active.EnvironmentID)
	}
}

// Multi-repo environment: distinct SHAs recorded and assembled.
func TestMultiRepoEnvironment(t *testing.T) {
	f := newEnvFixture(t)
	f.repos.AddVersion("base-go", "", map[string]string{"bin/go": "binary"})
	f.repos.AddVersion("app", "sha-a", map[string]string{"main.go": "app"})
	f.repos.AddVersion("lib", "sha-l", map[string]string{"lib.go": "lib"})
	spec := environmentbuilder.EnvironmentSpec{
		BaseRuntimeRef: "base-go",
		RepoInputs: []domain.RepoInput{
			{RepoURL: "app", SHA: "sha-a"},
			{RepoURL: "lib", SHA: "sha-l"},
		},
	}
	env := mustBuild(t, f, "coding", spec)
	if len(env.RepoInputs) != 2 {
		t.Fatalf("repo inputs recorded = %d", len(env.RepoInputs))
	}
	recorded := map[string]string{}
	for _, r := range env.RepoInputs {
		recorded[r.RepoURL] = r.SHA
	}
	if recorded["app"] != "sha-a" || recorded["lib"] != "sha-l" {
		t.Fatalf("exact SHAs not recorded: %v", recorded)
	}
	manifest, err := f.builder.ArtifactManifest(env.EnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	if manifest["repo/app/main.go"] != "app" || manifest["repo/lib/lib.go"] != "lib" {
		t.Fatalf("repos not assembled into artifact: %v", manifest)
	}
	if manifest["bin/go"] != "binary" {
		t.Fatal("base runtime missing from artifact")
	}
	if env.IntegrityDigest == "" {
		t.Fatal("missing integrity digest")
	}
}

// Rebuilding an identical spec returns the same environment and never
// re-runs install (idempotent rebuild, PLAN §7).
func TestIdempotentRebuild(t *testing.T) {
	f := newEnvFixture(t)
	f.repos.AddVersion("base-go", "", map[string]string{"bin/go": "binary"})
	f.repos.AddVersion("app", "sha-app-1", map[string]string{"main.go": "v1"})
	spec := baseSpec()
	first := mustBuild(t, f, "coding", spec)

	second, err := f.builder.StartBuild("coding", spec)
	if err != nil {
		t.Fatal(err)
	}
	if second.EnvironmentID != first.EnvironmentID {
		t.Fatalf("rebuild created a new environment: %s vs %s", second.EnvironmentID, first.EnvironmentID)
	}
	if second.ConfigDigest != first.ConfigDigest {
		t.Fatal("rebuild produced a different identity digest")
	}
	if err := f.builder.CompleteBuild(second.EnvironmentID); err != nil {
		t.Fatal(err)
	}
	if got := f.builder.InstallRuns(first.ConfigDigest); got != 1 {
		t.Fatalf("install ran %d times, want 1", got)
	}
	active, err := f.builder.Active("coding")
	if err != nil {
		t.Fatal(err)
	}
	if active.EnvironmentID != first.EnvironmentID {
		t.Fatal("ACTIVE churned on idempotent rebuild")
	}
}

// Cold vs prepared startup: N sandbox starts boot from the prepared artifact
// without re-executing the install command (PLAN §7 benchmark gate).
func TestColdVsPreparedStartup(t *testing.T) {
	f := newEnvFixture(t)
	f.repos.AddVersion("base-go", "", map[string]string{"bin/go": "binary"})
	f.repos.AddVersion("app", "sha-app-1", map[string]string{"main.go": "v1"})
	spec := baseSpec()
	env := mustBuild(t, f, "coding", spec)
	if got := f.builder.InstallRuns(env.ConfigDigest); got != 1 {
		t.Fatalf("install ran %d times for the build", got)
	}

	clock := domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	ws := workspace.NewMemory(clock, f.ids)
	rt, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outbox := eventservice.NewOutbox()
	store := sandboxmanager.NewMemoryStore()
	mgr := sandboxmanager.New(clock, f.ids, ws, rt, outbox, store, "host-1")
	mgr.SetEnvironmentSource(f.builder)

	const n = 3
	for i := 0; i < n; i++ {
		sb, err := mgr.CreateSandbox(api.CreateSandboxRequest{
			Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-prepared",
			EnvironmentID: env.EnvironmentID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mgr.Materialize(sb.SandboxID); err != nil {
			t.Fatal(err)
		}
		files, err := mgr.RuntimeFiles(sb.SandboxID)
		if err != nil {
			t.Fatal(err)
		}
		if files["install.marker"] != "installed\n" {
			t.Fatalf("sandbox %d missing prepared install output: %v", i, files)
		}
		if files["bin/go"] != "binary" {
			t.Fatalf("sandbox %d missing base layer", i)
		}
	}
	if got := f.builder.InstallRuns(env.ConfigDigest); got != 1 {
		t.Fatalf("install re-executed during sandbox starts: %d runs", got)
	}
}

// Failed startup command: the sandbox must not silently report RUNNING;
// it transitions to FAILED with an event (FR-ENV-005).
func TestFailedStartupCommandSemantics(t *testing.T) {
	clock := domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	ids := domain.NewIDGen()
	ws := workspace.NewMemory(clock, ids)
	rt, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outbox := eventservice.NewOutbox()
	store := sandboxmanager.NewMemoryStore()
	mgr := sandboxmanager.New(clock, ids, ws, rt, outbox, store, "host-1")

	sb, err := mgr.CreateSandbox(api.CreateSandboxRequest{
		Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: "task-startup",
		StartupCommands: []string{"true", "exit 3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Materialize(sb.SandboxID); err == nil {
		t.Fatal("materialize succeeded despite failing startup command")
	}
	cur, err := mgr.GetSandbox(sb.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.ObservedState != domain.SandboxFailed {
		t.Fatalf("sandbox state = %s, want FAILED", cur.ObservedState)
	}
	events, _ := outbox.Replay(0)
	failed := eventsOfType(events, domain.EventSandboxFailed)
	if len(failed) != 1 || failed[0].Payload["reason"] != "startup command failed" {
		t.Fatalf("missing startup-failure event: %v", events)
	}
	if !strings.Contains(failed[0].Payload["detail"].(string), "exited 3") {
		t.Fatalf("failure detail missing exit code: %v", failed[0].Payload)
	}
}

// Boot from artifact: sandbox sees artifact files + workspace overlay;
// writes stay private to the sandbox (INV-022, FR-WS-006).
func TestBootFromArtifactIsolation(t *testing.T) {
	f := newEnvFixture(t)
	f.repos.AddVersion("base-go", "", map[string]string{"etc/base.conf": "original"})
	f.repos.AddVersion("app", "sha-app-1", map[string]string{"main.go": "v1"})
	env := mustBuild(t, f, "coding", environmentbuilder.EnvironmentSpec{
		BaseRuntimeRef: "base-go",
		RepoInputs:     []domain.RepoInput{{RepoURL: "app", SHA: "sha-app-1"}},
	})

	clock := domain.NewManualClock(time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	ws := workspace.NewMemory(clock, f.ids)
	rt, err := localbackend.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outbox := eventservice.NewOutbox()
	mgr := sandboxmanager.New(clock, f.ids, ws, rt, outbox, sandboxmanager.NewMemoryStore(), "host-1")
	mgr.SetEnvironmentSource(f.builder)

	newSandbox := func(taskRef string) string {
		sb, err := mgr.CreateSandbox(api.CreateSandboxRequest{
			Version: api.SchemaVersionV1, TenantID: "tenant-1", TaskRef: taskRef,
			EnvironmentID: env.EnvironmentID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mgr.Materialize(sb.SandboxID); err != nil {
			t.Fatal(err)
		}
		return sb.SandboxID
	}
	a := newSandbox("task-a")
	b := newSandbox("task-b")

	d := agentdriver.New(mgr, "tenant-1", "principal-1", 107)
	if _, err := d.ExecSync(a, domain.Operation{
		Writes: map[string]string{"etc/base.conf": "modified-by-a", "a-only.txt": "x"},
	}); err != nil {
		t.Fatal(err)
	}
	filesB, err := mgr.RuntimeFiles(b)
	if err != nil {
		t.Fatal(err)
	}
	if filesB["etc/base.conf"] != "original" {
		t.Fatalf("sandbox B sees A's write: %q", filesB["etc/base.conf"])
	}
	if _, leaked := filesB["a-only.txt"]; leaked {
		t.Fatal("sandbox B sees A's new file")
	}
	// Workspace overlay wins over the artifact for the same path in A.
	filesA, err := mgr.RuntimeFiles(a)
	if err != nil {
		t.Fatal(err)
	}
	if filesA["etc/base.conf"] != "modified-by-a" {
		t.Fatalf("workspace overlay lost in A: %q", filesA["etc/base.conf"])
	}
	// The artifact itself is untouched.
	manifest, err := f.builder.ArtifactManifest(env.EnvironmentID)
	if err != nil {
		t.Fatal(err)
	}
	if manifest["etc/base.conf"] != "original" {
		t.Fatal("immutable artifact mutated by a sandbox")
	}
}
