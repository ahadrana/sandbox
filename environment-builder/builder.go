// Package environmentbuilder implements the Prepared Environment build
// pipeline (DESIGN §6.5, PLAN §7): versioned specs with deterministic
// identity, async bounded builds, immutable digest-verified artifacts, and
// family default (ACTIVE) management. Environment preparation is distinct
// from per-session startup (FR-ENV-005).
package environmentbuilder

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agent-sandbox/platform/domain"
)

var (
	ErrNotFound     = errors.New("environment not found")
	ErrIllegalState = errors.New("environment in wrong state for operation")
	ErrBuildFailed  = errors.New("environment build failed")
	ErrIntegrity    = errors.New("artifact integrity digest mismatch")
)

// EnvironmentSpec is the versioned build input. Its digest is the
// environment's identity: identical inputs produce identical digests.
type EnvironmentSpec struct {
	BaseRuntimeRef string
	RepoInputs     []domain.RepoInput
	InstallCommand string
	Config         map[string]string
}

// SpecDigest computes the deterministic environment identity.
func SpecDigest(spec EnvironmentSpec) string {
	var b strings.Builder
	b.WriteString("base:" + spec.BaseRuntimeRef + "\n")
	repos := append([]domain.RepoInput{}, spec.RepoInputs...)
	sort.Slice(repos, func(i, j int) bool {
		if repos[i].RepoURL != repos[j].RepoURL {
			return repos[i].RepoURL < repos[j].RepoURL
		}
		return repos[i].SHA < repos[j].SHA
	})
	for _, r := range repos {
		b.WriteString("repo:" + r.RepoURL + "@" + r.SHA + "\n")
	}
	b.WriteString("install:" + spec.InstallCommand + "\n")
	keys := make([]string, 0, len(spec.Config))
	for k := range spec.Config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("config:" + k + "=" + spec.Config[k] + "\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// RepoSource provides repository/base content at exact versions.
type RepoSource interface {
	// Checkout materializes ref at sha ("" = the ref itself is versioned)
	// into destDir.
	Checkout(ref, sha, destDir string) error
}

// LocalRepoSource models repos as directories: <root>/<ref>/<sha>/ for
// versioned repos and <root>/<ref>/ for base refs.
type LocalRepoSource struct {
	root string
}

func NewLocalRepoSource(root string) *LocalRepoSource {
	return &LocalRepoSource{root: root}
}

// AddVersion registers repo content at an exact SHA.
func (l *LocalRepoSource) AddVersion(ref, sha string, files map[string]string) error {
	dir := filepath.Join(l.root, filepath.Clean(ref))
	if sha != "" {
		dir = filepath.Join(dir, sha)
	}
	for path, content := range files {
		full := filepath.Join(dir, filepath.Clean(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (l *LocalRepoSource) Checkout(ref, sha, destDir string) error {
	src := filepath.Join(l.root, filepath.Clean(ref))
	if sha != "" {
		src = filepath.Join(src, sha)
	}
	if st, err := os.Stat(src); err != nil || !st.IsDir() {
		return fmt.Errorf("repo %q at %q not found", ref, sha)
	}
	return copyDir(src, destDir)
}

func copyDir(src, dest string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

// artifactManifest records every file in an artifact with its digest.
type artifactManifest struct {
	Files           map[string]string `json:"files"`
	IntegrityDigest string            `json:"integrity_digest"`
}

func digestFileSet(files map[string]string) string {
	h := sha256.New()
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(files[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Builder is the environment build service.
type Builder struct {
	mu             sync.Mutex
	root           string
	repos          RepoSource
	clock          domain.Clock
	ids            *domain.IDGen
	InstallTimeout time.Duration

	envs        map[string]*domain.Environment // environment_id -> record
	byKey       map[string]string              // family|digest -> environment_id
	installRuns map[string]int                 // config digest -> real install executions
	specs       map[string]EnvironmentSpec     // environment_id -> build spec
	compLocks   map[string]*sync.Mutex         // completion serialization keys -> lock
}

// Open opens (or creates) the builder registry rooted at root, reloading
// terminal environment records from artifacts.
func Open(root string, repos RepoSource, clock domain.Clock, ids *domain.IDGen) (*Builder, error) {
	for _, sub := range []string{"artifacts", "build", "logs"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
			return nil, err
		}
	}
	b := &Builder{
		root: root, repos: repos, clock: clock, ids: ids,
		InstallTimeout: 30 * time.Second,
		envs:           map[string]*domain.Environment{},
		byKey:          map[string]string{},
		installRuns:    map[string]int{},
		specs:          map[string]EnvironmentSpec{},
		compLocks:      map[string]*sync.Mutex{},
	}
	entries, err := os.ReadDir(filepath.Join(root, "artifacts"))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(root, "artifacts", e.Name(), "environment.json"))
		if err != nil {
			continue
		}
		var env domain.Environment
		if err := json.Unmarshal(data, &env); err != nil {
			continue
		}
		envCopy := env
		b.envs[envCopy.EnvironmentID] = &envCopy
		b.byKey[envCopy.Name+"|"+envCopy.ConfigDigest] = envCopy.EnvironmentID
	}
	return b, nil
}

// StartBuild registers a build and returns immediately with status BUILDING.
// It is idempotent: an identical spec for the same family returns the
// existing environment (INV-021).
func (b *Builder) StartBuild(family string, spec EnvironmentSpec) (*domain.Environment, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	digest := SpecDigest(spec)
	key := family + "|" + digest
	if id, ok := b.byKey[key]; ok {
		env := b.envs[id]
		if env.Status == domain.EnvironmentActive || env.Status == domain.EnvironmentBuilding {
			cp := *env
			return &cp, nil
		}
	}
	env := &domain.Environment{
		EnvironmentID:  b.ids.Next("env"),
		Name:           family,
		Version:        1,
		Status:         domain.EnvironmentBuilding,
		BaseRuntimeRef: spec.BaseRuntimeRef,
		RepoInputs:     append([]domain.RepoInput{}, spec.RepoInputs...),
		ConfigDigest:   digest,
		CreatedAt:      b.clock.Now(),
	}
	b.envs[env.EnvironmentID] = env
	b.byKey[key] = env.EnvironmentID
	b.specs[env.EnvironmentID] = spec
	cp := *env
	return &cp, nil
}

// completionLock returns the named serialization lock for CompleteBuild.
// Locks are acquired in a fixed order (environment, then artifact digest),
// which cannot cycle: an environment has exactly one digest.
func (b *Builder) completionLock(key string) *sync.Mutex {
	b.mu.Lock()
	defer b.mu.Unlock()
	l, ok := b.compLocks[key]
	if !ok {
		l = &sync.Mutex{}
		b.compLocks[key] = l
	}
	return l
}

// CompleteBuild drives a BUILDING environment to its terminal state:
// checkout base + repos at exact SHAs, bounded install command, immutable
// artifact on success. Terminal states: ACTIVE (success, becomes the family
// default) or FAILED (never replaces the last-known-good default).
// Completion is serialized per environment and per artifact digest:
// concurrent completions of the same environment run the install at most
// once, and concurrent builds sharing an artifactDir publish one intact
// artifact.
func (b *Builder) CompleteBuild(environmentID string) error {
	b.mu.Lock()
	env, ok := b.envs[environmentID]
	b.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	envLock := b.completionLock("env:" + environmentID)
	envLock.Lock()
	defer envLock.Unlock()
	digestLock := b.completionLock("digest:" + env.ConfigDigest)
	digestLock.Lock()
	defer digestLock.Unlock()

	b.mu.Lock()
	if env.Status != domain.EnvironmentBuilding {
		cp := *env
		b.mu.Unlock()
		if cp.Status == domain.EnvironmentActive {
			return nil
		}
		return ErrIllegalState
	}
	b.mu.Unlock()

	digest := env.ConfigDigest
	artifactDir := filepath.Join(b.root, "artifacts", digest)
	if _, err := os.Stat(filepath.Join(artifactDir, "manifest.json")); err == nil {
		// Artifact already built from identical inputs: reuse, no install re-run.
		return b.finish(env, artifactDir, true, "")
	}

	buildDir := filepath.Join(b.root, "build", env.EnvironmentID)
	os.RemoveAll(buildDir)
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(buildDir)

	b.mu.Lock()
	spec := b.specs[env.EnvironmentID]
	b.mu.Unlock()
	if err := b.repos.Checkout(spec.BaseRuntimeRef, "", buildDir); err != nil {
		return b.failBuild(env, "", err)
	}
	for _, repo := range env.RepoInputs {
		dest := filepath.Join(buildDir, "repo", filepath.Clean(repo.RepoURL))
		if err := b.repos.Checkout(repo.RepoURL, repo.SHA, dest); err != nil {
			return b.failBuild(env, "", err)
		}
	}

	logPath := ""
	installErr := error(nil)
	if cmd := spec.InstallCommand; cmd != "" {
		logPath = filepath.Join(b.root, "logs", env.EnvironmentID+".log")
		b.mu.Lock()
		b.installRuns[digest]++
		b.mu.Unlock()
		installErr = runInstall(buildDir, cmd, b.InstallTimeout, logPath)
	}
	if installErr != nil {
		return b.failBuild(env, logPath, installErr)
	}
	return b.finish(env, artifactDir, false, logPath)
}

// failBuild marks the environment FAILED; the family default is untouched.
func (b *Builder) failBuild(env *domain.Environment, logRef string, cause error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	env.Status = domain.EnvironmentFailed
	env.LogRef = logRef
	delete(b.byKey, env.Name+"|"+env.ConfigDigest)
	return fmt.Errorf("%w: %v", ErrBuildFailed, cause)
}

// finish publishes the immutable artifact and activates the environment as
// the family default, retiring the previous ACTIVE build.
func (b *Builder) finish(env *domain.Environment, artifactDir string, reused bool, logPath string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !reused {
		if err := os.MkdirAll(artifactDir, 0o755); err != nil {
			return err
		}
		buildDir := filepath.Join(b.root, "build", env.EnvironmentID)
		files, err := moveAndDigest(buildDir, filepath.Join(artifactDir, "fs"))
		if err != nil {
			return err
		}
		m := artifactManifest{Files: files, IntegrityDigest: digestFileSet(files)}
		data, err := json.Marshal(m)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(artifactDir, "manifest.json"), data, 0o644); err != nil {
			return err
		}
		if logPath != "" {
			logData, err := os.ReadFile(logPath)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(artifactDir, "install.log"), logData, 0o644); err != nil {
				return err
			}
		}
	}
	env.Status = domain.EnvironmentActive
	env.IntegrityDigest = ""
	env.ArtifactRefs = []string{artifactDir}
	env.LogRef = logPath
	if data, err := os.ReadFile(filepath.Join(artifactDir, "manifest.json")); err == nil {
		var m artifactManifest
		if json.Unmarshal(data, &m) == nil {
			env.IntegrityDigest = m.IntegrityDigest
		}
	}
	for _, other := range b.envs {
		if other.Name == env.Name && other.EnvironmentID != env.EnvironmentID && other.Status == domain.EnvironmentActive {
			other.Status = domain.EnvironmentRetired
			if err := b.persistRecordLocked(other); err != nil {
				return err
			}
		}
	}
	record, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(artifactDir, "environment.json"), record, 0o644); err != nil {
		return err
	}
	return nil
}

// persistRecordLocked rewrites the environment's environment.json inside its
// artifact directory, so status transitions (e.g. ACTIVE -> RETIRED) survive
// a restart. Caller holds b.mu.
func (b *Builder) persistRecordLocked(env *domain.Environment) error {
	record, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(b.root, "artifacts", env.ConfigDigest, "environment.json"), record, 0o644)
}

func moveAndDigest(srcDir, destDir string) (map[string]string, error) {
	if err := os.RemoveAll(destDir); err != nil {
		return nil, err
	}
	files := map[string]string{}
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		files[rel] = hex.EncodeToString(sum[:])
		full := filepath.Join(destDir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		return os.WriteFile(full, data, 0o644)
	})
	return files, err
}

// runInstall executes the bounded install command with a timeout, capturing
// output to logPath.
func runInstall(dir, command string, timeout time.Duration, logPath string) error {
	log, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer log.Close()
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Dir = dir
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("install command failed: %v", err)
		}
		return nil
	case <-time.After(timeout):
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return fmt.Errorf("install command timed out after %s", timeout)
	}
}

func (b *Builder) Get(environmentID string) (*domain.Environment, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	env, ok := b.envs[environmentID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *env
	return &cp, nil
}

// Active returns the family's current default (ACTIVE) environment.
func (b *Builder) Active(family string) (*domain.Environment, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, env := range b.envs {
		if env.Name == family && env.Status == domain.EnvironmentActive {
			cp := *env
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// Activate explicitly promotes a successful build to the family default.
func (b *Builder) Activate(environmentID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	env, ok := b.envs[environmentID]
	if !ok {
		return ErrNotFound
	}
	if env.Status != domain.EnvironmentActive && env.Status != domain.EnvironmentRetired {
		return ErrIllegalState
	}
	for _, other := range b.envs {
		if other.Name == env.Name && other.Status == domain.EnvironmentActive {
			other.Status = domain.EnvironmentRetired
			if err := b.persistRecordLocked(other); err != nil {
				return err
			}
		}
	}
	env.Status = domain.EnvironmentActive
	return b.persistRecordLocked(env)
}

// ArtifactManifest reads the artifact's file set, verifying every file
// digest and the manifest integrity digest.
func (b *Builder) ArtifactManifest(environmentID string) (map[string]string, error) {
	b.mu.Lock()
	env, ok := b.envs[environmentID]
	b.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	if env.Status != domain.EnvironmentActive && env.Status != domain.EnvironmentRetired {
		return nil, ErrIllegalState
	}
	artifactDir := filepath.Join(b.root, "artifacts", env.ConfigDigest)
	data, err := os.ReadFile(filepath.Join(artifactDir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m artifactManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if digestFileSet(m.Files) != m.IntegrityDigest {
		return nil, ErrIntegrity
	}
	out := make(map[string]string, len(m.Files))
	for rel, digest := range m.Files {
		content, err := os.ReadFile(filepath.Join(artifactDir, "fs", rel))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != digest {
			return nil, ErrIntegrity
		}
		out[rel] = string(content)
	}
	return out, nil
}

// InstallRuns reports how many times the install command actually executed
// for a config digest (prepared-vs-cold proof, PLAN §7).
func (b *Builder) InstallRuns(configDigest string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.installRuns[configDigest]
}
