// Package isolatedbackend is the strongest isolation backend this
// environment supports: the per-incarnation supervisor daemon (and with it
// every sandbox command) runs under bubblewrap with a private mount
// namespace (only the incarnation directory is writable; system paths are
// read-only binds), cleared environment, and network/IPC/UTS namespace
// isolation. It is exactly the local backend with a confining
// CommandWrapper, so lifecycle semantics are identical and the difference is
// declared through Capabilities (PLAN §9 gate). The pid namespace is
// deliberately NOT unshared so host-side inventory/termination and
// background-descendant semantics stay identical to the local backend.
package isolatedbackend

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	localbackend "github.com/agent-sandbox/platform/runtime/local-backend"
)

// Available reports whether bubblewrap confinement can run here.
func Available() bool {
	if _, err := exec.LookPath("bwrap"); err != nil {
		return false
	}
	return exec.Command("unshare", "--user", "--map-root-user", "--mount", "true").Run() == nil
}

// Capabilities is the isolated backend's declared surface.
var Capabilities = backendinterface.Capabilities{
	IsolationClass:     backendinterface.IsolationNamespace,
	NetworkIsolated:    true,
	HostCredentialFree: true,
}

// New creates an isolated backend rooted at root.
func New(root string) (*localbackend.Backend, error) {
	return localbackend.New(root,
		localbackend.WithCommandWrapper(bwrapWrap),
		localbackend.WithCapabilities(Capabilities),
	)
}

// bwrapWrap confines the supervisor daemon under bubblewrap. The incarnation
// directory (workspace, output spill, daemon socket) is bound at its
// unchanged host path so the daemon's flags mean the same thing inside and
// outside the namespace. Only AGENT_SANDBOX_* environment entries (the
// ownership marker) plus PATH/HOME cross the boundary; host credentials and
// ambient environment never enter the guest (FR-SEC-001). /proc is mounted
// (same pid namespace) because the daemon's inventory and ownership checks
// scan it.
func bwrapWrap(argv, env []string, wsDir string) ([]string, []string) {
	incDir := filepath.Dir(wsDir)
	args := []string{
		"--die-with-parent", "--new-session", "--clearenv",
		"--unshare-net", "--unshare-ipc", "--unshare-uts",
		// /tmp is tmpfs'd FIRST: the incarnation bind (and the daemon
		// binary bind) must land on top of it, or the daemon's socket and
		// spill writes vanish into the masked tmpfs.
		"--tmpfs", "/tmp",
		"--bind", incDir, incDir,
		"--proc", "/proc",
		// Minimal /dev (null/zero/full/random): the daemon's exec.Command
		// opens /dev/null for untapped stdio.
		"--dev", "/dev",
	}
	for _, dir := range []string{"/bin", "/usr", "/lib", "/lib64"} {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			args = append(args, "--ro-bind", dir, dir)
		}
	}
	// The daemon binary typically lives outside the system binds (a
	// per-process build dir under /tmp): bind it explicitly, after the
	// /tmp tmpfs so the bind lands on top.
	if st, err := os.Stat(argv[0]); err == nil && !st.IsDir() {
		args = append(args, "--ro-bind", argv[0], argv[0])
	}
	var kept []string
	for _, e := range env {
		if !strings.HasPrefix(e, "AGENT_SANDBOX_") && !strings.HasPrefix(e, "PATH=") && !strings.HasPrefix(e, "HOME=") {
			continue
		}
		kv := strings.SplitN(e, "=", 2)
		args = append(args, "--setenv", kv[0], kv[1])
		kept = append(kept, e)
	}
	args = append(args, "--")
	wrapped := append([]string{"bwrap"}, args...)
	wrapped = append(wrapped, argv...)
	return wrapped, kept
}
