// Package isolatedbackend is the strongest isolation backend this
// environment supports: every sandbox command runs under bubblewrap with a
// private mount namespace (only the incarnation workspace is writable;
// system paths are read-only binds), cleared environment, and
// network/IPC/UTS namespace isolation. It is exactly the local backend with
// a confining CommandWrapper, so lifecycle semantics are identical and the
// difference is declared through Capabilities (PLAN §9 gate). The pid
// namespace is deliberately NOT unshared so host-side inventory/termination
// and background-descendant semantics stay identical to the local backend.
package isolatedbackend

import (
	"os"
	"os/exec"
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

// bwrapWrap confines argv under bubblewrap. Only AGENT_SANDBOX_* environment
// entries (the ownership marker) cross the boundary; host credentials and
// ambient environment never enter the guest (FR-SEC-001).
func bwrapWrap(argv, env []string, wsDir string) ([]string, []string) {
	args := []string{
		"--die-with-parent", "--new-session", "--clearenv",
		"--unshare-net", "--unshare-ipc", "--unshare-uts",
		"--bind", wsDir, "/workspace",
		"--chdir", "/workspace",
		"--tmpfs", "/tmp",
	}
	for _, dir := range []string{"/bin", "/usr", "/lib", "/lib64"} {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			args = append(args, "--ro-bind", dir, dir)
		}
	}
	var kept []string
	for _, e := range env {
		if !strings.HasPrefix(e, "AGENT_SANDBOX_") {
			continue
		}
		kv := strings.SplitN(e, "=", 2)
		args = append(args, "--setenv", kv[0], kv[1])
		kept = append(kept, e)
	}
	args = append(args, "--setenv", "HOME", "/tmp", "--")
	wrapped := append([]string{"bwrap"}, args...)
	wrapped = append(wrapped, argv...)
	return wrapped, kept
}
