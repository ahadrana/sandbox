package firecrackerbackend

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// workspaceMountUnit is injected into each per-incarnation rootfs copy. It
// mounts the workspace virtio-block drive (/dev/vdb) at /workspace and
// prints a console marker used by tests and readiness probing.
const workspaceMountUnit = `[Unit]
Description=agent-sandbox workspace mount
Before=multi-user.target

[Service]
Type=oneshot
ExecStartPre=/bin/sh -c 'for i in $$(seq 1 100); do [ -b /dev/vdb ] && exit 0; sleep 0.1; done; echo AGENT_WORKSPACE_MISSING > /dev/ttyS0; exit 1'
ExecStart=/bin/sh -c 'mkdir -p /workspace && mount -t ext4 /dev/vdb /workspace && echo AGENT_WORKSPACE_READY > /dev/ttyS0'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`

// checkWorkspacePath rejects absolute and escaping relative paths.
func checkWorkspacePath(path string) error {
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("unsafe workspace path: %q", path)
	}
	return nil
}

// buildWorkspaceImage creates an ext4 image at imgPath containing the
// manifest files, using mkfs.ext4 + debugfs (no root required).
func buildWorkspaceImage(imgPath string, manifest map[string]string) error {
	paths := make([]string, 0, len(manifest))
	var total int64
	for p, content := range manifest {
		if err := checkWorkspacePath(p); err != nil {
			return err
		}
		paths = append(paths, p)
		total += int64(len(content))
	}
	sort.Strings(paths)
	sizeMiB := total/(1<<20)*2 + 8
	img, err := os.Create(imgPath)
	if err != nil {
		return err
	}
	if err := img.Truncate(sizeMiB << 20); err != nil {
		img.Close()
		return err
	}
	img.Close()
	if out, err := exec.Command("mkfs.ext4", "-q", "-F", imgPath).CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.ext4: %v: %s", err, out)
	}
	if len(paths) == 0 {
		return nil
	}
	tmp, err := os.MkdirTemp("", "fc-ws-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	var cmds strings.Builder
	for i, p := range paths {
		host := filepath.Join(tmp, fmt.Sprintf("f%d", i))
		if err := os.WriteFile(host, []byte(manifest[p]), 0o644); err != nil {
			return err
		}
		guest := filepath.ToSlash(filepath.Clean(p))
		// mkdir -p equivalent: debugfs mkdir errors on existing dirs, which
		// we tolerate because debugfs continues the command script.
		dir := ""
		for _, part := range strings.Split(filepath.Dir(guest), "/") {
			if part == "." || part == "" {
				continue
			}
			dir += "/" + part
			cmds.WriteString("mkdir " + dir + "\n")
		}
		cmds.WriteString("write " + host + " /" + guest + "\n")
	}
	script := filepath.Join(tmp, "cmds")
	if err := os.WriteFile(script, []byte(cmds.String()), 0o600); err != nil {
		return err
	}
	if out, err := exec.Command("debugfs", "-w", "-f", script, imgPath).CombinedOutput(); err != nil {
		return fmt.Errorf("debugfs: %v: %s", err, out)
	}
	return nil
}

// injectWorkspaceUnit writes the workspace mount unit and /workspace mount
// point into a per-incarnation rootfs image copy, and enables the unit via a
// symlink in multi-user.target.wants.
func injectWorkspaceUnit(rootfsPath string) error {
	// The source rootfs is a crash-stop artifact (dirty ext4 journal).
	// debugfs ignores the journal, so writing over an un-recovered journal
	// corrupts directory entries; replay it first.
	// e2fsck exit codes are a bitmask: 1 = errors corrected, 2 = corrected +
	// reboot suggested; both are expected when replaying a crash-stop journal.
	cmd := exec.Command("e2fsck", "-fy", rootfsPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() > 2 {
			return fmt.Errorf("e2fsck rootfs recover: %v: %s", err, out)
		}
	}
	tmp, err := os.MkdirTemp("", "fc-unit-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	unit := filepath.Join(tmp, "unit")
	if err := os.WriteFile(unit, []byte(workspaceMountUnit), 0o644); err != nil {
		return err
	}
	script := filepath.Join(tmp, "cmds")
	body := "mkdir /workspace\n" +
		"write " + unit + " /etc/systemd/system/agent-workspace.service\n" +
		// systemd requires .wants dropins to be symlinks; debugfs symlinks
		// are valid only because the journal was replayed above.
		"symlink /etc/systemd/system/multi-user.target.wants/agent-workspace.service /etc/systemd/system/agent-workspace.service\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		return err
	}
	if out, err := exec.Command("debugfs", "-w", "-f", script, rootfsPath).CombinedOutput(); err != nil {
		return fmt.Errorf("debugfs rootfs inject: %v: %s", err, out)
	}
	return nil
}

// guestAgentUnitTemplate is the systemd unit starting the in-guest
// supervisor after the workspace mount; %s carries the incarnation ID and
// %d the vsock port.
const guestAgentUnitTemplate = `[Unit]
Description=agent-sandbox guest supervisor
Requires=agent-workspace.service
After=agent-workspace.service

[Service]
Environment=AGENT_SANDBOX_INCARNATION_ID=%s
ExecStart=/usr/local/bin/guest-supervisor -port %d
Restart=always
RestartSec=0.2

[Install]
WantedBy=multi-user.target
`

// injectGuestAgent writes the guest-supervisor daemon binary (with exec
// permission via debugfs sif) and its systemd unit into a rootfs image copy.
// Must run after injectWorkspaceUnit (the unit Requires/Afters it) and after
// the journal recovery it performs.
func injectGuestAgent(rootfsPath, binPath, incarnationID string, port uint32) error {
	tmp, err := os.MkdirTemp("", "fc-agent-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	unit := filepath.Join(tmp, "unit")
	if err := os.WriteFile(unit, []byte(fmt.Sprintf(guestAgentUnitTemplate, incarnationID, port)), 0o644); err != nil {
		return err
	}
	script := filepath.Join(tmp, "cmds")
	body := "write " + binPath + " /usr/local/bin/guest-supervisor\n" +
		"sif /usr/local/bin/guest-supervisor mode 0100755\n" +
		"write " + unit + " /etc/systemd/system/guest-supervisor.service\n" +
		"symlink /etc/systemd/system/multi-user.target.wants/guest-supervisor.service /etc/systemd/system/guest-supervisor.service\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		return err
	}
	if out, err := exec.Command("debugfs", "-w", "-f", script, rootfsPath).CombinedOutput(); err != nil {
		return fmt.Errorf("debugfs agent inject: %v: %s", err, out)
	}
	return nil
}

// copyFile copies src to dst, preferring reflink (CoW) where the filesystem
// supports it and falling back to a full copy.
func copyFile(dst, src string) error {
	if out, err := exec.Command("cp", "--reflink=auto", "--", src, dst).CombinedOutput(); err != nil {
		return fmt.Errorf("cp %s %s: %v: %s", src, dst, err, out)
	}
	return nil
}
