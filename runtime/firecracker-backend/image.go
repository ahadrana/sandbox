package firecrackerbackend

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
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

// checkWorkspacePath validates manifest paths before they are interpolated
// into a debugfs command script (shared strict rule: no control chars,
// whitespace, or backslash — debugfs tokenizes on whitespace and splits
// commands on newlines, with no quoting). The host validates independently
// of the guest: manifests can arrive from the workspace store, whose
// contents may have been minted by root inside a VM.
func checkWorkspacePath(path string) error {
	return supervisor.CheckWorkspacePath(path)
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
// %d the vsock port. The supervisor binary is NOT in the rootfs: it lives
// on the shared read-only tools drive (P0.3, filesystem label fc-tools)
// which this unit mounts at /opt/fc-tools. The mount is idempotent
// (mountpoint -q first) because Restart=always re-runs ExecStartPre; the
// /dev/vdX fallbacks cover kernels that mount by label too late.
const guestAgentUnitTemplate = `[Unit]
Description=agent-sandbox guest supervisor
Requires=agent-workspace.service
After=agent-workspace.service

[Service]
Environment=AGENT_SANDBOX_INCARNATION_ID=%s
ExecStartPre=/bin/sh -c 'mkdir -p /opt/fc-tools && (mountpoint -q /opt/fc-tools || mount -t ext4 -o ro LABEL=fc-tools /opt/fc-tools || mount -t ext4 -o ro /dev/vdc /opt/fc-tools || mount -t ext4 -o ro /dev/vdb /opt/fc-tools || mount -t ext4 -o ro /dev/vdd /opt/fc-tools)'
ExecStart=/opt/fc-tools/guest-supervisor -port %d
Restart=always
RestartSec=0.2

[Install]
WantedBy=multi-user.target
`

// toolsLabel is the filesystem label of the content-addressed tools drive.
const toolsLabel = "fc-tools"

// sha256File returns the hex sha256 of the file at path.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// buildToolsImage creates an ext4 image at imgPath containing the
// guest-supervisor binary at /guest-supervisor (mode 0755), filesystem
// label fc-tools, using mkfs.ext4 + debugfs (no root required).
func buildToolsImage(imgPath, supervisorBin string) error {
	sizeMiB := int64(8)
	if fi, err := os.Stat(supervisorBin); err == nil {
		sizeMiB = fi.Size()/(1<<20)*2 + 8
	}
	img, err := os.Create(imgPath)
	if err != nil {
		return err
	}
	if err := img.Truncate(sizeMiB << 20); err != nil {
		img.Close()
		return err
	}
	img.Close()
	if out, err := exec.Command("mkfs.ext4", "-q", "-F", "-L", toolsLabel, imgPath).CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.ext4 tools: %v: %s", err, out)
	}
	tmp, err := os.MkdirTemp("", "fc-tools-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	script := filepath.Join(tmp, "cmds")
	body := "write " + supervisorBin + " /guest-supervisor\n" +
		"sif /guest-supervisor mode 0100755\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		return err
	}
	if out, err := exec.Command("debugfs", "-w", "-f", script, imgPath).CombinedOutput(); err != nil {
		return fmt.Errorf("debugfs tools inject: %v: %s", err, out)
	}
	return nil
}

// ensureToolsImage returns the path of this backend's shared, read-only
// tools ext4 image (P0.3) and the sha256 of the supervisor binary it was
// built from. The image is content-addressed
// (<Root>/tools/tools-<sha256>.ext4): one file serves every incarnation,
// replacing the old per-incarnation ~3MB debugfs injection into each
// rootfs copy. Built once per content via tmp+rename, so a crashed build
// never leaves a partial image behind (the .tmp file is cleaned up on the
// next build attempt). Tools images are never deleted: a snapshot's saved
// VMM state references the image path, so restore depends on it surviving
// (GC of unreferenced images is a documented follow-up).
func (b *Backend) ensureToolsImage() (string, string, error) {
	sha, err := sha256File(b.cfg.GuestSupervisorBin)
	if err != nil {
		return "", "", fmt.Errorf("guest supervisor binary: %w", err)
	}
	b.toolsMu.Lock()
	defer b.toolsMu.Unlock()
	dir := filepath.Join(b.cfg.Root, "tools")
	img := filepath.Join(dir, "tools-"+sha+".ext4")
	if _, err := os.Stat(img); err == nil {
		return img, sha, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	tmp := img + ".tmp"
	os.Remove(tmp) // clean up a crashed earlier build
	if err := buildToolsImage(tmp, b.cfg.GuestSupervisorBin); err != nil {
		os.Remove(tmp)
		return "", "", err
	}
	if err := os.Rename(tmp, img); err != nil {
		os.Remove(tmp)
		return "", "", err
	}
	return img, sha, nil
}

// injectGuestAgentUnit writes the guest-supervisor systemd unit into a
// rootfs image copy. The unit mounts the shared tools drive and runs the
// supervisor from it; the binary itself is no longer injected per
// incarnation (P0.3). Must run after injectWorkspaceUnit (the unit
// Requires/Afters it) and after the journal recovery it performs.
func injectGuestAgentUnit(rootfsPath, incarnationID string, port uint32) error {
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
	body := "write " + unit + " /etc/systemd/system/guest-supervisor.service\n" +
		"symlink /etc/systemd/system/multi-user.target.wants/guest-supervisor.service /etc/systemd/system/guest-supervisor.service\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		return err
	}
	if out, err := exec.Command("debugfs", "-w", "-f", script, rootfsPath).CombinedOutput(); err != nil {
		return fmt.Errorf("debugfs agent inject: %v: %s", err, out)
	}
	return nil
}

// injectNetworkUnit writes the guest NIC bring-up unit into a rootfs image.
// The guest resolver is the TAP host address: the incarnation's
// DNS-learning proxy listens there.
func injectNetworkUnit(rootfsPath, guestIP, hostIP string) error {
	tmp, err := os.MkdirTemp("", "fc-net-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	unit := filepath.Join(tmp, "unit")
	if err := os.WriteFile(unit, []byte(fmt.Sprintf(networkUnitTemplate, hostIP, guestIP, hostIP)), 0o644); err != nil {
		return err
	}
	script := filepath.Join(tmp, "cmds")
	body := "write " + unit + " /etc/systemd/system/agent-network.service\n" +
		"symlink /etc/systemd/system/multi-user.target.wants/agent-network.service /etc/systemd/system/agent-network.service\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		return err
	}
	if out, err := exec.Command("debugfs", "-w", "-f", script, rootfsPath).CombinedOutput(); err != nil {
		return fmt.Errorf("debugfs network unit inject: %v: %s", err, out)
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
