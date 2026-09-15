package firecrackerbackend

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Jailer support (ADR-0001 hardening gate): when Config.JailerBin is set,
// VMMs spawn through the Firecracker jailer (chroot + mount/PID namespaces +
// cgroup v2 confinement) instead of raw exec. The jailer must run as root
// (passwordless sudo); it drops to the invoking user's uid/gid so jail
// artifacts stay manageable by the backend. If jailer spawn fails the
// backend falls back to a raw spawn and records JailerWarning — capabilities
// and logs reflect what is actually enforced.
//
// Layout per incarnation: <ChrootBase>/firecracker/<id>/root/ containing
// hardlinked kernel/rootfs/workspace images; Firecracker API paths are
// jail-relative ("/rootfs.ext4" etc.), host paths are the jail-root paths.

type vmmLayout struct {
	hostDir   string // host-side dir holding console.log and drive files
	hostSock  string // host-side api.sock
	hostVsock string // host-side vsock uds
	apiSock   string // api path as the (possibly jailed) VMM sees it
	apiVsock  string
	apiKernel string
	apiRootfs string
	apiWS     string
	apiTools  string
	jailed    bool
	jailRoot  string
}

func (b *Backend) jailerUsable() bool {
	if b.cfg.JailerBin == "" {
		return false
	}
	if b.jailerFailed != "" {
		return false
	}
	return true
}

// layoutFor computes host and API paths for an incarnation, depending on
// whether the jailer is in use.
func (b *Backend) layoutFor(inc *incarnation) vmmLayout {
	if !inc.jailed {
		return vmmLayout{
			hostDir:   inc.dir,
			hostSock:  filepath.Join(inc.dir, "api.sock"),
			hostVsock: filepath.Join(inc.dir, "vsock.sock"),
			apiSock:   filepath.Join(inc.dir, "api.sock"),
			apiVsock:  filepath.Join(inc.dir, "vsock.sock"),
			apiKernel: b.cfg.KernelPath,
			apiRootfs: filepath.Join(inc.dir, "rootfs.ext4"),
			apiWS:     filepath.Join(inc.dir, "workspace.img"),
			// The tools image is content-addressed and read-only, so the
			// VMM opens the single shared file directly (no per-VM copy).
			apiTools: inc.toolsImage,
		}
	}
	root := inc.jailRoot
	return vmmLayout{
		hostDir:   root,
		hostSock:  filepath.Join(root, "api.sock"),
		hostVsock: filepath.Join(root, "vsock.sock"),
		apiSock:   "/api.sock",
		apiVsock:  "/vsock.sock",
		apiKernel: "/vmlinux",
		apiRootfs: "/rootfs.ext4",
		apiWS:     "/workspace.img",
		apiTools:  "/tools.ext4",
		jailed:    true,
		jailRoot:  root,
	}
}

func linkOrCopy(dst, src string) error {
	os.Remove(dst)
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	return copyFile(dst, src)
}

// prepareJail builds the jailer chroot layout for inc and returns the jail
// root. Drive files are hardlinked from the incarnation dir (no extra 300MB
// copies). A stale jail tree (crash leftover) is unmounted and removed
// first; removal errors are NOT ignored (FM6).
func (b *Backend) prepareJail(inc *incarnation) (string, error) {
	base := b.cfg.ChrootBase
	if base == "" {
		base = filepath.Join(b.cfg.Root, "jails")
	}
	root := filepath.Join(base, "firecracker", inc.id, "root")
	jailDir := filepath.Join(base, "firecracker", inc.id)
	// A leftover /snap bind mount makes RemoveAll fail with EBUSY: unmount
	// first (best-effort), then remove, and treat a remaining failure as
	// fatal rather than stacking state on a dirty tree.
	unmountRetry(filepath.Join(root, "snap"))
	if err := os.RemoveAll(jailDir); err != nil {
		sudo("rm", "-rf", jailDir).Run()
		if _, serr := os.Stat(jailDir); serr == nil {
			return "", fmt.Errorf("stale jail tree %s not removable: %v", jailDir, err)
		}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	if err := linkOrCopy(filepath.Join(root, "vmlinux"), b.cfg.KernelPath); err != nil {
		return "", err
	}
	if err := linkOrCopy(filepath.Join(root, "rootfs.ext4"), filepath.Join(inc.dir, "rootfs.ext4")); err != nil {
		return "", err
	}
	if err := linkOrCopy(filepath.Join(root, "workspace.img"), filepath.Join(inc.dir, "workspace.img")); err != nil {
		return "", err
	}
	if inc.toolsImage != "" {
		// P0.3: share the read-only tools image into the jail; the saved
		// VMM state references the jail-relative path /tools.ext4.
		if err := linkOrCopy(filepath.Join(root, "tools.ext4"), inc.toolsImage); err != nil {
			return "", err
		}
	}
	return root, nil
}

// spawnJailed starts the VMM through the jailer. The jailer runs via
// passwordless sudo and drops privileges to the current uid/gid.
func (b *Backend) spawnJailed(inc *incarnation, l vmmLayout) (*exec.Cmd, *os.File, error) {
	console, err := os.OpenFile(filepath.Join(inc.dir, "console.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, err
	}
	uid, gid := os.Getuid(), os.Getgid()
	args := []string{"-n", b.cfg.JailerBin,
		"--id", inc.id,
		"--exec-file", b.cfg.FirecrackerBin,
		"--uid", fmt.Sprint(uid),
		"--gid", fmt.Sprint(gid),
		"--cgroup-version", "2",
	}
	if b.cfg.ChrootBase != "" {
		args = append(args, "--chroot-base-dir", b.cfg.ChrootBase)
	} else {
		args = append(args, "--chroot-base-dir", filepath.Join(b.cfg.Root, "jails"))
	}
	args = append(args, "--", "--api-sock", l.apiSock)
	cmd := exec.Command("sudo", args...)
	cmd.Stdout = console
	cmd.Stderr = console
	// New process group so Terminate can SIGKILL sudo+jailer+firecracker.
	cmd.SysProcAttr = sysProcAttrNewGroup()
	if err := cmd.Start(); err != nil {
		console.Close()
		return nil, nil, fmt.Errorf("spawn jailer: %w", err)
	}
	return cmd, console, nil
}

// jailerProbe checks once whether the jailer path can work here.
func jailerProbe(bin string) error {
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("jailer not found: %v", err)
	}
	if out, err := sudo("true").CombinedOutput(); err != nil {
		return fmt.Errorf("jailer requires passwordless sudo: %v: %s", err, out)
	}
	return nil
}

// bindMount bind-mounts hostDir onto target (snapshot sharing into a jail).
// Idempotent: the per-incarnation <jail>/snap mount survives from Restore
// through later Snapshots of the same incarnation, and mount --bind onto an
// occupied mountpoint STACKS rather than replacing — so an existing mount
// is reused, never stacked (FM6).
func bindMount(hostDir, target string) error {
	if mountpointPresent(target) {
		return nil
	}
	if err := os.MkdirAll(target, 0o700); err != nil {
		return err
	}
	if out, err := sudo("mount", "--bind", hostDir, target).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "already mounted") {
			return nil
		}
		return fmt.Errorf("bind mount %s -> %s: %v: %s", hostDir, target, err, out)
	}
	return nil
}

// mountpointPresent reports whether target appears in this process's mount
// table.
func mountpointPresent(target string) bool {
	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == target {
			return true
		}
	}
	return false
}

// unmountRetry lazy-detaches target, retrying briefly: the bind mount lives
// in a shared peer group with the jailer's mount namespace, and that
// namespace's teardown lags the jailer's death (RCU) — an immediate umount
// can fail EINVAL while the peer reference settles (FM6). A mount that
// survives all retries is logged loudly, never silently stacked.
func unmountRetry(target string) {
	if !mountpointPresent(target) {
		return
	}
	var last []byte
	for i := 0; i < 20; i++ {
		out, err := sudo("umount", "-l", target).CombinedOutput()
		if err == nil || strings.Contains(string(out), "not mounted") {
			return
		}
		last = out
		time.Sleep(50 * time.Millisecond)
	}
	if mountpointPresent(target) {
		fmt.Fprintf(os.Stderr, "firecrackerbackend: umount %s failed after retries: %s\n", target, last)
	}
}

// cleanupJail unmounts the snapshot bind mount and removes the jail tree
// for inc. Safe to call on non-jailed incarnations. The inc.jailRoot swap
// happens under b.mu (FL12); the blocking umount/rm do not (FL7).
func (b *Backend) cleanupJail(inc *incarnation) {
	b.mu.Lock()
	root := inc.jailRoot
	inc.jailRoot = ""
	inc.jailed = false
	b.mu.Unlock()
	if root == "" {
		return
	}
	unmountRetry(filepath.Join(root, "snap"))
	base := b.cfg.ChrootBase
	if base == "" {
		base = filepath.Join(b.cfg.Root, "jails")
	}
	jailDir := filepath.Join(base, "firecracker", inc.id)
	// The jailer leaves root-owned dirs inside the jail tree (e.g. the
	// /sys skeleton), so removal may need privileges.
	if err := os.RemoveAll(jailDir); err != nil {
		sudo("rm", "-rf", jailDir).Run()
	}
}

// sweepStaleJails reclaims jail state leaked by a crashed backend process
// (FM11): any /snap bind mount under the chroot base recorded in
// /proc/mounts is unmounted, then every jail tree matching the incarnation
// naming convention is removed. Errors are logged loudly, never fatal.
func (b *Backend) sweepStaleJails() {
	base := b.cfg.ChrootBase
	if base == "" {
		base = filepath.Join(b.cfg.Root, "jails")
	}
	if data, err := os.ReadFile("/proc/mounts"); err == nil {
		prefix := filepath.Join(base, "firecracker") + "/"
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			mp := fields[1]
			if strings.HasPrefix(mp, prefix) && strings.HasSuffix(mp, "/snap") {
				fmt.Fprintf(os.Stderr, "firecrackerbackend: crash sweep: unmounting stale jail bind %s\n", mp)
				unmountRetry(mp)
			}
		}
	}
	entries, err := os.ReadDir(filepath.Join(base, "firecracker"))
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || validateIncarnationID(e.Name()) != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "firecrackerbackend: crash sweep: removing stale jail tree %s\n", e.Name())
		dir := filepath.Join(base, "firecracker", e.Name())
		if err := os.RemoveAll(dir); err != nil {
			sudo("rm", "-rf", dir).Run()
		}
	}
}
