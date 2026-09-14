package firecrackerbackend

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/runtime/backend-interface"
	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

// incarnationIDPattern whitelists IDs before they touch filesystem paths,
// jailer arguments, systemd unit injection, or `sudo rm -rf` jail cleanup.
// The `..` check is defense in depth on top of the character class.
var incarnationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func validateIncarnationID(id string) error {
	if !incarnationIDPattern.MatchString(id) || strings.Contains(id, "..") {
		return fmt.Errorf("firecrackerbackend: invalid incarnation ID %q", id)
	}
	return nil
}

const (
	defaultBootArgs    = "console=ttyS0 reboot=k panic=1 pci=off"
	snapshotClass      = "firecracker_full"
	consoleLoginMarker = "login:"
)

// Config configures a Backend. KernelPath, RootfsPath and FirecrackerBin are
// required; everything else has a default.
type Config struct {
	// Root holds per-incarnation dirs and snapshot dirs.
	// Default: /tmp/fc-backend-<uid>.
	Root           string
	KernelPath     string
	RootfsPath     string
	FirecrackerBin string
	// JailerBin, when set, spawns VMMs through the Firecracker jailer
	// (chroot + namespaces + cgroup v2) via passwordless sudo. If the
	// jailer cannot be used the backend falls back to raw spawns and
	// records the reason in JailerStatus.
	JailerBin string
	// ChrootBase is the jailer chroot base dir; default <Root>/jails.
	ChrootBase string
	// Networking attaches a per-incarnation TAP device with host NAT and
	// an iptables egress chain enforcing network.EgressPolicy (from
	// Spec.Env["AGENT_SANDBOX_EGRESS"]). Requires passwordless sudo and
	// ip/iptables. When false no NIC exists at all (fail-closed).
	Networking bool
	// MaxSnapshotsPerIncarnation bounds retained snapshots per incarnation
	// (oldest GC'd after each Snapshot); default 3, <=0 keeps all.
	MaxSnapshotsPerIncarnation int
	// DeleteSnapshotsOnTerminate also removes the incarnation's snapshots
	// on Terminate (default false: committed checkpoints survive).
	DeleteSnapshotsOnTerminate bool
	BootArgs                   string // default: smoke-tested "console=ttyS0 reboot=k panic=1 pci=off"
	VCPUs                      int64  // default 1
	// DefaultMemMiB applies when Spec.MemoryBytes is 0; default 256.
	DefaultMemMiB int64
	BootTimeout   time.Duration // default 90s
	APITimeout    time.Duration // default 10s
	// VsockBaseCID is the first guest CID assigned to vsock devices
	// (provisioned for the stage-3 supervisor transport); default 3.
	VsockBaseCID uint32
	// GuestSupervisorBin is the path of a static linux guest-supervisor
	// daemon binary injected into every incarnation rootfs and started at
	// boot; when empty the Exec data path stays unsupported (stage-2 mode).
	GuestSupervisorBin string
	// SupervisorPort is the vsock port the in-guest supervisor listens on;
	// default 5000.
	SupervisorPort uint32
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.Root == "" {
		out.Root = fmt.Sprintf("/tmp/fc-backend-%d", os.Getuid())
	}
	if out.BootArgs == "" {
		out.BootArgs = defaultBootArgs
	}
	if out.VCPUs == 0 {
		out.VCPUs = 1
	}
	if out.DefaultMemMiB == 0 {
		out.DefaultMemMiB = 256
	}
	if out.BootTimeout == 0 {
		out.BootTimeout = 90 * time.Second
	}
	if out.APITimeout == 0 {
		out.APITimeout = 10 * time.Second
	}
	if out.VsockBaseCID == 0 {
		out.VsockBaseCID = 3
	}
	if out.SupervisorPort == 0 {
		out.SupervisorPort = 5000
	}
	if out.MaxSnapshotsPerIncarnation == 0 {
		out.MaxSnapshotsPerIncarnation = 3
	}
	return out
}

type incarnation struct {
	id        string
	spec      backendinterface.Spec
	dir       string
	cmd       *exec.Cmd
	console   *os.File
	started   bool
	paused    bool
	dead      bool
	exited    chan struct{}
	startedAt time.Time
	wsMirror  map[string]string
	dirty     bool
	ops       map[string]domain.Operation
	vsockCID  uint32
	sup       *vsockSupervisor
	jailed    bool
	jailRoot  string
	net       *netState
	// opMu serializes guest-mutating operations (Exec writes/commands)
	// against the pause/snapshot window: Snapshot holds it across
	// pause+snapshotCreate so an Exec either fully lands in the guest before
	// the pause, or blocks and then fails with ErrIllegalState once paused —
	// never half-applied mid-snapshot (wsMirror/guest divergence, INV-006).
	opMu sync.Mutex
}

// Backend is a Firecracker-microVM RuntimeBackend (IsolationClass VM).
type Backend struct {
	cfg     Config
	mu      sync.Mutex
	incs    map[string]*incarnation
	nextCID uint32
	// jailerFailed records why the jailer is not in use (empty = jailer
	// active or not configured); surfaced via JailerStatus.
	jailerFailed string
}

// JailerStatus reports the jailer fallback reason ("" when the jailer is
// active or was never configured).
func (b *Backend) JailerStatus() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.jailerFailed
}

// New creates a Backend storing incarnation state under cfg.Root.
func New(cfg Config) (*Backend, error) {
	c := cfg.withDefaults()
	if c.KernelPath == "" || c.RootfsPath == "" || c.FirecrackerBin == "" {
		return nil, fmt.Errorf("firecrackerbackend: KernelPath, RootfsPath and FirecrackerBin are required")
	}
	if err := os.MkdirAll(filepath.Join(c.Root, "snapshots"), 0o755); err != nil {
		return nil, err
	}
	if c.Networking {
		if err := checkNetPrereqs(); err != nil {
			return nil, err
		}
	}
	b := &Backend{cfg: c, incs: map[string]*incarnation{}, nextCID: c.VsockBaseCID}
	if c.JailerBin != "" {
		if err := jailerProbe(c.JailerBin); err != nil {
			b.jailerFailed = err.Error()
			fmt.Fprintf(os.Stderr, "firecrackerbackend: jailer disabled, using raw spawns: %v\n", err)
		}
	}
	return b, nil
}

// Capabilities declares this backend's isolation surface (ADR-0001).
func (b *Backend) Capabilities() backendinterface.Capabilities {
	return backendinterface.Capabilities{
		IsolationClass:     backendinterface.IsolationVM,
		SupportsPause:      true,
		SupportsSnapshot:   true,
		SupportsRestore:    true,
		SupportsCheckpoint: true,
		// Full VM snapshots go to disk; after capture the VMM can be
		// terminated and its RAM honestly reclaimed, with Restore booting
		// back from the snapshot.
		CheckpointReclaimsMemory: true,
		// With Networking off no NIC is attached at all (nothing to
		// isolate, fail-closed); with it on, guest traffic is confined
		// to a per-incarnation TAP behind a host egress chain.
		NetworkIsolated:    b.cfg.Networking,
		HostCredentialFree: true,
	}
}

func (b *Backend) get(h backendinterface.Handle) (*incarnation, error) {
	inc, ok := b.incs[h.IncarnationID]
	if !ok {
		return nil, backendinterface.ErrNotFound
	}
	if inc.dead {
		return nil, backendinterface.ErrRuntimeGone
	}
	return inc, nil
}

// Create materializes the per-incarnation directory: a private rootfs copy
// (with the workspace mount unit injected) and a workspace ext4 image built
// from Spec.WorkspaceManifest. When networking is enabled it also reserves
// the incarnation's network slot, so the guest network unit baked into the
// rootfs matches the TAP the VM gets at Start.
func (b *Backend) Create(spec backendinterface.Spec) (backendinterface.Handle, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := validateIncarnationID(spec.IncarnationID); err != nil {
		return backendinterface.Handle{}, err
	}
	if _, exists := b.incs[spec.IncarnationID]; exists {
		return backendinterface.Handle{}, fmt.Errorf("firecrackerbackend: incarnation %q already exists", spec.IncarnationID)
	}
	dir := filepath.Join(b.cfg.Root, spec.IncarnationID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return backendinterface.Handle{}, err
	}
	fail := func(err error) (backendinterface.Handle, error) {
		if inc := b.incs[spec.IncarnationID]; inc != nil && inc.net != nil {
			releaseSlot(inc.id, inc.net)
		}
		delete(b.incs, spec.IncarnationID)
		os.RemoveAll(dir)
		return backendinterface.Handle{}, err
	}
	rootfs := filepath.Join(dir, "rootfs.ext4")
	if err := copyFile(rootfs, b.cfg.RootfsPath); err != nil {
		return fail(err)
	}
	if err := injectWorkspaceUnit(rootfs); err != nil {
		return fail(err)
	}
	if b.cfg.GuestSupervisorBin != "" {
		if err := injectGuestAgent(rootfs, b.cfg.GuestSupervisorBin, spec.IncarnationID, b.cfg.SupervisorPort); err != nil {
			return fail(err)
		}
	}
	inc := &incarnation{
		id:       spec.IncarnationID,
		spec:     spec,
		dir:      dir,
		wsMirror: map[string]string{},
		ops:      map[string]domain.Operation{},
	}
	for k, v := range spec.WorkspaceManifest {
		inc.wsMirror[k] = v
	}
	b.incs[spec.IncarnationID] = inc
	if b.cfg.Networking {
		if err := b.allocateNetworking(inc, preferredSlot(spec.IncarnationID)); err != nil {
			delete(b.incs, spec.IncarnationID)
			os.RemoveAll(dir)
			return backendinterface.Handle{}, err
		}
		if err := injectNetworkUnit(rootfs, inc.net.guestIP, inc.net.hostIP); err != nil {
			return fail(err)
		}
	}
	if err := buildWorkspaceImage(filepath.Join(dir, "workspace.img"), spec.WorkspaceManifest); err != nil {
		return fail(err)
	}
	return backendinterface.Handle{IncarnationID: spec.IncarnationID}, nil
}

// spawn starts the firecracker process for inc — through the jailer when
// configured and usable, raw otherwise — and waits for the API socket.
// Called without holding b.mu; bookkeeping that needs the lock takes it.
func (b *Backend) spawn(inc *incarnation) error {
	var cmd *exec.Cmd
	var console *os.File
	if b.jailerUsable() {
		root, err := b.prepareJail(inc)
		if err == nil {
			inc.jailed = true
			inc.jailRoot = root
			cmd, console, err = b.spawnJailed(inc, b.layoutFor(inc))
		}
		if err != nil {
			inc.jailed = false
			inc.jailRoot = ""
			b.mu.Lock()
			b.jailerFailed = err.Error()
			b.mu.Unlock()
			fmt.Fprintf(os.Stderr, "firecrackerbackend: jailer spawn failed, falling back to raw spawn: %v\n", err)
			cmd = nil
		}
	}
	l := b.layoutFor(inc)
	if cmd == nil {
		var err error
		os.Remove(l.hostSock)
		console, err = os.OpenFile(filepath.Join(inc.dir, "console.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		cmd = exec.Command(b.cfg.FirecrackerBin, "--api-sock", l.apiSock)
		cmd.Stdout = console
		cmd.Stderr = console
		if err := cmd.Start(); err != nil {
			console.Close()
			return fmt.Errorf("spawn firecracker: %w", err)
		}
	}
	inc.cmd = cmd
	inc.console = console
	inc.exited = make(chan struct{})
	go func() {
		cmd.Wait()
		console.Close()
		close(inc.exited)
	}()
	// Wait for the API socket to come up, failing fast on process exit.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(l.hostSock); err == nil {
			return nil
		}
		select {
		case <-inc.exited:
			return fmt.Errorf("firecracker exited before API socket appeared: %s", tailConsole(inc.dir))
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			b.killProc(inc)
			return fmt.Errorf("timeout waiting for firecracker API socket")
		}
	}
}

func (b *Backend) api(inc *incarnation) *apiClient {
	return newAPIClient(b.layoutFor(inc).hostSock, b.cfg.APITimeout)
}

func (b *Backend) memMiB(spec backendinterface.Spec) int64 {
	mib := spec.MemoryBytes / (1 << 20)
	if mib <= 0 {
		mib = b.cfg.DefaultMemMiB
	}
	if mib < 128 {
		mib = 128
	}
	return mib
}

func (b *Backend) configureNew(inc *incarnation) error {
	l := b.layoutFor(inc)
	api := b.api(inc)
	if err := api.setBootSource(l.apiKernel, b.cfg.BootArgs); err != nil {
		return err
	}
	if err := api.setMachineConfig(b.cfg.VCPUs, b.memMiB(inc.spec)); err != nil {
		return err
	}
	if err := api.addDrive("rootfs", l.apiRootfs, true, false); err != nil {
		return err
	}
	if err := api.addDrive("workspace", l.apiWS, false, false); err != nil {
		return err
	}
	if inc.net != nil {
		if err := api.addNIC("eth0", inc.net.tap, inc.net.mac); err != nil {
			return err
		}
	}
	return api.setVsock(inc.vsockCID, l.apiVsock)
}

// waitConsole polls the console log for marker until timeout, process exit,
// or API death. Used for boot readiness.
func (b *Backend) waitConsole(inc *incarnation, marker string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		data, _ := os.ReadFile(filepath.Join(inc.dir, "console.log"))
		if strings.Contains(string(data), marker) {
			return nil
		}
		select {
		case <-inc.exited:
			return fmt.Errorf("firecracker exited while waiting for %q: %s", marker, tailConsole(inc.dir))
		case <-time.After(200 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for console marker %q: %s", marker, tailConsole(inc.dir))
		}
	}
}

func tailConsole(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "console.log"))
	if err != nil {
		return "(no console log)"
	}
	s := string(data)
	if len(s) > 2000 {
		s = s[len(s)-2000:]
	}
	return s
}

// attachSupervisor connects to the in-guest supervisor over vsock and waits
// for its Health check, polling until BootTimeout. Called after boot and
// after snapshot restore (Firecracker restores vsock; fresh dials reconnect
// transparently).
func (b *Backend) attachSupervisor(inc *incarnation) error {
	sup := newVsockSupervisor(b.layoutFor(inc).hostVsock, b.cfg.SupervisorPort, b.cfg.APITimeout)
	sup.alive = func() bool {
		// Read under b.mu: spawn reassigns inc.exited on (re)boot.
		b.mu.Lock()
		defer b.mu.Unlock()
		select {
		case <-inc.exited:
			return false
		default:
			return true
		}
	}
	deadline := time.Now().Add(b.cfg.BootTimeout)
	var lastErr error
	for {
		if err := sup.Health(); err == nil {
			b.mu.Lock()
			inc.sup = sup
			b.mu.Unlock()
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-inc.exited:
			return fmt.Errorf("firecracker exited waiting for guest supervisor: %s", tailConsole(inc.dir))
		case <-time.After(250 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for guest supervisor health: %v: %s", lastErr, tailConsole(inc.dir))
		}
	}
}

// supFor returns the incarnation's supervisor transport or
// supervisor.ErrUnsupported when no guest agent was injected (stage-2 mode).
func (b *Backend) supFor(inc *incarnation) (*vsockSupervisor, error) {
	if inc.sup == nil {
		return nil, supervisor.ErrUnsupported
	}
	return inc.sup, nil
}

// Start boots the microVM and blocks until the guest reaches its login
// prompt (serial console) or BootTimeout elapses.
func (b *Backend) Start(h backendinterface.Handle) error {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return err
	}
	if inc.started {
		b.mu.Unlock()
		return backendinterface.ErrIllegalState
	}
	inc.started = true // a failed boot still consumes the incarnation
	b.nextCID++
	inc.vsockCID = b.nextCID
	b.mu.Unlock()

	if b.cfg.Networking {
		if err := b.setupNetworking(inc); err != nil {
			return err
		}
	}
	fail := func(err error) error {
		b.killProc(inc)
		b.teardownNetworking(inc)
		return err
	}
	if err := b.spawn(inc); err != nil {
		b.teardownNetworking(inc)
		return err
	}
	if err := b.configureNew(inc); err != nil {
		return fail(err)
	}
	if err := b.api(inc).action("InstanceStart"); err != nil {
		return fail(err)
	}
	if err := b.waitConsole(inc, consoleLoginMarker, b.cfg.BootTimeout); err != nil {
		return fail(err)
	}
	if b.cfg.GuestSupervisorBin != "" {
		if err := b.attachSupervisor(inc); err != nil {
			return fail(err)
		}
	}
	b.mu.Lock()
	inc.startedAt = time.Now()
	b.mu.Unlock()
	return nil
}

// Pause halts the vCPUs via the Firecracker API (RAM stays allocated).
func (b *Backend) Pause(h backendinterface.Handle) error {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return err
	}
	if !inc.started || inc.paused {
		b.mu.Unlock()
		return backendinterface.ErrIllegalState
	}
	b.mu.Unlock()
	if err := b.api(inc).setVMState("Paused"); err != nil {
		return err
	}
	b.mu.Lock()
	inc.paused = true
	b.mu.Unlock()
	return nil
}

// Resume unpauses the vCPUs.
func (b *Backend) Resume(h backendinterface.Handle) error {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return err
	}
	if !inc.paused {
		b.mu.Unlock()
		return backendinterface.ErrIllegalState
	}
	b.mu.Unlock()
	if err := b.api(inc).setVMState("Resumed"); err != nil {
		return err
	}
	b.mu.Lock()
	inc.paused = false
	b.mu.Unlock()
	return nil
}

type snapshotMeta struct {
	Spec      backendinterface.Spec `json:"spec"`
	CreatedAt time.Time             `json:"created_at"`
	// NetSlot records the network slot baked into the snapshot's net
	// device config (TAP name/MAC/guest IP); restore must reuse it.
	NetSlot *int `json:"net_slot,omitempty"`
}

func (b *Backend) snapshotDir(incarnationID string) string {
	return filepath.Join(b.cfg.Root, "snapshots", incarnationID)
}

// gcSnapshots retains only the newest MaxSnapshotsPerIncarnation snapshot
// dirs for an incarnation (dir names are unix-nanosecond timestamps, so
// lexicographic order is chronological).
func (b *Backend) gcSnapshots(incarnationID string) {
	max := b.cfg.MaxSnapshotsPerIncarnation
	if max <= 0 {
		return
	}
	root := b.snapshotDir(incarnationID)
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	for len(dirs) > max {
		os.RemoveAll(filepath.Join(root, dirs[0]))
		dirs = dirs[1:]
	}
}

// Snapshot captures a full VM checkpoint: the VM is paused if running, then
// memory + vCPU state plus reflink copies of both drives are stored under
// <root>/snapshots/<incarnation>/<ts>, surviving Terminate of the source VM.
// The VM stays paused afterwards (mirror of the local backend's contract).
// Oldest snapshots beyond MaxSnapshotsPerIncarnation are garbage-collected.
func (b *Backend) Snapshot(h backendinterface.Handle) (backendinterface.CheckpointData, error) {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return backendinterface.CheckpointData{}, err
	}
	if !inc.started {
		b.mu.Unlock()
		return backendinterface.CheckpointData{}, backendinterface.ErrIllegalState
	}
	wasRunning := !inc.paused
	b.mu.Unlock()

	// Hold the op mutex across pause + drive copy + snapshotCreate so no
	// Exec can be mid-flight against the guest while its memory and disks
	// are captured (racing writes would be lost or half-applied, INV-006).
	inc.opMu.Lock()
	defer inc.opMu.Unlock()

	if wasRunning {
		if err := b.Pause(h); err != nil {
			return backendinterface.CheckpointData{}, err
		}
	}
	ts := fmt.Sprint(time.Now().UnixNano())
	snapRoot := b.snapshotDir(inc.id)
	snapDir := filepath.Join(snapRoot, ts)
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		return backendinterface.CheckpointData{}, err
	}
	// Disk state must be captured alongside memory: copy both drives while
	// the VM is paused (reflink where the fs supports it).
	if err := copyFile(filepath.Join(snapDir, "rootfs.ext4"), filepath.Join(inc.dir, "rootfs.ext4")); err != nil {
		return backendinterface.CheckpointData{}, err
	}
	if err := copyFile(filepath.Join(snapDir, "workspace.img"), filepath.Join(inc.dir, "workspace.img")); err != nil {
		return backendinterface.CheckpointData{}, err
	}
	memPath := filepath.Join(snapDir, "mem.file")
	statePath := filepath.Join(snapDir, "vm.state")
	if inc.jailed {
		// A jailed VMM can only write inside its chroot: share the
		// incarnation's snapshot dir via bind mount.
		if err := bindMount(snapRoot, filepath.Join(inc.jailRoot, "snap")); err != nil {
			return backendinterface.CheckpointData{}, err
		}
		memPath = "/snap/" + ts + "/mem.file"
		statePath = "/snap/" + ts + "/vm.state"
	}
	if err := b.api(inc).snapshotCreate(memPath, statePath); err != nil {
		return backendinterface.CheckpointData{}, err
	}
	meta := snapshotMeta{Spec: inc.spec, CreatedAt: time.Now()}
	if inc.net != nil {
		slot := inc.net.slot
		meta.NetSlot = &slot
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return backendinterface.CheckpointData{}, err
	}
	if err := os.WriteFile(filepath.Join(snapDir, "meta.json"), metaBytes, 0o644); err != nil {
		return backendinterface.CheckpointData{}, err
	}
	b.gcSnapshots(inc.id)
	b.mu.Lock()
	files := map[string]string{}
	for k, v := range inc.wsMirror {
		files[k] = v
	}
	b.mu.Unlock()
	return backendinterface.CheckpointData{
		IncarnationID: inc.id,
		Files:         files,
		Metadata: map[string]string{
			"class":        snapshotClass,
			"snapshot_dir": snapDir,
		},
	}, nil
}

// Restore boots a fresh firecracker process from a full snapshot taken by
// Snapshot. Any still-running process for the incarnation is killed first
// (crash-recovery path, INV-009).
func (b *Backend) Restore(cp backendinterface.CheckpointData) (backendinterface.Handle, error) {
	if cp.Metadata["class"] != snapshotClass {
		return backendinterface.Handle{}, fmt.Errorf("unsupported checkpoint class %q", cp.Metadata["class"])
	}
	if err := validateIncarnationID(cp.IncarnationID); err != nil {
		return backendinterface.Handle{}, err
	}
	snapDir := cp.Metadata["snapshot_dir"]
	metaBytes, err := os.ReadFile(filepath.Join(snapDir, "meta.json"))
	if err != nil {
		return backendinterface.Handle{}, fmt.Errorf("checkpoint metadata unreadable: %w", err)
	}
	var meta snapshotMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return backendinterface.Handle{}, fmt.Errorf("checkpoint metadata corrupt: %w", err)
	}
	b.mu.Lock()
	inc, ok := b.incs[cp.IncarnationID]
	if ok && !inc.dead && inc.cmd != nil {
		b.killProcLocked(inc)
	}
	if !ok {
		inc = &incarnation{id: cp.IncarnationID, ops: map[string]domain.Operation{}, wsMirror: map[string]string{}}
		b.incs[cp.IncarnationID] = inc
	}
	inc.spec = meta.Spec
	inc.dead = false
	inc.paused = false
	inc.started = true
	for k, v := range cp.Files {
		inc.wsMirror[k] = v
	}
	b.nextCID++
	inc.vsockCID = b.nextCID
	dir := filepath.Join(b.cfg.Root, cp.IncarnationID)
	inc.dir = dir
	inc.jailed = false
	inc.jailRoot = ""
	b.mu.Unlock()

	// Networking: reallocate the slot recorded in the snapshot metadata so
	// the TAP name/MAC/guest IP match the net device config the snapshot
	// restores; the policy comes from the restored spec.
	if b.cfg.Networking {
		b.teardownNetworking(inc)
		preferred := preferredSlot(inc.id)
		if meta.NetSlot != nil {
			preferred = *meta.NetSlot
		}
		if err := b.allocateNetworking(inc, preferred); err != nil {
			return backendinterface.Handle{}, err
		}
		if err := b.setupNetworking(inc); err != nil {
			return backendinterface.Handle{}, err
		}
	}
	fail := func(err error) error {
		b.killProc(inc)
		b.teardownNetworking(inc)
		b.cleanupJail(inc)
		return err
	}
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return backendinterface.Handle{}, err
	}
	if err := copyFile(filepath.Join(dir, "rootfs.ext4"), filepath.Join(snapDir, "rootfs.ext4")); err != nil {
		return backendinterface.Handle{}, fail(err)
	}
	if err := copyFile(filepath.Join(dir, "workspace.img"), filepath.Join(snapDir, "workspace.img")); err != nil {
		return backendinterface.Handle{}, fail(err)
	}
	if err := b.spawn(inc); err != nil {
		return backendinterface.Handle{}, fail(err)
	}
	// Snapshot load restores every device (drives, machine-config, vsock)
	// from the saved state; Firecracker rejects any pre-boot configuration
	// on this path. The incarnation dir is recreated at its original path,
	// so the drive paths recorded in the snapshot stay valid. A backend
	// restored with a different Root would need path rewriting (follow-up).
	l := b.layoutFor(inc)
	api := b.api(inc)
	memPath := filepath.Join(snapDir, "mem.file")
	statePath := filepath.Join(snapDir, "vm.state")
	if inc.jailed {
		if err := bindMount(b.snapshotDir(inc.id), filepath.Join(inc.jailRoot, "snap")); err != nil {
			return backendinterface.Handle{}, fail(err)
		}
		ts := filepath.Base(snapDir)
		memPath = "/snap/" + ts + "/mem.file"
		statePath = "/snap/" + ts + "/vm.state"
	}
	if err := api.snapshotLoad(statePath, memPath, l.apiVsock, true); err != nil {
		return backendinterface.Handle{}, fail(err)
	}
	if err := api.ping(); err != nil {
		return backendinterface.Handle{}, fail(err)
	}
	if b.cfg.GuestSupervisorBin != "" {
		if err := b.attachSupervisor(inc); err != nil {
			return backendinterface.Handle{}, fail(err)
		}
	}
	b.mu.Lock()
	inc.startedAt = time.Now()
	b.mu.Unlock()
	return backendinterface.Handle{IncarnationID: cp.IncarnationID}, nil
}

func (b *Backend) killProcLocked(inc *incarnation) {
	if inc.cmd != nil && inc.cmd.Process != nil && inc.exited != nil {
		select {
		case <-inc.exited:
		default:
			if inc.jailed {
				// sudo+jailer+firecracker run in their own process
				// group (Setpgid at spawn).
				killProcessGroup(inc.cmd.Process.Pid)
			} else {
				inc.cmd.Process.Kill()
			}
			select {
			case <-inc.exited:
			case <-time.After(5 * time.Second):
			}
		}
	}
	inc.cmd = nil
	inc.sup = nil
}

func (b *Backend) killProc(inc *incarnation) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.killProcLocked(inc)
}

// Terminate SIGKILLs the VMM process, reaps it, tears down networking and
// jail artifacts, and removes the incarnation directory. Snapshots under
// <root>/snapshots are retained unless DeleteSnapshotsOnTerminate is set.
func (b *Backend) Terminate(h backendinterface.Handle) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, ok := b.incs[h.IncarnationID]
	if !ok {
		return nil
	}
	b.killProcLocked(inc)
	inc.dead = true
	b.teardownNetworking(inc)
	b.cleanupJail(inc)
	if b.cfg.DeleteSnapshotsOnTerminate {
		os.RemoveAll(b.snapshotDir(inc.id))
	}
	os.RemoveAll(inc.dir)
	return nil
}

// Stats reports host-side usage of the VMM process (INV-016): CPU seconds
// and RSS from /proc, uptime from boot/restore. Guest-internal process
// counts need the stage-3 supervisor and report 0.
func (b *Backend) Stats(h backendinterface.Handle) (backendinterface.Stats, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, err := b.get(h)
	if err != nil {
		return backendinterface.Stats{}, err
	}
	st := backendinterface.Stats{}
	if !inc.startedAt.IsZero() {
		st.UptimeSeconds = int64(time.Since(inc.startedAt).Seconds())
	}
	if inc.cmd != nil && inc.cmd.Process != nil {
		if cpu, rss, err := procUsage(inc.cmd.Process.Pid); err == nil {
			st.CPUSeconds = cpu
			st.MemoryBytes = rss
		}
	}
	if inc.sup != nil {
		if inv, err := inc.sup.ProcessInventory(); err == nil {
			st.ProcessCount = len(inv)
		}
	}
	return st, nil
}

// Alive reports whether the incarnation still exists and (once booted) its
// VMM process is still running.
func (b *Backend) Alive(h backendinterface.Handle) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, ok := b.incs[h.IncarnationID]
	if !ok || inc.dead {
		return false
	}
	if inc.started && inc.exited != nil {
		select {
		case <-inc.exited:
			return false
		default:
		}
	}
	return true
}

// KillRuntime simulates a crash: the VMM process is SIGKILLed and the
// working directory (uncommitted state) destroyed. Snapshots survive.
func (b *Backend) KillRuntime(h backendinterface.Handle) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, ok := b.incs[h.IncarnationID]
	if !ok {
		return
	}
	b.killProcLocked(inc)
	inc.dead = true
	b.teardownNetworking(inc)
	b.cleanupJail(inc)
	os.RemoveAll(inc.dir)
}

// Close reaps every spawned firecracker process (guardrail for test and
// host-agent shutdown).
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, inc := range b.incs {
		b.killProcLocked(inc)
		inc.dead = true
		b.teardownNetworking(inc)
		b.cleanupJail(inc)
	}
	return nil
}

// LiveHandles lists incarnations still present in this backend.
func (b *Backend) LiveHandles() []backendinterface.Handle {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []backendinterface.Handle
	for id, inc := range b.incs {
		if !inc.dead {
			out = append(out, backendinterface.Handle{IncarnationID: id})
		}
	}
	return out
}

// LiveSpecs returns the retained create-spec metadata of every live
// incarnation (adoption support, INV-016).
func (b *Backend) LiveSpecs() []backendinterface.Spec {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []backendinterface.Spec
	for _, inc := range b.incs {
		if !inc.dead {
			out = append(out, inc.spec)
		}
	}
	return out
}

// Tick is a no-op: the backend lives in real time.
func (b *Backend) Tick() {}

// Exec applies the operation through the in-guest supervisor: Writes are
// materialized into the guest /workspace (mirrored host-side and marked
// dirty until MarkCommitted, INV-006), Command runs via the supervisor with
// spec-level env then per-op env (last-wins), and SpawnBackground maps to
// real sleep processes — the same semantics as the local backend.
func (b *Backend) Exec(h backendinterface.Handle, executionID string, op domain.Operation) error {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return err
	}
	if !inc.started || inc.paused {
		b.mu.Unlock()
		return backendinterface.ErrIllegalState
	}
	b.mu.Unlock()

	// Serialize against Snapshot's pause window: after acquiring opMu the
	// state is re-checked, so an Exec racing a pause either fully lands in
	// the guest before it or fails cleanly with ErrIllegalState — the
	// wsMirror is never updated for writes the guest never saw (INV-006).
	inc.opMu.Lock()
	defer inc.opMu.Unlock()
	b.mu.Lock()
	if !inc.started || inc.paused || inc.dead {
		b.mu.Unlock()
		return backendinterface.ErrIllegalState
	}
	inc.ops[executionID] = op
	if len(op.Writes) > 0 {
		inc.dirty = true
	}
	sup, supErr := b.supFor(inc)
	b.mu.Unlock()

	for path, content := range op.Writes {
		if err := checkWorkspacePath(path); err != nil {
			return err
		}
		if supErr == nil {
			if err := sup.WriteFile(path, content); err != nil {
				return err
			}
		}
		b.mu.Lock()
		inc.wsMirror[path] = content
		b.mu.Unlock()
	}
	if op.Command != "" {
		if supErr != nil {
			return supErr
		}
		env := map[string]string{}
		for k, v := range inc.spec.Env {
			env[k] = v
		}
		for k, v := range op.Env {
			env[k] = v
		}
		if err := sup.Exec(supervisor.ExecRequest{ExecutionID: executionID, Command: op.Command, Baseline: op.Baseline, Env: env}); err != nil {
			return err
		}
	}
	for i, bg := range op.SpawnBackground {
		if supErr != nil {
			return supErr
		}
		secs := 0.25 * float64(bg.Ticks)
		bgID := fmt.Sprintf("%s#bg-%d-%s", executionID, i, bg.Name)
		if err := sup.Exec(supervisor.ExecRequest{
			ExecutionID: bgID,
			Command:     fmt.Sprintf("sleep %.2f", secs),
			Baseline:    op.Baseline,
		}); err != nil {
			return err
		}
	}
	return nil
}

// WaitExecution blocks until the operation's command exits in the guest and
// returns its result; operations without a command complete immediately.
func (b *Backend) WaitExecution(h backendinterface.Handle, executionID string) (supervisor.Result, error) {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return supervisor.Result{}, err
	}
	op, known := inc.ops[executionID]
	sup, supErr := b.supFor(inc)
	b.mu.Unlock()
	if !known {
		return supervisor.Result{}, supervisor.ErrNotFound
	}
	if op.Command == "" {
		return supervisor.Result{ExitCode: op.ExitCode}, nil
	}
	if supErr != nil {
		return supervisor.Result{}, supErr
	}
	return sup.Wait(executionID)
}

// WorkspaceFiles reads the live guest /workspace through the supervisor when
// available; the host-side mirror covers the pre-boot/no-agent window.
func (b *Backend) WorkspaceFiles(h backendinterface.Handle) (map[string]string, error) {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return nil, err
	}
	sup, supErr := b.supFor(inc)
	b.mu.Unlock()
	if supErr == nil && !inc.paused {
		files, err := sup.WorkspaceFiles()
		if err == nil {
			return files, nil
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]string{}
	for k, v := range inc.wsMirror {
		out[k] = v
	}
	return out, nil
}

func (b *Backend) Dirty(h backendinterface.Handle) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	inc, err := b.get(h)
	if err != nil {
		return false
	}
	return inc.dirty
}

func (b *Backend) MarkCommitted(h backendinterface.Handle) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if inc, err := b.get(h); err == nil {
		inc.dirty = false
	}
}

// LiveDescendants counts live guest processes owned by the incarnation (0
// when no supervisor transport is available).
func (b *Backend) LiveDescendants(h backendinterface.Handle) int {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return 0
	}
	sup, supErr := b.supFor(inc)
	b.mu.Unlock()
	if supErr != nil {
		return 0
	}
	inv, err := sup.ProcessInventory()
	if err != nil {
		return 0
	}
	return len(inv)
}

// LiveNonBaselineDescendants counts live owned guest processes excluding
// baseline service process groups (quiescence signal, PLAN §10).
func (b *Backend) LiveNonBaselineDescendants(h backendinterface.Handle) int {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return 0
	}
	sup, supErr := b.supFor(inc)
	b.mu.Unlock()
	if supErr != nil {
		return 0
	}
	inv, baseline, err := sup.inventory()
	if err != nil {
		return 0
	}
	n := 0
	for _, p := range inv {
		if !baseline[p.PGID] {
			n++
		}
	}
	return n
}

// ProcessInventory exposes the incarnation's live owned guest processes.
func (b *Backend) ProcessInventory(h backendinterface.Handle) ([]supervisor.ProcessInfo, error) {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return nil, err
	}
	sup, supErr := b.supFor(inc)
	b.mu.Unlock()
	if supErr != nil {
		return nil, nil
	}
	return sup.ProcessInventory()
}

// TerminateBackground kills every live non-baseline descendant in the guest
// (policy enforcement); baseline services and the incarnation survive.
func (b *Backend) TerminateBackground(h backendinterface.Handle) error {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return err
	}
	sup, supErr := b.supFor(inc)
	b.mu.Unlock()
	if supErr != nil {
		return nil
	}
	return sup.TerminateBackground()
}
