package firecrackerbackend

import (
	"encoding/json"
	"errors"
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
	"github.com/agent-sandbox/platform/runtime/hostfacts"
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
	// IncrementalSnapshots enables diff checkpoints (ADR-006): VMs boot
	// with KVM dirty-page tracking and Snapshot emits a sparse diff memory
	// file when a parent checkpoint exists within the chain-depth budget.
	IncrementalSnapshots bool
	// MaxSnapshotChainDepth bounds consecutive diffs above a full base;
	// reaching it collapses the next Snapshot to a new full. Default 4.
	MaxSnapshotChainDepth int
	// DeleteSnapshotsOnTerminate also removes the incarnation's snapshots
	// on Terminate (default false: committed checkpoints survive).
	DeleteSnapshotsOnTerminate bool
	// PublishDenyPorts lists host ports a binding may never publish (review
	// H1), on top of the fixed <1024 floor. nil means
	// DefaultPublishDenyPorts (the platform's own service ports); an
	// explicit non-nil slice replaces the defaults.
	PublishDenyPorts []int
	BootArgs         string // default: smoke-tested "console=ttyS0 reboot=k panic=1 pci=off"
	VCPUs            int64  // default 1
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
	// DNSUpstream is the resolver the per-incarnation DNS-learning proxy
	// forwards allowed queries to ("host" or "host:port"); default: the
	// first nameserver in /etc/resolv.conf, else 8.8.8.8.
	DNSUpstream string
	// DNSMinTTL clamps learned (IP,TTL) allow entries to a minimum
	// lifetime, avoiding chain churn on sub-second TTLs; default 5s.
	DNSMinTTL time.Duration
	// DNSMaxLearned caps learned allow entries per incarnation (oldest
	// evicted); default 1024.
	DNSMaxLearned int
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
	if out.MaxSnapshotChainDepth == 0 {
		out.MaxSnapshotChainDepth = 4
	}
	if out.DNSMinTTL == 0 {
		out.DNSMinTTL = 5 * time.Second
	}
	if out.DNSMaxLearned == 0 {
		out.DNSMaxLearned = 1024
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
	// results caches the last maxCachedResults completed waits so
	// WaitExecution stays idempotent while inc.ops can be pruned once a
	// result is observed (FL9: bounded per-incarnation maps).
	results      map[string]supervisor.Result
	resultsOrder []string
	vsockCID     uint32
	sup          *supervisor.Client
	jailed       bool
	jailRoot     string
	net          *netState
	// toolsImage is the host path of the content-addressed read-only tools
	// drive attached to this incarnation (P0.3); empty in stage-2 mode and
	// for legacy (pre-P0.3) snapshots whose supervisor lives in the rootfs.
	toolsImage string
	// toolsSHA is the sha256 of the supervisor binary the tools image was
	// built from (recorded in snapshot metadata, P0.4).
	toolsSHA string
	// lastSnap and chainDepth track the checkpoint chain tip this
	// incarnation would extend (ADR-006): lastSnap is the snapshot dir
	// name of the latest checkpoint the (possibly restored) VM's dirty
	// bitmap is relative to, chainDepth its depth above the full base.
	lastSnap   string
	chainDepth int
	// mergedFrom records the chain tip whose merged artifact this
	// incarnation's RAM is backed by ("" when restored from a full
	// snapshot or booted fresh); the GC must keep that artifact alive.
	mergedFrom string
	// opMu serializes guest-mutating operations (Exec writes/commands)
	// against the pause/snapshot window: Snapshot holds it across
	// pause+snapshotCreate so an Exec either fully lands in the guest before
	// the pause, or blocks and then fails with ErrIllegalState once paused —
	// never half-applied mid-snapshot (wsMirror/guest divergence, INV-006).
	opMu sync.Mutex
}

// maxCachedResults bounds the per-incarnation completed-result cache (FL9).
const maxCachedResults = 256

// Backend is a Firecracker-microVM RuntimeBackend (IsolationClass VM).
type Backend struct {
	cfg     Config
	mu      sync.Mutex
	incs    map[string]*incarnation
	nextCID uint32
	// toolsMu serializes tools-image builds (ensureToolsImage); separate
	// from mu because Create calls it while holding mu (P0.3).
	toolsMu sync.Mutex
	// jailerFailed records why the jailer is not in use (empty = jailer
	// active or not configured); surfaced via JailerStatus.
	jailerFailed string
	// kernelSHA/fcVersion cache the snapshot-package facts (P0.4); computed
	// lazily under mu on first Snapshot.
	kernelSHA string
	fcVersion string
}

// JailerStatus reports the jailer fallback reason ("" when the jailer is
// active or was never configured).
func (b *Backend) JailerStatus() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.jailerFailed
}

// New creates a Backend storing incarnation state under cfg.Root. Startup
// also sweeps host plumbing leaked by a previous (crashed) backend process
// (FM11): stale fc-tap-* devices, FC-EGR-*/FC-EGR6-* chains, and jail bind
// mounts/trees — only resources matching this platform's exact naming
// conventions, and never a slot registered to a live incarnation of this
// process.
func New(cfg Config) (*Backend, error) {
	c := cfg.withDefaults()
	if c.KernelPath == "" || c.RootfsPath == "" || c.FirecrackerBin == "" {
		return nil, fmt.Errorf("firecrackerbackend: KernelPath, RootfsPath and FirecrackerBin are required")
	}
	// Guest memory and tenant workspace contents live under Root: private
	// from creation, umask-independent (FM7).
	if err := os.MkdirAll(c.Root, 0o700); err != nil {
		return nil, err
	}
	os.Chmod(c.Root, 0o700)
	if err := os.MkdirAll(filepath.Join(c.Root, "snapshots"), 0o700); err != nil {
		return nil, err
	}
	os.Chmod(filepath.Join(c.Root, "snapshots"), 0o700)
	if c.Networking {
		if err := checkNetPrereqs(); err != nil {
			return nil, err
		}
		sweepStaleNetworking()
	}
	b := &Backend{cfg: c, incs: map[string]*incarnation{}, nextCID: c.VsockBaseCID}
	if c.JailerBin != "" {
		b.sweepStaleJails()
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
		// The endpoint data plane (DNAT host:port -> guestIP:port) exists
		// only when the backend manages guest networking at all.
		SupportsPortPublish: b.cfg.Networking,
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return backendinterface.Handle{}, err
	}
	os.Chmod(dir, 0o700)
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
	os.Chmod(rootfs, 0o600)
	if err := injectWorkspaceUnit(rootfs); err != nil {
		return fail(err)
	}
	var toolsImage, toolsSHA string
	if b.cfg.GuestSupervisorBin != "" {
		// P0.3: the supervisor binary ships on ONE content-addressed
		// read-only tools drive shared by every incarnation, not injected
		// into each rootfs copy (~3MB/VM saved).
		var err error
		toolsImage, toolsSHA, err = b.ensureToolsImage()
		if err != nil {
			return fail(err)
		}
		if err := injectGuestAgentUnit(rootfs, spec.IncarnationID, b.cfg.SupervisorPort); err != nil {
			return fail(err)
		}
	}
	inc := &incarnation{
		id:         spec.IncarnationID,
		spec:       spec,
		dir:        dir,
		wsMirror:   map[string]string{},
		ops:        map[string]domain.Operation{},
		results:    map[string]supervisor.Result{},
		toolsImage: toolsImage,
		toolsSHA:   toolsSHA,
	}
	for k, v := range spec.WorkspaceManifest {
		inc.wsMirror[k] = v
	}
	b.incs[spec.IncarnationID] = inc
	if b.cfg.Networking {
		if err := b.allocateNetworkingLocked(inc, preferredSlot(spec.IncarnationID)); err != nil {
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
	os.Chmod(filepath.Join(dir, "workspace.img"), 0o600)
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
			b.mu.Lock()
			inc.jailed = true
			inc.jailRoot = root
			b.mu.Unlock()
			cmd, console, err = b.spawnJailed(inc, b.layoutFor(inc))
		}
		if err != nil {
			// FL12: a failed jailed spawn must not strand the prepared
			// jail tree before the raw fallback runs.
			b.cleanupJail(inc)
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
		console, err = os.OpenFile(filepath.Join(inc.dir, "console.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
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
			b.stopProc(inc)
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
	if err := api.setMachineConfig(b.cfg.VCPUs, b.memMiB(inc.spec), b.cfg.IncrementalSnapshots); err != nil {
		return err
	}
	if err := api.addDrive("rootfs", l.apiRootfs, true, false); err != nil {
		return err
	}
	if err := api.addDrive("workspace", l.apiWS, false, false); err != nil {
		return err
	}
	if inc.toolsImage != "" {
		// Third drive: the shared read-only tools ext4 (P0.3), mounted
		// in-guest by label fc-tools at /opt/fc-tools.
		if err := api.addDrive("tools", l.apiTools, false, true); err != nil {
			return err
		}
	}
	if ns := b.netOf(inc); ns != nil {
		if err := api.addNIC("eth0", ns.tap, ns.mac); err != nil {
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
	sup := supervisor.NewClient(vsockDial(b.layoutFor(inc).hostVsock, b.cfg.SupervisorPort, b.cfg.APITimeout), b.cfg.APITimeout)
	sup.Alive = func() bool {
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
func (b *Backend) supFor(inc *incarnation) (*supervisor.Client, error) {
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
		b.stopProc(inc)
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
	// NetGeneration records the egress policy generation at snapshot time;
	// restore bumps it (generation+1, conntrack flush) so pre-restore
	// flows cannot continue under the old policy (P0.1).
	NetGeneration *int `json:"net_generation,omitempty"`
	// Self-describing snapshot package (P0.4): the facts below make the
	// snapshot portable-checkable. Restore validates every populated field
	// against the current host/backend and fails with a typed
	// SnapshotIncompatibleError on mismatch. Empty fields (legacy
	// snapshots) skip validation.
	// ToolsImage is the content-addressed tools drive the saved VMM state
	// references (P0.3); restore reuses THIS image even when the current
	// supervisor binary differs (a supervisor upgrade must never block
	// restore).
	ToolsImage         string `json:"tools_image,omitempty"`
	SupervisorSHA256   string `json:"supervisor_sha256,omitempty"`
	KernelSHA256       string `json:"kernel_sha256,omitempty"`
	FirecrackerVersion string `json:"firecracker_version,omitempty"`
	Arch               string `json:"arch,omitempty"`
	KernelRelease      string `json:"kernel_release,omitempty"`
	CPUPart            string `json:"cpu_part,omitempty"`
	// Incremental chain fields (ADR-006). Kind is "full" or "diff" (empty
	// = full for pre-ADR-006 snapshots); Parent names the parent snapshot
	// dir within the same snapshot root; Depth counts diffs above the
	// full base (0 for full). MemSHA256/VMStateSHA256 are recorded for
	// every link and verified on restore (CI-3).
	Kind          string `json:"kind,omitempty"`
	Parent        string `json:"parent,omitempty"`
	Depth         int    `json:"depth,omitempty"`
	MemSHA256     string `json:"mem_sha256,omitempty"`
	VMStateSHA256 string `json:"vm_state_sha256,omitempty"`
}

// Snapshot kinds (snapshotMeta.Kind; ADR-006).
const (
	snapshotKindFull = "full"
	snapshotKindDiff = "diff"
)

// SnapshotIncompatibleError is Restore's typed failure when a
// self-describing snapshot's recorded facts (P0.4) do not match the
// current host or backend, or when a referenced snapshot artifact (tools
// image) is missing.
type SnapshotIncompatibleError struct {
	Field string // e.g. "kernel_sha256", "arch", "tools_image"
	Want  string // value recorded in the snapshot
	Got   string // value on the current host/backend
}

func (e *SnapshotIncompatibleError) Error() string {
	return fmt.Sprintf("firecrackerbackend: snapshot incompatible: %s recorded as %q but current is %q", e.Field, e.Want, e.Got)
}

// IsSnapshotIncompatible reports whether err is (or wraps) a
// SnapshotIncompatibleError.
func IsSnapshotIncompatible(err error) bool {
	var si *SnapshotIncompatibleError
	return errors.As(err, &si)
}

// kernelSHA256 returns the cached sha256 of the configured kernel image,
// computing it on first use (P0.4 snapshot package).
func (b *Backend) kernelSHA256() (string, error) {
	b.mu.Lock()
	cached := b.kernelSHA
	b.mu.Unlock()
	if cached != "" {
		return cached, nil
	}
	sha, err := sha256File(b.cfg.KernelPath)
	if err != nil {
		return "", fmt.Errorf("kernel image: %w", err)
	}
	b.mu.Lock()
	b.kernelSHA = sha
	b.mu.Unlock()
	return sha, nil
}

// firecrackerVersion returns the cached first line of
// `firecracker --version` (P0.4 snapshot package).
func (b *Backend) firecrackerVersion() string {
	b.mu.Lock()
	cached := b.fcVersion
	b.mu.Unlock()
	if cached != "" {
		return cached
	}
	v := "unknown"
	if out, err := exec.Command(b.cfg.FirecrackerBin, "--version").Output(); err == nil {
		if line, _, _ := strings.Cut(string(out), "\n"); strings.TrimSpace(line) != "" {
			v = strings.TrimSpace(line)
		}
	}
	b.mu.Lock()
	b.fcVersion = v
	b.mu.Unlock()
	return v
}

// validateSnapshotPackage checks the self-describing facts recorded in
// meta against the current host/backend (P0.4). Unpopulated fields (legacy
// snapshots) are skipped. SupervisorSHA256 is intentionally NOT fatal: the
// supervisor recorded in the snapshot is the one the restored VM must run,
// so a mismatch just means the recorded tools image is used. Returns a
// *SnapshotIncompatibleError on fatal mismatch.
func (b *Backend) validateSnapshotPackage(meta *snapshotMeta) error {
	facts := hostfacts.Current()
	check := func(field, recorded, current string) error {
		if recorded == "" {
			return nil
		}
		if recorded != current {
			return &SnapshotIncompatibleError{Field: field, Want: recorded, Got: current}
		}
		return nil
	}
	if err := check("arch", meta.Arch, facts.Arch); err != nil {
		return err
	}
	if err := check("kernel_release", meta.KernelRelease, facts.KernelRelease); err != nil {
		return err
	}
	if err := check("cpu_part", meta.CPUPart, facts.CPUPart); err != nil {
		return err
	}
	if meta.KernelSHA256 != "" {
		sha, err := b.kernelSHA256()
		if err != nil {
			return err
		}
		if err := check("kernel_sha256", meta.KernelSHA256, sha); err != nil {
			return err
		}
	}
	if err := check("firecracker_version", meta.FirecrackerVersion, b.firecrackerVersion()); err != nil {
		return err
	}
	// The tools image is referenced by the saved VMM state: it must exist.
	if meta.ToolsImage != "" {
		if _, err := os.Stat(meta.ToolsImage); err != nil {
			return &SnapshotIncompatibleError{Field: "tools_image", Want: meta.ToolsImage, Got: "missing: " + err.Error()}
		}
	}
	return nil
}

func (b *Backend) snapshotDir(incarnationID string) string {
	return filepath.Join(b.cfg.Root, "snapshots", incarnationID)
}

// gcSnapshots retains only the newest MaxSnapshotsPerIncarnation snapshot
// dirs for an incarnation (dir names are unix-nanosecond timestamps, so
// lexicographic order is chronological). Chain safety (ADR-006): a dir
// referenced as another checkpoint's parent is NEVER deleted (mid-chain
// deletion is refused, not rebased), so retention can exceed the max while
// a chain is live; after an auto-collapse the dead chain becomes
// reclaimable from its tip backwards. Merged artifacts (.merged-<tip>) are
// reclaimed once their tip dir is gone and no live incarnation's RAM is
// backed by them.
func (b *Backend) gcSnapshots(incarnationID string) {
	max := b.cfg.MaxSnapshotsPerIncarnation
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
	// Referenced parents are chain-internal: refuse to delete them.
	referenced := map[string]bool{}
	for _, d := range dirs {
		data, err := os.ReadFile(filepath.Join(root, d, "meta.json"))
		if err != nil {
			continue
		}
		var meta snapshotMeta
		if json.Unmarshal(data, &meta) == nil && meta.Parent != "" {
			referenced[meta.Parent] = true
		}
	}
	if max > 0 {
		kept := dirs
		for _, d := range dirs {
			if len(kept) <= max {
				break
			}
			if referenced[d] {
				continue
			}
			os.RemoveAll(filepath.Join(root, d))
			for i, k := range kept {
				if k == d {
					kept = append(kept[:i], kept[i+1:]...)
					break
				}
			}
		}
	}
	// Merged-artifact GC.
	b.mu.Lock()
	live := map[string]bool{}
	for _, inc := range b.incs {
		if inc.mergedFrom != "" && !inc.dead {
			live[inc.mergedFrom] = true
		}
	}
	b.mu.Unlock()
	exists := map[string]bool{}
	for _, d := range dirs {
		exists[d] = true
	}
	entries, err = os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), ".merged-") || strings.HasSuffix(e.Name(), ".tmp") || strings.HasSuffix(e.Name(), ".sha256") {
			continue
		}
		tip := strings.TrimPrefix(e.Name(), ".merged-")
		if !exists[tip] && !live[tip] {
			os.Remove(filepath.Join(root, e.Name()))
			os.Remove(filepath.Join(root, e.Name()+".sha256"))
		}
	}
}

// gcToolsImages deletes content-addressed tools images (P0.3) that are no
// longer referenced: an image is retained iff a LIVE incarnation uses it
// or ANY retained snapshot link's meta records its sha256
// (SupervisorSHA256 — chain links are covered because every link carries
// its own package facts, ADR-006 CI-4). Saved VMM state references the
// image path, so deleting a referenced image would break restore (typed
// tools_image error at validation); only fully unreferenced images are
// collected. Orphaned .tmp build artifacts are always removed.
//
// Locking (review M8): b.mu is held across the entire reference scan and
// delete pass — Create holds b.mu across ensureToolsImage + incarnation
// registration, so a concurrent build can neither have a .tmp in flight
// nor register a reference after the scan. toolsMu is taken second (the
// Create path's b.mu -> toolsMu order) for the documented build exclusion.
func (b *Backend) gcToolsImages() {
	if b.cfg.GuestSupervisorBin == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.toolsMu.Lock()
	defer b.toolsMu.Unlock()
	toolsDir := filepath.Join(b.cfg.Root, "tools")
	entries, err := os.ReadDir(toolsDir)
	if err != nil {
		return
	}
	referenced := map[string]bool{}
	for _, inc := range b.incs {
		if !inc.dead && inc.toolsSHA != "" {
			referenced[inc.toolsSHA] = true
		}
	}
	snapsRoot := filepath.Join(b.cfg.Root, "snapshots")
	incDirs, err := os.ReadDir(snapsRoot)
	if err == nil {
		for _, incDir := range incDirs {
			if !incDir.IsDir() {
				continue
			}
			snaps, err := os.ReadDir(filepath.Join(snapsRoot, incDir.Name()))
			if err != nil {
				continue
			}
			for _, s := range snaps {
				if !s.IsDir() {
					continue
				}
				data, err := os.ReadFile(filepath.Join(snapsRoot, incDir.Name(), s.Name(), "meta.json"))
				if err != nil {
					continue
				}
				var meta snapshotMeta
				if json.Unmarshal(data, &meta) == nil && meta.SupervisorSHA256 != "" {
					referenced[meta.SupervisorSHA256] = true
				}
			}
		}
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".tmp") {
			os.Remove(filepath.Join(toolsDir, name)) // crashed build leftover
			continue
		}
		if !strings.HasPrefix(name, "tools-") || !strings.HasSuffix(name, ".ext4") {
			continue
		}
		sha := strings.TrimSuffix(strings.TrimPrefix(name, "tools-"), ".ext4")
		if !referenced[sha] {
			os.Remove(filepath.Join(toolsDir, name))
		}
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
	// FL6: a failed snapshot must not wedge the VM: resume it when we
	// paused it (best-effort) and remove the partial snapshot dir so it is
	// never counted toward GC or mistaken for a restorable checkpoint.
	fail := func(err error) (backendinterface.CheckpointData, error) {
		if wasRunning {
			b.Resume(h)
		}
		os.RemoveAll(snapDir)
		return backendinterface.CheckpointData{}, err
	}
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		return backendinterface.CheckpointData{}, err
	}
	os.Chmod(snapDir, 0o700) // guest memory lands here (FM7)
	// Disk state must be captured alongside memory: copy both drives while
	// the VM is paused (reflink where the fs supports it).
	if err := copyFile(filepath.Join(snapDir, "rootfs.ext4"), filepath.Join(inc.dir, "rootfs.ext4")); err != nil {
		return fail(err)
	}
	os.Chmod(filepath.Join(snapDir, "rootfs.ext4"), 0o600)
	if err := copyFile(filepath.Join(snapDir, "workspace.img"), filepath.Join(inc.dir, "workspace.img")); err != nil {
		return fail(err)
	}
	os.Chmod(filepath.Join(snapDir, "workspace.img"), 0o600)
	// Chain decision (ADR-006): a diff extends the tip this VM's dirty
	// bitmap is relative to, within the depth budget; anything else
	// collapses to a new full (generation-0 base).
	kind, parent, parentDepth := snapshotKindFull, "", 0
	b.mu.Lock()
	if b.cfg.IncrementalSnapshots && inc.lastSnap != "" && inc.chainDepth < b.cfg.MaxSnapshotChainDepth {
		kind, parent, parentDepth = snapshotKindDiff, inc.lastSnap, inc.chainDepth
	}
	b.mu.Unlock()
	memPath := filepath.Join(snapDir, "mem.file")
	statePath := filepath.Join(snapDir, "vm.state")
	if inc.jailed {
		// A jailed VMM can only write inside its chroot: share the
		// incarnation's snapshot dir via bind mount.
		if err := bindMount(snapRoot, filepath.Join(inc.jailRoot, "snap")); err != nil {
			return fail(err)
		}
		memPath = "/snap/" + ts + "/mem.file"
		statePath = "/snap/" + ts + "/vm.state"
	}
	if err := b.snapshotCreateHook(inc, memPath, statePath, kind); err != nil {
		return fail(err)
	}
	// The VMM (possibly root via the jailer) wrote these: force owner-only
	// permissions on the guest memory image and vCPU state (FM7).
	os.Chmod(filepath.Join(snapDir, "mem.file"), 0o600)
	os.Chmod(filepath.Join(snapDir, "vm.state"), 0o600)
	// Integrity hashes (CI-3): recorded for every link, verified on
	// restore, so a corrupted mid-chain diff is detected as corruption.
	memSHA, err := sha256File(filepath.Join(snapDir, "mem.file"))
	if err != nil {
		return fail(err)
	}
	stateSHA, err := sha256File(filepath.Join(snapDir, "vm.state"))
	if err != nil {
		return fail(err)
	}
	meta := snapshotMeta{Spec: inc.spec, CreatedAt: time.Now(), Kind: kind, MemSHA256: memSHA, VMStateSHA256: stateSHA}
	if kind == snapshotKindDiff {
		meta.Parent = parent
		meta.Depth = parentDepth + 1
	}
	b.mu.Lock()
	if inc.net != nil {
		slot := inc.net.slot
		meta.NetSlot = &slot
		inc.net.mu.Lock()
		gen := inc.net.generation
		inc.net.mu.Unlock()
		meta.NetGeneration = &gen
	}
	meta.ToolsImage = inc.toolsImage
	meta.SupervisorSHA256 = inc.toolsSHA
	b.mu.Unlock()
	// Self-describing package (P0.4): record host/backend facts so a later
	// restore can reject incompatible environments with a typed error.
	facts := hostfacts.Current()
	meta.Arch = facts.Arch
	meta.KernelRelease = facts.KernelRelease
	meta.CPUPart = facts.CPUPart
	kernelSHA, err := b.kernelSHA256()
	if err != nil {
		return fail(err)
	}
	meta.KernelSHA256 = kernelSHA
	meta.FirecrackerVersion = b.firecrackerVersion()
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return fail(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "meta.json"), metaBytes, 0o600); err != nil {
		return fail(err)
	}
	b.mu.Lock()
	inc.lastSnap = ts
	inc.chainDepth = meta.Depth
	b.mu.Unlock()
	b.gcSnapshots(inc.id)
	b.gcToolsImages()
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
			// Placement-guard visibility (P1.7): hosts matching these
			// facts get the checkpoint-locality bonus.
			"arch":           facts.Arch,
			"kernel_release": facts.KernelRelease,
			"cpu_part":       facts.CPUPart,
			// Chain visibility (ADR-006): opaque to the control plane.
			"kind":   kind,
			"parent": meta.Parent,
			"depth":  fmt.Sprint(meta.Depth),
		},
	}, nil
}

// snapshotCreateFault, when set, fails the next snapshotCreate calls (FL6
// regression test hook).
var snapshotCreateFault func() error

func (b *Backend) snapshotCreateHook(inc *incarnation, memPath, statePath, kind string) error {
	if snapshotCreateFault != nil {
		if err := snapshotCreateFault(); err != nil {
			return err
		}
	}
	fcType := "Full"
	if kind == snapshotKindDiff {
		fcType = "Diff"
	}
	return b.api(inc).snapshotCreate(memPath, statePath, fcType)
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
	// P0.4: the snapshot is self-describing — reject hosts/backends whose
	// facts differ from what the snapshot was taken under (typed error).
	if err := b.validateSnapshotPackage(&meta); err != nil {
		return backendinterface.Handle{}, err
	}
	// ADR-006: validate the whole chain (per-link package facts + hashes)
	// and resolve the memory file to load — the tip's own file for a full
	// snapshot, or a merged artifact for a diff tip (Firecracker v1.17
	// cannot load diff memory files directly).
	chain, err := b.loadSnapshotChain(snapDir)
	if err != nil {
		return backendinterface.Handle{}, err
	}
	memFile, err := b.mergeChainMem(chain)
	if err != nil {
		return backendinterface.Handle{}, err
	}
	// The restored VM must run the supervisor it was snapshotted with:
	// reuse the recorded tools image even when the current binary differs
	// (a supervisor upgrade never blocks restore). Legacy snapshots
	// (pre-P0.3) record no tools image: their supervisor lives inside the
	// snapshot's rootfs and no tools drive is attached.
	toolsImage, toolsSHA := meta.ToolsImage, meta.SupervisorSHA256
	b.mu.Lock()
	inc, ok := b.incs[cp.IncarnationID]
	if !ok {
		inc = &incarnation{id: cp.IncarnationID, ops: map[string]domain.Operation{}, results: map[string]supervisor.Result{}, wsMirror: map[string]string{}}
		b.incs[cp.IncarnationID] = inc
	}
	b.mu.Unlock()
	// Crash-recovery path (INV-009): reap any still-running VMM and fully
	// clean its jail state BEFORE re-jailing (FM6) — the stale /snap bind
	// mount and jail tree must go, or repeated jailed restores stack
	// mounts and fail prepareJail's RemoveAll with EBUSY.
	if ok {
		b.stopProc(inc)
		b.cleanupJail(inc)
	}
	b.mu.Lock()
	inc.spec = meta.Spec
	inc.dead = false
	inc.paused = false
	inc.started = true
	inc.toolsImage = toolsImage
	inc.toolsSHA = toolsSHA
	// The restored VM's dirty bitmap was reset by snapshotLoad, so its next
	// checkpoint chains on top of the tip it was restored from (ADR-006).
	inc.lastSnap = filepath.Base(snapDir)
	inc.chainDepth = meta.Depth
	if len(chain) > 1 {
		inc.mergedFrom = filepath.Base(snapDir)
	} else {
		inc.mergedFrom = ""
	}
	for k, v := range cp.Files {
		inc.wsMirror[k] = v
	}
	b.nextCID++
	inc.vsockCID = b.nextCID
	dir := filepath.Join(b.cfg.Root, cp.IncarnationID)
	inc.dir = dir
	b.mu.Unlock()

	// Networking: reallocate the slot recorded in the snapshot metadata so
	// the TAP name/MAC/guest IP match the net device config the snapshot
	// restores; the policy comes from the restored spec. The egress
	// generation CONTINUES from the snapshot's value (+1 in
	// setupNetworking, plus a conntrack flush), so flows established
	// before the restore are invalidated (P0.1).
	if b.cfg.Networking {
		b.teardownNetworking(inc)
		preferred := preferredSlot(inc.id)
		if meta.NetSlot != nil {
			preferred = *meta.NetSlot
		}
		b.mu.Lock()
		err := b.allocateNetworkingLocked(inc, preferred)
		if err == nil && meta.NetGeneration != nil {
			inc.net.generation = *meta.NetGeneration
		}
		b.mu.Unlock()
		if err != nil {
			return backendinterface.Handle{}, err
		}
		if err := b.setupNetworking(inc); err != nil {
			return backendinterface.Handle{}, err
		}
	}
	fail := func(err error) error {
		b.stopProc(inc)
		b.teardownNetworking(inc)
		b.cleanupJail(inc)
		return err
	}
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return backendinterface.Handle{}, err
	}
	os.Chmod(dir, 0o700)
	if err := copyFile(filepath.Join(dir, "rootfs.ext4"), filepath.Join(snapDir, "rootfs.ext4")); err != nil {
		return backendinterface.Handle{}, fail(err)
	}
	os.Chmod(filepath.Join(dir, "rootfs.ext4"), 0o600)
	if err := copyFile(filepath.Join(dir, "workspace.img"), filepath.Join(snapDir, "workspace.img")); err != nil {
		return backendinterface.Handle{}, fail(err)
	}
	os.Chmod(filepath.Join(dir, "workspace.img"), 0o600)
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
	memPath := memFile
	statePath := filepath.Join(snapDir, "vm.state")
	if inc.jailed {
		if err := bindMount(b.snapshotDir(inc.id), filepath.Join(inc.jailRoot, "snap")); err != nil {
			return backendinterface.Handle{}, fail(err)
		}
		// memFile is either the tip's own mem.file or the merged artifact;
		// both live under the bind-mounted snapshot root.
		rel, err := filepath.Rel(b.snapshotDir(inc.id), memFile)
		if err != nil {
			return backendinterface.Handle{}, fail(err)
		}
		ts := filepath.Base(snapDir)
		memPath = "/snap/" + filepath.ToSlash(rel)
		statePath = "/snap/" + ts + "/vm.state"
	}
	// track_dirty_pages is not persisted in snapshots: re-arm it so the
	// restored VM can take further diffs (ADR-006).
	if err := api.snapshotLoad(statePath, memPath, l.apiVsock, true, b.cfg.IncrementalSnapshots); err != nil {
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

// stopProc SIGKILLs and reaps the VMM process. Fields are swapped under
// b.mu, but the (up to 5s) exit wait runs WITHOUT the lock so a stuck VMM
// never stalls other incarnations (FL7). Idempotent: the process handle is
// nil-ed under the lock, so concurrent callers no-op.
func (b *Backend) stopProc(inc *incarnation) {
	b.mu.Lock()
	cmd, exited, jailed := inc.cmd, inc.exited, inc.jailed
	inc.cmd = nil
	inc.sup = nil
	b.mu.Unlock()
	if cmd == nil || cmd.Process == nil || exited == nil {
		return
	}
	select {
	case <-exited:
		return
	default:
	}
	if jailed {
		// sudo+jailer+firecracker run in their own process group (Setpgid
		// at spawn).
		killProcessGroup(cmd.Process.Pid)
	} else {
		cmd.Process.Kill()
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
	}
}

// Terminate SIGKILLs the VMM process, reaps it, tears down networking and
// jail artifacts, and removes the incarnation directory. Snapshots under
// <root>/snapshots are retained unless DeleteSnapshotsOnTerminate is set.
func (b *Backend) Terminate(h backendinterface.Handle) error {
	b.mu.Lock()
	inc, ok := b.incs[h.IncarnationID]
	if ok {
		inc.dead = true
	}
	b.mu.Unlock()
	if !ok {
		return nil
	}
	b.stopProc(inc)
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
	inc, ok := b.incs[h.IncarnationID]
	if ok {
		inc.dead = true
	}
	b.mu.Unlock()
	if !ok {
		return
	}
	b.stopProc(inc)
	b.teardownNetworking(inc)
	b.cleanupJail(inc)
	os.RemoveAll(inc.dir)
}

// Close reaps every spawned firecracker process (guardrail for test and
// host-agent shutdown).
func (b *Backend) Close() error {
	b.mu.Lock()
	incs := make([]*incarnation, 0, len(b.incs))
	for _, inc := range b.incs {
		inc.dead = true
		incs = append(incs, inc)
	}
	b.mu.Unlock()
	for _, inc := range incs {
		b.stopProc(inc)
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
// Completed results are cached (bounded, maxCachedResults) and the live op
// entry pruned, so per-incarnation maps stay bounded (FL9) while repeat
// waits (reconciler, duplicate CompleteExecution) stay idempotent.
func (b *Backend) WaitExecution(h backendinterface.Handle, executionID string) (supervisor.Result, error) {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return supervisor.Result{}, err
	}
	if res, done := inc.results[executionID]; done {
		b.mu.Unlock()
		return res, nil
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
	res, err := sup.Wait(executionID)
	if err != nil {
		return supervisor.Result{}, err
	}
	b.mu.Lock()
	delete(inc.ops, executionID)
	inc.results[executionID] = res
	inc.resultsOrder = append(inc.resultsOrder, executionID)
	for len(inc.resultsOrder) > maxCachedResults {
		delete(inc.results, inc.resultsOrder[0])
		inc.resultsOrder = inc.resultsOrder[1:]
	}
	b.mu.Unlock()
	return res, nil
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
	inv, baseline, err := sup.Inventory()
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
