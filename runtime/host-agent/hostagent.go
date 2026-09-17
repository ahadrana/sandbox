// Package hostagent simulates a Kubernetes-fleet Runtime Host (DESIGN §6.6,
// PLAN §8): registration, heartbeats, capacity accounting, a bounded local
// artifact/workspace cache, fenced create/terminate, and supervision of its
// incarnations through any RuntimeBackend (local process or Firecracker VM).
// Kubernetes objects never appear in any public surface (INV-019).
package hostagent

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/agent-sandbox/platform/control-plane/scheduler"
	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/runtime/backend-interface"
	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
	"github.com/agent-sandbox/platform/runtime/hostfacts"
)

var (
	ErrStaleFence = errors.New("stale placement fence")
	ErrCapacity   = errors.New("host capacity exceeded")
	ErrHostDown   = errors.New("host unreachable")
	// ErrInvalidCheckpoint marks a restore checkpoint whose accounting facts
	// (sandbox_id, memory_bytes) are missing or unparseable (review M5).
	ErrInvalidCheckpoint = errors.New("invalid checkpoint")
)

// RuntimeBackend is the backend surface a HostAgent supervises: the full
// manager Runtime contract (backendinterface.Backend plus the execution and
// supervision operations) plus the adoption surface — LiveHandles/LiveSpecs
// let a restarted host agent re-adopt still-live incarnations and rebuild
// ownership, fence, and capacity state (INV-016). The local process backend
// and the Firecracker VM backend both satisfy it.
type RuntimeBackend interface {
	backendinterface.Backend
	Exec(h backendinterface.Handle, executionID string, op domain.Operation) error
	WaitExecution(h backendinterface.Handle, executionID string) (supervisor.Result, error)
	LiveDescendants(h backendinterface.Handle) int
	LiveNonBaselineDescendants(h backendinterface.Handle) int
	ProcessInventory(h backendinterface.Handle) ([]supervisor.ProcessInfo, error)
	TerminateBackground(h backendinterface.Handle) error
	WorkspaceFiles(h backendinterface.Handle) (map[string]string, error)
	Dirty(h backendinterface.Handle) bool
	MarkCommitted(h backendinterface.Handle)
	KillRuntime(h backendinterface.Handle)
	Alive(h backendinterface.Handle) bool
	Tick()
	LiveHandles() []backendinterface.Handle
	LiveSpecs() []backendinterface.Spec
}

// EnvironmentSource resolves prepared-environment artifacts.
type EnvironmentSource interface {
	ArtifactManifest(environmentID string) (map[string]string, error)
}

// WorkspaceStore resolves committed workspace generations.
type WorkspaceStore interface {
	Materialize(workspaceID string, generation int64) (map[string]string, error)
}

// artifactCache is a bounded LRU cache of environment/workspace manifests.
type artifactCache struct {
	mu      sync.Mutex
	max     int
	entries map[string]*cacheEntry
	pinned  map[string]int // pin refcount: artifacts of live incarnations
	use     int64
	fetches int
}

type cacheEntry struct {
	manifest map[string]string
	lastUse  int64
}

func newArtifactCache(max int) *artifactCache {
	return &artifactCache{max: max, entries: map[string]*cacheEntry{}, pinned: map[string]int{}}
}

// getOrFetch returns a cached manifest or fetches it from the durable store,
// counting every fetch.
func (c *artifactCache) getOrFetch(key string, fetch func() (map[string]string, error)) (map[string]string, error) {
	c.mu.Lock()
	c.use++
	if e, ok := c.entries[key]; ok {
		e.lastUse = c.use
		c.mu.Unlock()
		return e.manifest, nil
	}
	c.mu.Unlock()

	manifest, err := fetch()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fetches++
	c.use++
	if len(c.entries) >= c.max {
		// Eviction policy: LRU among UNPINNED entries — an artifact used by
		// a live incarnation is never evicted; if everything is pinned the
		// cache temporarily exceeds its size bound (correctness over size).
		var oldestKey string
		var oldestUse int64 = -1
		for k, e := range c.entries {
			if c.pinned[k] > 0 {
				continue
			}
			if oldestUse < 0 || e.lastUse < oldestUse {
				oldestKey, oldestUse = k, e.lastUse
			}
		}
		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}
	c.entries[key] = &cacheEntry{manifest: manifest, lastUse: c.use}
	return manifest, nil
}

// Pin protects an artifact from eviction; Unpin releases one reference.
func (c *artifactCache) Pin(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pinned[key]++
}

func (c *artifactCache) Unpin(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pinned[key] > 0 {
		c.pinned[key]--
	}
}

func (c *artifactCache) Fetches() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fetches
}

// Flush evicts everything (test hook).
func (c *artifactCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]*cacheEntry{}
}

func (c *artifactCache) has(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[key]
	return ok
}

// keys snapshots the cache keys under the cache lock (safe for concurrent
// readers like View).
func (c *artifactCache) keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.entries))
	for k := range c.entries {
		out = append(out, k)
	}
	return out
}

// CreateRequest is a fenced incarnation-create command from the control plane.
type CreateRequest struct {
	SandboxID           string
	IncarnationID       string
	Fence               int64
	Epoch               int64
	EnvironmentID       string
	WorkspaceID         string
	WorkspaceGeneration int64
	MemoryBytes         int64
}

type incRecord struct {
	sandboxID string
	fence     int64
	memory    int64
	envID     string
	paused    bool
}

// HostAgent is one simulated runtime host.
type HostAgent struct {
	mu      sync.Mutex
	hostID  string
	backend RuntimeBackend
	envs    EnvironmentSource
	ws      WorkspaceStore
	cache   *artifactCache

	memCapacity int64
	memUsed     int64
	slots       int
	slotsUsed   int

	incarnations map[string]*incRecord // incarnationID -> record
	fences       map[string]int64      // sandboxID -> highest accepted fence
	bySandbox    map[string]string     // sandboxID -> live incarnationID

	// protectedPorts may never be published to guests: publishing the
	// agent's own RPC port would DNAT-hijack heartbeats and RPC traffic
	// into a guest (observed: host declared lost, teardown suppressed).
	protectedPorts map[int]bool

	// factsOverride, when set, replaces hostfacts.Current() in View —
	// the seam SandboxLab (ADR-010) uses to simulate a heterogeneous
	// fleet (mixed kernels/CPU parts) on one machine.
	factsOverride *hostfacts.Facts
}

// ProtectPorts forbids publishing the given host ports (the daemon calls
// it with its own RPC listen port).
func (h *HostAgent) ProtectPorts(ports ...int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.protectedPorts == nil {
		h.protectedPorts = map[int]bool{}
	}
	for _, p := range ports {
		h.protectedPorts[p] = true
	}
}

// SetFacts overrides the host facts View reports (ADR-010): simulation
// scenarios need heterogeneous fleets (mixed kernel releases / CPU parts)
// on one machine. Unset, View reports hostfacts.Current() as before.
func (h *HostAgent) SetFacts(f hostfacts.Facts) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.factsOverride = &f
}

func New(hostID string, backend RuntimeBackend, envs EnvironmentSource, ws WorkspaceStore, memCapacity int64, slots int, cacheSize int) *HostAgent {
	h := &HostAgent{
		hostID: hostID, backend: backend, envs: envs, ws: ws,
		cache:       newArtifactCache(cacheSize),
		memCapacity: memCapacity, slots: slots,
		incarnations: map[string]*incRecord{}, fences: map[string]int64{},
		bySandbox: map[string]string{},
	}
	// Host restart with an intact backend: adopt still-live incarnations so
	// they remain supervised. Ownership and fence state are rebuilt from the
	// retained create-spec metadata, so a replayed pre-restart Create is
	// idempotent (same sandbox, same fence -> same incarnation), never a
	// duplicate.
	for _, spec := range backend.LiveSpecs() {
		fence := adoptedFence(spec)
		h.incarnations[spec.IncarnationID] = &incRecord{
			sandboxID: spec.SandboxID, fence: fence,
			memory: spec.MemoryBytes, envID: spec.EnvironmentID,
		}
		if spec.SandboxID != "" {
			h.bySandbox[spec.SandboxID] = spec.IncarnationID
			if fence > h.fences[spec.SandboxID] {
				h.fences[spec.SandboxID] = fence
			}
		}
		h.slotsUsed++
		h.memUsed += spec.MemoryBytes
	}
	for _, handle := range backend.LiveHandles() {
		if _, ok := h.incarnations[handle.IncarnationID]; !ok {
			h.incarnations[handle.IncarnationID] = &incRecord{}
			h.slotsUsed++
		}
	}
	return h
}

// fenceEnvKey carries the placement fence in the backend-retained spec
// metadata, surviving host-agent restarts.
const fenceEnvKey = "AGENT_SANDBOX_PLACEMENT_FENCE"

// adoptedFence recovers the placement fence recorded at create time.
func adoptedFence(spec backendinterface.Spec) int64 {
	var n int64
	fmt.Sscanf(spec.Env[fenceEnvKey], "%d", &n)
	return n
}

func (h *HostAgent) HostID() string { return h.hostID }

// IncarnationIDs snapshots the host's live incarnation IDs under the host
// lock (used by fleet orphan reconciliation at re-registration).
func (h *HostAgent) IncarnationIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.incarnations))
	for id := range h.incarnations {
		out = append(out, id)
	}
	return out
}

func (h *HostAgent) Backend() RuntimeBackend { return h.backend }

func (h *HostAgent) Cache() *artifactCache { return h.cache }

// Create materializes an incarnation from cache/durable stores under a
// placement fence. Replays with the current fence are idempotent (exactly
// one incarnation); older fences are rejected. The fence/capacity check and
// the backend create are atomic under h.mu: neither assemble nor
// backend.Create calls back into the host, so concurrent duplicate creates
// yield exactly one incarnation and a single capacity charge.
func (h *HostAgent) Create(req CreateRequest) (backendinterface.Handle, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if req.Fence < h.fences[req.SandboxID] {
		return backendinterface.Handle{}, ErrStaleFence
	}
	if req.Fence == h.fences[req.SandboxID] {
		if incID, ok := h.bySandbox[req.SandboxID]; ok {
			return backendinterface.Handle{IncarnationID: incID}, nil
		}
	}
	if h.slotsUsed+1 > h.slots || h.memUsed+req.MemoryBytes > h.memCapacity {
		return backendinterface.Handle{}, ErrCapacity
	}

	// Pin the environment artifact before assembly so eviction pressure
	// from this very create cannot evict it (pin protection, PLAN §13).
	if req.EnvironmentID != "" {
		h.cache.Pin("env:" + req.EnvironmentID)
	}
	manifest, err := h.assemble(req)
	if err != nil {
		if req.EnvironmentID != "" {
			h.cache.Unpin("env:" + req.EnvironmentID)
		}
		return backendinterface.Handle{}, err
	}
	handle, err := h.backend.Create(backendinterface.Spec{
		SandboxID:           req.SandboxID,
		IncarnationID:       req.IncarnationID,
		Epoch:               req.Epoch,
		EnvironmentID:       req.EnvironmentID,
		WorkspaceID:         req.WorkspaceID,
		WorkspaceGeneration: req.WorkspaceGeneration,
		WorkspaceManifest:   manifest,
		MemoryBytes:         req.MemoryBytes,
		Env:                 map[string]string{fenceEnvKey: fmt.Sprintf("%d", req.Fence)},
	})
	if err != nil {
		if req.EnvironmentID != "" {
			h.cache.Unpin("env:" + req.EnvironmentID)
		}
		return backendinterface.Handle{}, err
	}
	h.fences[req.SandboxID] = req.Fence
	h.bySandbox[req.SandboxID] = req.IncarnationID
	h.incarnations[req.IncarnationID] = &incRecord{sandboxID: req.SandboxID, fence: req.Fence, memory: req.MemoryBytes, envID: req.EnvironmentID}
	h.slotsUsed++
	h.memUsed += req.MemoryBytes
	return handle, nil
}

// assemble builds the incarnation manifest: environment artifact base layer
// plus the workspace generation overlay, from cache or durable stores.
func (h *HostAgent) assemble(req CreateRequest) (map[string]string, error) {
	manifest := map[string]string{}
	if req.EnvironmentID != "" && h.envs != nil {
		base, err := h.cache.getOrFetch("env:"+req.EnvironmentID, func() (map[string]string, error) {
			return h.envs.ArtifactManifest(req.EnvironmentID)
		})
		if err != nil {
			return nil, err
		}
		for k, v := range base {
			manifest[k] = v
		}
	}
	key := fmt.Sprintf("ws:%s:%d", req.WorkspaceID, req.WorkspaceGeneration)
	overlay, err := h.cache.getOrFetch(key, func() (map[string]string, error) {
		return h.ws.Materialize(req.WorkspaceID, req.WorkspaceGeneration)
	})
	if err != nil {
		return nil, err
	}
	for k, v := range overlay {
		manifest[k] = v
	}
	return manifest, nil
}

// Terminate destroys an incarnation, frees capacity, and scrubs local state.
func (h *HostAgent) Terminate(handle backendinterface.Handle) error {
	h.mu.Lock()
	rec, ok := h.incarnations[handle.IncarnationID]
	if ok {
		delete(h.incarnations, handle.IncarnationID)
		delete(h.bySandbox, rec.sandboxID)
		h.slotsUsed--
		h.memUsed -= rec.memory
		if rec.envID != "" {
			h.cache.Unpin("env:" + rec.envID)
		}
	}
	h.mu.Unlock()
	return h.backend.Terminate(handle)
}

func (h *HostAgent) route(handle backendinterface.Handle) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.incarnations[handle.IncarnationID]; !ok {
		return backendinterface.ErrNotFound
	}
	return nil
}

// The remaining methods supervise incarnations through the local backend;
// they are the in-process stand-in for the supervisor transport proxy.

func (h *HostAgent) Start(handle backendinterface.Handle) error {
	if err := h.route(handle); err != nil {
		return err
	}
	return h.backend.Start(handle)
}

func (h *HostAgent) Pause(handle backendinterface.Handle) error {
	if err := h.route(handle); err != nil {
		return err
	}
	if err := h.backend.Pause(handle); err != nil {
		return err
	}
	h.mu.Lock()
	if rec, ok := h.incarnations[handle.IncarnationID]; ok {
		rec.paused = true
	}
	h.mu.Unlock()
	return nil
}

func (h *HostAgent) Resume(handle backendinterface.Handle) error {
	if err := h.route(handle); err != nil {
		return err
	}
	if err := h.backend.Resume(handle); err != nil {
		return err
	}
	h.mu.Lock()
	if rec, ok := h.incarnations[handle.IncarnationID]; ok {
		rec.paused = false
	}
	h.mu.Unlock()
	return nil
}

func (h *HostAgent) Snapshot(handle backendinterface.Handle) (backendinterface.CheckpointData, error) {
	if err := h.route(handle); err != nil {
		return backendinterface.CheckpointData{}, err
	}
	cp, err := h.backend.Snapshot(handle)
	if err != nil {
		return backendinterface.CheckpointData{}, err
	}
	// Self-describing checkpoint (ADR-008): a routed restore must be able to
	// re-register the incarnation on the origin host from the checkpoint
	// alone, so the host's accounting facts travel in the metadata.
	h.mu.Lock()
	if rec, ok := h.incarnations[handle.IncarnationID]; ok {
		if cp.Metadata == nil {
			cp.Metadata = map[string]string{}
		}
		cp.Metadata["sandbox_id"] = rec.sandboxID
		cp.Metadata["environment_id"] = rec.envID
		cp.Metadata["memory_bytes"] = fmt.Sprintf("%d", rec.memory)
		cp.Metadata["fence"] = fmt.Sprintf("%d", rec.fence)
	}
	h.mu.Unlock()
	return cp, nil
}

// Restore boots an incarnation from a checkpoint on THIS host (ADR-008:
// checkpoints are host-local artifacts, so restore is origin-host-only) and
// re-registers the host-side accounting Snapshot recorded. An incarnation
// still registered (STOP/CONT class, never terminated) keeps its record; a
// reclaimed one is charged capacity again. The placement fence in the
// checkpoint metadata — refreshed by the fleet at restore placement time —
// is validated and adopted exactly like Create's.
//
// Retry semantics (review H5): restoring an already-live incarnation under
// the SAME fence is an idempotent replay — the first attempt's ACK was
// lost; the existing handle is returned and the backend is NOT re-booted.
// Accounting facts are mandatory for a re-registration (review M5): a
// checkpoint with a missing sandbox_id or unparseable memory_bytes is
// rejected with ErrInvalidCheckpoint rather than skipping the fence check
// or charging 0 capacity.
func (h *HostAgent) Restore(cp backendinterface.CheckpointData) (backendinterface.Handle, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec, known := h.incarnations[cp.IncarnationID]
	sandboxID := cp.Metadata["sandbox_id"]
	if known {
		sandboxID = rec.sandboxID
	}
	var fence int64
	hasFence := cp.Metadata["fence"] != ""
	if hasFence {
		fmt.Sscanf(cp.Metadata["fence"], "%d", &fence)
		if sandboxID != "" && fence < h.fences[sandboxID] {
			return backendinterface.Handle{}, ErrStaleFence
		}
	}
	if known && !rec.paused && (!hasFence || fence == rec.fence) {
		// Lost-ACK replay: the incarnation is already live from a prior
		// restore under this fence — return it, never re-boot (review H5).
		return backendinterface.Handle{IncarnationID: cp.IncarnationID}, nil
	}
	var memory int64
	if !known {
		if sandboxID == "" {
			return backendinterface.Handle{}, fmt.Errorf("checkpoint %s missing sandbox_id: %w", cp.IncarnationID, ErrInvalidCheckpoint)
		}
		if n, _ := fmt.Sscanf(cp.Metadata["memory_bytes"], "%d", &memory); n != 1 || memory <= 0 {
			return backendinterface.Handle{}, fmt.Errorf("checkpoint %s has unparseable memory_bytes %q: %w", cp.IncarnationID, cp.Metadata["memory_bytes"], ErrInvalidCheckpoint)
		}
	}
	if !known && (h.slotsUsed+1 > h.slots || h.memUsed+memory > h.memCapacity) {
		return backendinterface.Handle{}, ErrCapacity
	}
	handle, err := h.backend.Restore(cp)
	if err != nil {
		return backendinterface.Handle{}, err
	}
	if known {
		rec.paused = false
		// Never regress the record fence below an already-advanced value
		// (review L5): adoption is a max, not an assignment.
		if hasFence && fence > rec.fence {
			rec.fence = fence
		}
	} else {
		h.incarnations[cp.IncarnationID] = &incRecord{
			sandboxID: sandboxID, fence: fence,
			memory: memory, envID: cp.Metadata["environment_id"],
		}
		if sandboxID != "" {
			h.bySandbox[sandboxID] = cp.IncarnationID
		}
		h.slotsUsed++
		h.memUsed += memory
	}
	if sandboxID != "" && fence > h.fences[sandboxID] {
		h.fences[sandboxID] = fence
	}
	return handle, nil
}

// PublishPort exposes a guest TCP port on the host address (ADR-007 data
// plane) when the backend implements backendinterface.PortPublisher;
// otherwise honestly unsupported. Like every other routed op the handle
// must be registered AND the fence must match the current placement
// (review H2): a stale control-plane view must not install DNAT the
// ownership model would reject.
func (h *HostAgent) PublishPort(handle backendinterface.Handle, guestPort, hostPort int, fence int64) error {
	h.mu.Lock()
	rec, ok := h.incarnations[handle.IncarnationID]
	if !ok {
		h.mu.Unlock()
		return backendinterface.ErrNotFound
	}
	if fence != rec.fence {
		h.mu.Unlock()
		return fmt.Errorf("publish fence %d, current placement fence %d: %w", fence, rec.fence, ErrStaleFence)
	}
	protected := h.protectedPorts[hostPort]
	h.mu.Unlock()
	if protected {
		return fmt.Errorf("host port %d is reserved for the host agent itself: %w", hostPort, backendinterface.ErrPortConflict)
	}
	pp, ok := h.backend.(backendinterface.PortPublisher)
	if !ok {
		return supervisor.ErrUnsupported
	}
	return pp.PublishPort(handle, guestPort, hostPort)
}

// UnpublishPort removes a published host port under the same route+fence
// discipline as PublishPort (review H2). An unknown incarnation is a no-op
// (its teardown already removed the rules); a stale fence is a typed error
// — the current placement's rules are not a stale view's to remove.
func (h *HostAgent) UnpublishPort(handle backendinterface.Handle, hostPort int, fence int64) error {
	h.mu.Lock()
	rec, ok := h.incarnations[handle.IncarnationID]
	if !ok {
		h.mu.Unlock()
		return nil
	}
	if fence != rec.fence {
		h.mu.Unlock()
		return fmt.Errorf("unpublish fence %d, current placement fence %d: %w", fence, rec.fence, ErrStaleFence)
	}
	h.mu.Unlock()
	pp, ok := h.backend.(backendinterface.PortPublisher)
	if !ok {
		return nil
	}
	return pp.UnpublishPort(handle, hostPort)
}

func (h *HostAgent) Stats(handle backendinterface.Handle) (backendinterface.Stats, error) {
	if err := h.route(handle); err != nil {
		return backendinterface.Stats{}, err
	}
	return h.backend.Stats(handle)
}

// Exec forwards an execution to the incarnation's supervisor.
func (h *HostAgent) Exec(handle backendinterface.Handle, executionID string, op domain.Operation) error {
	if err := h.route(handle); err != nil {
		return err
	}
	return h.backend.Exec(handle, executionID, op)
}

func (h *HostAgent) WaitExecution(handle backendinterface.Handle, executionID string) (supervisor.Result, error) {
	if err := h.route(handle); err != nil {
		return supervisor.Result{}, err
	}
	return h.backend.WaitExecution(handle, executionID)
}

func (h *HostAgent) LiveDescendants(handle backendinterface.Handle) int {
	if err := h.route(handle); err != nil {
		return 0
	}
	return h.backend.LiveDescendants(handle)
}

func (h *HostAgent) WorkspaceFiles(handle backendinterface.Handle) (map[string]string, error) {
	if err := h.route(handle); err != nil {
		return nil, err
	}
	return h.backend.WorkspaceFiles(handle)
}

func (h *HostAgent) Dirty(handle backendinterface.Handle) bool {
	if err := h.route(handle); err != nil {
		return false
	}
	return h.backend.Dirty(handle)
}

func (h *HostAgent) MarkCommitted(handle backendinterface.Handle) {
	if err := h.route(handle); err != nil {
		return
	}
	h.backend.MarkCommitted(handle)
}

func (h *HostAgent) KillRuntime(handle backendinterface.Handle) {
	h.mu.Lock()
	if rec, ok := h.incarnations[handle.IncarnationID]; ok {
		delete(h.incarnations, handle.IncarnationID)
		delete(h.bySandbox, rec.sandboxID)
		h.slotsUsed--
		h.memUsed -= rec.memory
		if rec.envID != "" {
			h.cache.Unpin("env:" + rec.envID)
		}
	}
	h.mu.Unlock()
	h.backend.KillRuntime(handle)
}

func (h *HostAgent) Alive(handle backendinterface.Handle) bool {
	return h.backend.Alive(handle)
}

func (h *HostAgent) LiveNonBaselineDescendants(handle backendinterface.Handle) int {
	if err := h.route(handle); err != nil {
		return 0
	}
	return h.backend.LiveNonBaselineDescendants(handle)
}

// ProcessInventory delegates to the host's backend.
func (h *HostAgent) ProcessInventory(handle backendinterface.Handle) ([]supervisor.ProcessInfo, error) {
	if err := h.route(handle); err != nil {
		return nil, err
	}
	return h.backend.ProcessInventory(handle)
}

func (h *HostAgent) TerminateBackground(handle backendinterface.Handle) error {
	if err := h.route(handle); err != nil {
		return err
	}
	return h.backend.TerminateBackground(handle)
}

func (h *HostAgent) Tick() { h.backend.Tick() }

// Capabilities delegates to the host's backend.
func (h *HostAgent) Capabilities() backendinterface.Capabilities {
	return h.backend.Capabilities()
}

// View is the heartbeat payload: health plus capacity and cache state.
func (h *HostAgent) View() scheduler.HostView {
	h.mu.Lock()
	defer h.mu.Unlock()
	facts := hostfacts.Current()
	if h.factsOverride != nil {
		facts = *h.factsOverride
	}
	v := scheduler.HostView{
		HostID:             h.hostID,
		Healthy:            true,
		CapacityMemory:     h.memCapacity,
		UsedMemory:         h.memUsed,
		CapacitySlots:      h.slots,
		UsedSlots:          h.slotsUsed,
		CachedEnvironments: map[string]bool{},
		CachedWorkspaces:   map[string]bool{},
		CachedCheckpoints:  map[string]bool{},
		// P1.7: host facts gate the checkpoint-locality bonus on restore.
		KernelRelease: facts.KernelRelease,
		CPUPart:       facts.CPUPart,
		Arch:          facts.Arch,
	}
	if h.memCapacity > 0 {
		v.Pressure = float64(h.memUsed) / float64(h.memCapacity)
	}
	for _, rec := range h.incarnations {
		if rec.paused {
			v.CachedCheckpoints[rec.sandboxID] = true
		}
	}
	for _, key := range h.cache.keys() {
		if strings.HasPrefix(key, "env:") {
			v.CachedEnvironments[strings.TrimPrefix(key, "env:")] = true
			continue
		}
		if strings.HasPrefix(key, "ws:") {
			id := strings.TrimPrefix(key, "ws:")
			if i := strings.LastIndex(id, ":"); i > 0 {
				v.CachedWorkspaces[id[:i]] = true
			}
		}
	}
	return v
}
