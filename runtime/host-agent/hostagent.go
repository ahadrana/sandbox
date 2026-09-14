// Package hostagent simulates a Kubernetes-fleet Runtime Host (DESIGN §6.6,
// PLAN §8): registration, heartbeats, capacity accounting, a bounded local
// artifact/workspace cache, fenced create/terminate, and supervision of its
// incarnations through the local backend. Kubernetes objects never appear in
// any public surface (INV-019).
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
	localbackend "github.com/agent-sandbox/platform/runtime/local-backend"
)

var (
	ErrStaleFence = errors.New("stale placement fence")
	ErrCapacity   = errors.New("host capacity exceeded")
	ErrHostDown   = errors.New("host unreachable")
)

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
	backend *localbackend.Backend
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
}

func New(hostID string, backend *localbackend.Backend, envs EnvironmentSource, ws WorkspaceStore, memCapacity int64, slots int, cacheSize int) *HostAgent {
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

func (h *HostAgent) Backend() *localbackend.Backend { return h.backend }

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
	return h.backend.Snapshot(handle)
}

func (h *HostAgent) Restore(cp backendinterface.CheckpointData) (backendinterface.Handle, error) {
	return h.backend.Restore(cp)
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
