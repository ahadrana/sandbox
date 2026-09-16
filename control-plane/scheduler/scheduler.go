// Package scheduler places runtime incarnations (never individual execs,
// DESIGN §6.3) onto runtime hosts. Cache locality is an optimization only;
// cold placement is always correct (INV-023).
package scheduler

import (
	"errors"
	"sort"
	"sync"
)

var ErrNoCapacity = errors.New("no healthy host with sufficient capacity")

// HostView is the scheduler's read model of one runtime host.
type HostView struct {
	HostID             string
	Healthy            bool
	CapacityMemory     int64
	UsedMemory         int64
	CapacitySlots      int
	UsedSlots          int
	Pressure           float64 // 0..1
	CachedEnvironments map[string]bool
	CachedWorkspaces   map[string]bool
	// CachedCheckpoints marks sandboxes with a compatible checkpoint held
	// on this host (resume locality bonus).
	CachedCheckpoints map[string]bool
	// KernelRelease and CPUPart are the host facts (uname -r, CPU model
	// discriminator) that gate checkpoint-locality (P1.7): a full-VM
	// checkpoint is only restorable on a host whose facts match the
	// checkpoint's guard. Populated by HostAgent.View.
	KernelRelease string
	CPUPart       string
	// Arch is the machine architecture (uname -m) — the coarsest checkpoint
	// compatibility fact (review L7).
	Arch string
}

// Guard describes the host facts a checkpoint depends on (P1.7). A host's
// CachedCheckpoints entry only earns its locality bonus when the host's
// facts match the guard exactly; a mismatching host is scored as if it
// held no checkpoint.
type Guard struct {
	KernelRelease string
	CPUPart       string
	Arch          string
}

// Request describes one incarnation placement.
type Request struct {
	SandboxID      string
	EnvironmentID  string
	WorkspaceID    string
	MemoryRequired int64
	Priority       int
	// CheckpointGuard, when set, is the host-facts guard of the checkpoint
	// being restored (P1.7); nil means no restore is in play.
	CheckpointGuard *Guard
}

// Placement is the scheduling decision; Fence is monotonic per sandbox and
// fences host-side create requests.
type Placement struct {
	SandboxID string
	HostID    string
	Fence     int64
}

// Scheduler is a deterministic scoring placement engine.
//
// Fence limitation: per-sandbox fence counters are memory-only. After a
// control-plane rebuild against warm hosts, a replayed create carrying an
// older persisted fence can be rejected as stale even though it is
// legitimate; persisting the fence counter in the manager store is future
// work. Callers must release sandbox fences via ReleaseFence at sandbox
// termination so the map does not grow unboundedly.
type Scheduler struct {
	mu     sync.Mutex
	fences map[string]int64
}

func New() *Scheduler {
	return &Scheduler{fences: map[string]int64{}}
}

// Fence returns the next placement fence for a sandbox.
func (s *Scheduler) nextFence(sandboxID string) int64 {
	s.fences[sandboxID]++
	return s.fences[sandboxID]
}

// ReleaseFence drops the per-sandbox fence counter; called when a sandbox
// terminates.
func (s *Scheduler) ReleaseFence(sandboxID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.fences, sandboxID)
}

// score ranks a host: capacity dominates, cache locality is a bonus,
// pressure a penalty. Locality never gates correctness. Zero-capacity
// dimensions score 0 — never NaN.
func score(req Request, h HostView) float64 {
	freeSlots := 0.0
	if h.CapacitySlots > 0 {
		freeSlots = float64(h.CapacitySlots-h.UsedSlots) / float64(h.CapacitySlots)
	}
	freeMem := 0.0
	if h.CapacityMemory > 0 {
		freeMem = float64(h.CapacityMemory-h.UsedMemory) / float64(h.CapacityMemory)
	}
	score := 3*freeSlots + 2*freeMem - 2*h.Pressure
	if h.CachedEnvironments[req.EnvironmentID] && req.EnvironmentID != "" {
		score += 4
	}
	if h.CachedWorkspaces[req.WorkspaceID] {
		score += 2
	}
	if h.CachedCheckpoints[req.SandboxID] && checkpointCompatible(req.CheckpointGuard, h) {
		score += 3
	}
	return score
}

// checkpointCompatible reports whether host facts satisfy the checkpoint's
// restore guard (P1.7): a nil guard means no restore is in play (bonus
// applies unconditionally); a set guard requires an exact match on every
// guarded fact.
func checkpointCompatible(g *Guard, h HostView) bool {
	if g == nil {
		return true
	}
	if g.KernelRelease != "" && h.KernelRelease != g.KernelRelease {
		return false
	}
	if g.CPUPart != "" && h.CPUPart != g.CPUPart {
		return false
	}
	if g.Arch != "" && h.Arch != g.Arch {
		return false
	}
	return true
}

// Place chooses a healthy host with free capacity for one incarnation.
func (s *Scheduler) Place(req Request, hosts []HostView) (Placement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var candidates []HostView
	for _, h := range hosts {
		if !h.Healthy {
			continue
		}
		if h.UsedSlots+1 > h.CapacitySlots {
			continue
		}
		if h.UsedMemory+req.MemoryRequired > h.CapacityMemory {
			continue
		}
		candidates = append(candidates, h)
	}
	if len(candidates) == 0 {
		return Placement{}, ErrNoCapacity
	}
	sort.Slice(candidates, func(i, j int) bool {
		si, sj := score(req, candidates[i]), score(req, candidates[j])
		if si != sj {
			return si > sj
		}
		return candidates[i].HostID < candidates[j].HostID
	})
	return Placement{
		SandboxID: req.SandboxID,
		HostID:    candidates[0].HostID,
		Fence:     s.nextFence(req.SandboxID),
	}, nil
}
