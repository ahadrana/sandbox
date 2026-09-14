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
}

// Request describes one incarnation placement.
type Request struct {
	SandboxID      string
	EnvironmentID  string
	WorkspaceID    string
	MemoryRequired int64
	Priority       int
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
	if h.CachedCheckpoints[req.SandboxID] {
		score += 3
	}
	return score
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
