package sandboxlab

import (
	"fmt"
	"time"

	"github.com/agent-sandbox/platform/runtime/backend-interface"
	fakebackend "github.com/agent-sandbox/platform/runtime/fake-backend"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
	"github.com/agent-sandbox/platform/runtime/hostfacts"
	"github.com/agent-sandbox/platform/workspace"
)

// Latencies models per-operation work as virtual time (ADR-010 §4): a
// SimHost op advances the virtual clock by the configured amount before
// returning. Latency models work, not contention.
type Latencies struct {
	Create    time.Duration
	Snapshot  time.Duration
	Restore   time.Duration
	Terminate time.Duration
}

// capsBackend is the conformance-suite capability wrapper: the fake backend
// with an overridden Capabilities surface (e.g. CheckpointReclaimsMemory so
// checkpoint suspends reclaim the incarnation and resume routes a restore).
type capsBackend struct {
	*fakebackend.Backend
	caps backendinterface.Capabilities
}

func (b capsBackend) Capabilities() backendinterface.Capabilities { return b.caps }

// SimHost is one simulated runtime host: a REAL *hostagent.HostAgent over
// the fake backend, with per-op virtual latencies and per-host facts. It
// satisfies hostagent.Host by embedding and overriding the latency-bearing
// operations.
type SimHost struct {
	*hostagent.HostAgent
	k     *Kernel
	lat   Latencies
	facts hostfacts.Facts
	// Restores counts continuity-restore RPCs per incarnation — the
	// single-flight evidence the resume-storm scenario asserts.
	Restores map[string]int
}

// NewSimHost builds a host with the given capacity, facts, and latencies.
// Checkpoint suspends reclaim memory (snapshot-class checkpoints), matching
// the production Firecracker capability surface.
func NewSimHost(k *Kernel, hostID string, ws *workspace.Memory, memCapacity int64, slots int, facts hostfacts.Facts, lat Latencies) *SimHost {
	caps := fakebackend.New().Capabilities()
	caps.CheckpointReclaimsMemory = true
	agent := hostagent.New(hostID, capsBackend{fakebackend.New(), caps}, nil, ws, memCapacity, slots, 64)
	agent.SetFacts(facts)
	return &SimHost{HostAgent: agent, k: k, lat: lat, facts: facts, Restores: map[string]int{}}
}

// burn accounts one operation's virtual latency and records it in the
// trace, so behavior (not just schedule) is part of the determinism
// artifact.
func (s *SimHost) burn(op string, d time.Duration) {
	if d <= 0 {
		return
	}
	s.k.Advance(d)
	s.k.Note(fmt.Sprintf("op:%s host:%s", op, s.HostID()))
}

func (s *SimHost) Create(req hostagent.CreateRequest) (backendinterface.Handle, error) {
	h, err := s.HostAgent.Create(req)
	if err == nil {
		s.burn("create", s.lat.Create)
	}
	return h, err
}

func (s *SimHost) Restore(cp backendinterface.CheckpointData) (backendinterface.Handle, error) {
	s.Restores[cp.IncarnationID]++
	h, err := s.HostAgent.Restore(cp)
	if err == nil {
		s.burn("restore", s.lat.Restore)
	}
	return h, err
}

func (s *SimHost) Snapshot(h backendinterface.Handle) (backendinterface.CheckpointData, error) {
	cp, err := s.HostAgent.Snapshot(h)
	if err == nil {
		// The fake backend records no capture facts; the production
		// Firecracker backend stamps arch/kernel/cpu-part into the
		// checkpoint at capture (P1.7). SimHost stamps its configured facts
		// so the checkpoint-locality guard has something real to match on.
		if cp.Metadata == nil {
			cp.Metadata = map[string]string{}
		}
		cp.Metadata["arch"] = s.facts.Arch
		cp.Metadata["kernel_release"] = s.facts.KernelRelease
		cp.Metadata["cpu_part"] = s.facts.CPUPart
		s.burn("snapshot", s.lat.Snapshot)
	}
	return cp, err
}

func (s *SimHost) Terminate(h backendinterface.Handle) error {
	err := s.HostAgent.Terminate(h)
	if err == nil {
		s.burn("terminate", s.lat.Terminate)
	}
	return err
}

// compile-time check: SimHost must satisfy the fleet's Host surface.
var _ hostagent.Host = (*SimHost)(nil)
