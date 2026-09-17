package sandboxlab

import (
	"fmt"
	"math"
	"time"

	"github.com/agent-sandbox/platform/runtime/backend-interface"
	fakebackend "github.com/agent-sandbox/platform/runtime/fake-backend"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
	"github.com/agent-sandbox/platform/runtime/hostfacts"
	"github.com/agent-sandbox/platform/workspace"
)

// Latencies models per-operation work as virtual time (ADR-010 §4): a
// SimHost op in flat mode advances the virtual clock by the configured
// amount before returning. In contention mode (Pools set) the flat latency
// is the op's UNCONTENDED duration: its work vector is derived from it.
type Latencies struct {
	Create    time.Duration
	Snapshot  time.Duration
	Restore   time.Duration
	Terminate time.Duration
}

// Pools configures the phase-6 resource-contention model (ADR-010). The
// zero value selects flat-latency mode (byte-identical legacy behavior).
// When VCPU > 0 the host shares its pools fluidly among in-flight ops and
// idle-VM background load; unset io/net pools get defaults (500 / 1000
// MB/s). VMIdleVCPU is explicit: 0 means idle VMs consume no vCPU.
type Pools struct {
	VCPU       float64
	IOMBps     float64
	NetMBps    float64
	VMIdleVCPU float64 // background vCPU load per live VM
}

func (p Pools) withDefaults() Pools {
	if p.IOMBps <= 0 {
		p.IOMBps = 500
	}
	if p.NetMBps <= 0 {
		p.NetMBps = 1000
	}
	return p
}

// Reference bandwidths (ADR-010 phase 6): an op's I/O and network work is
// FIXED bytes, derived from its flat latency against these reference rates
// — so the uncontended duration is exactly L on any host whose pools meet
// the reference, while hosts with smaller pools are honestly slower and
// bigger pools do not inflate the work.
const (
	refIOMBps  = 250.0
	refNetMBps = 500.0
)

// opCPUDemand is the per-op vCPU demand in cores (restore/create are
// boot-heavy; snapshot/terminate lighter).
func opCPUDemand(kind string) float64 {
	switch kind {
	case "create", "restore":
		return 1.0
	case "snapshot":
		return 0.5
	default: // terminate
		return 0.25
	}
}

// inflight is one op's remaining work under the fluid model.
type inflight struct {
	id       uint64
	kind     string
	start    time.Duration
	cpuCores float64
	remCPU   float64 // core-seconds
	remIO    float64 // MB
	remNet   float64 // MB
}

// resModel is one host's fluid fair-sharing simulator. All state changes
// happen at settle points (op start, wake event); between them rates are
// constant, so projected completions are exact.
type resModel struct {
	k      *Kernel
	host   *SimHost
	pools  Pools
	active map[uint64]*inflight
	nextID uint64
	last   time.Duration
	wake   uint64 // version counter; stale wake events no-op
}

const remEps = 1e-9

// rates computes each active op's current (cpu cores, io MB/s, net MB/s).
func (m *resModel) rates() (cpu, io, net map[uint64]float64) {
	cpu, io, net = map[uint64]float64{}, map[uint64]float64{}, map[uint64]float64{}
	demand := float64(m.host.View().UsedSlots) * m.pools.VMIdleVCPU
	for _, op := range m.active {
		if op.remCPU > remEps {
			demand += op.cpuCores
		}
	}
	nIO, nNet := 0, 0
	for _, op := range m.active {
		if op.remIO > remEps {
			nIO++
		}
		if op.remNet > remEps {
			nNet++
		}
	}
	for id, op := range m.active {
		if op.remCPU > remEps && demand > 0 {
			cpu[id] = op.cpuCores * math.Min(1, m.pools.VCPU/demand)
		}
		if op.remIO > remEps && nIO > 0 {
			io[id] = m.pools.IOMBps / float64(nIO)
		}
		if op.remNet > remEps && nNet > 0 {
			net[id] = m.pools.NetMBps / float64(nNet)
		}
	}
	return
}

// settle advances every in-flight op to virtual time now, completes those
// whose work is finished (recording the stretched duration and a trace
// note), and reprograms the next wake event.
func (m *resModel) settle(now time.Duration) {
	dt := now - m.last
	m.last = now
	if dt > 0 {
		cpu, io, net := m.rates()
		sec := dt.Seconds()
		for id, op := range m.active {
			op.remCPU -= cpu[id] * sec
			op.remIO -= io[id] * sec
			op.remNet -= net[id] * sec
		}
	}
	for id, op := range m.active {
		if op.remCPU <= remEps && op.remIO <= remEps && op.remNet <= remEps {
			d := now - op.start
			m.host.OpDur[op.kind] = append(m.host.OpDur[op.kind], d)
			m.k.Note(fmt.Sprintf("op:%s host:%s done %dms", op.kind, m.host.HostID(), d.Milliseconds()))
			delete(m.active, id)
		}
	}
	m.reprogram(now)
}

// reprogram schedules the next wake at the earliest projected completion
// under current rates; stale wakes no-op via the version counter.
func (m *resModel) reprogram(now time.Duration) {
	m.wake++
	if len(m.active) == 0 {
		return
	}
	cpu, io, net := m.rates()
	var next time.Duration = -1
	for id, op := range m.active {
		var d float64
		if op.remCPU > remEps {
			d = math.Max(d, op.remCPU/cpu[id])
		}
		if op.remIO > remEps {
			d = math.Max(d, op.remIO/io[id])
		}
		if op.remNet > remEps {
			d = math.Max(d, op.remNet/net[id])
		}
		fin := now + time.Duration(d*1e9) // seconds -> ns
		if next < 0 || fin < next {
			next = fin
		}
	}
	v := m.wake
	m.k.At(next, "settle "+m.host.HostID(), func() {
		if v != m.wake {
			return // stale: a later start/finish reprogrammed
		}
		m.settle(m.k.Now())
	})
}

// startOp registers an op whose flat latency L is its uncontended
// duration: cpu work = L × demand core-seconds; io/net work = L × the
// reference bandwidth (fixed bytes, independent of this host's pools).
func (m *resModel) startOp(kind string, L time.Duration) {
	m.settle(m.k.Now())
	cores := opCPUDemand(kind)
	sec := L.Seconds()
	m.nextID++
	m.active[m.nextID] = &inflight{
		id: m.nextID, kind: kind, start: m.k.Now(),
		cpuCores: cores,
		remCPU:   sec * cores,
		remIO:    sec * refIOMBps,
		remNet:   sec * refNetMBps,
	}
	m.reprogram(m.k.Now())
}

func (m *resModel) idle() bool { return len(m.active) == 0 }

// capsBackend is the conformance-suite capability wrapper: the fake backend
// with an overridden Capabilities surface (e.g. CheckpointReclaimsMemory so
// checkpoint suspends reclaim the incarnation and resume routes a restore).
// It also implements the optional PortPublisher seam as a no-op: the sim's
// data plane is honest (publish succeeds, nothing is DNATed — there is no
// network in-process), so endpoint bindings exercise their full lifecycle.
type capsBackend struct {
	*fakebackend.Backend
	caps backendinterface.Capabilities
}

func (b capsBackend) Capabilities() backendinterface.Capabilities { return b.caps }

func (b capsBackend) PublishPort(h backendinterface.Handle, guestPort, hostPort int) error {
	return nil
}

func (b capsBackend) UnpublishPort(h backendinterface.Handle, hostPort int) error { return nil }

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
	// OpDur records completed op durations (contention mode only) — the
	// p50/p99 evidence the verdict prints.
	OpDur map[string][]time.Duration

	rm *resModel // nil: flat-latency mode
}

// NewSimHost builds a host with the given capacity, facts, and latencies.
// Checkpoint suspends reclaim memory (snapshot-class checkpoints), matching
// the production Firecracker capability surface.
func NewSimHost(k *Kernel, hostID string, ws *workspace.Memory, memCapacity int64, slots int, facts hostfacts.Facts, lat Latencies) *SimHost {
	caps := fakebackend.New().Capabilities()
	caps.CheckpointReclaimsMemory = true
	caps.SupportsPortPublish = true
	agent := hostagent.New(hostID, capsBackend{fakebackend.New(), caps}, nil, ws, memCapacity, slots, 64)
	agent.SetFacts(facts)
	return &SimHost{HostAgent: agent, k: k, lat: lat, facts: facts, Restores: map[string]int{}, OpDur: map[string][]time.Duration{}}
}

// SetPools enables the phase-6 contention model on this host.
func (s *SimHost) SetPools(p Pools) {
	if p.VCPU <= 0 {
		return
	}
	s.rm = &resModel{k: s.k, host: s, pools: p.withDefaults(), active: map[uint64]*inflight{}}
}

// OpsIdle reports whether the contention model has no in-flight ops (the
// driver's join condition). Flat-mode hosts are always idle.
func (s *SimHost) OpsIdle() bool { return s.rm == nil || s.rm.idle() }

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

// charge routes the op's time cost: flat mode burns inline (legacy,
// byte-identical traces); contention mode registers in-flight work whose
// completion is a kernel wake event, joined by the scenario driver.
func (s *SimHost) charge(op string, d time.Duration) {
	if s.rm == nil {
		s.burn(op, d)
		return
	}
	s.rm.startOp(op, d)
}

func (s *SimHost) Create(req hostagent.CreateRequest) (backendinterface.Handle, error) {
	h, err := s.HostAgent.Create(req)
	if err == nil {
		s.charge("create", s.lat.Create)
	}
	return h, err
}

func (s *SimHost) Restore(cp backendinterface.CheckpointData) (backendinterface.Handle, error) {
	s.Restores[cp.IncarnationID]++
	h, err := s.HostAgent.Restore(cp)
	if err == nil {
		s.charge("restore", s.lat.Restore)
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
		s.charge("snapshot", s.lat.Snapshot)
	}
	return cp, err
}

func (s *SimHost) Terminate(h backendinterface.Handle) error {
	err := s.HostAgent.Terminate(h)
	if err == nil {
		s.charge("terminate", s.lat.Terminate)
	}
	return err
}

// compile-time check: SimHost must satisfy the fleet's Host surface.
var _ hostagent.Host = (*SimHost)(nil)
