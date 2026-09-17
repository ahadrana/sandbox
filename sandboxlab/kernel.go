// Package sandboxlab is SandboxLab (ADR-010): a deterministic
// discrete-event simulation harness that runs the REAL control-plane code —
// sandbox-manager, fleet, scheduler, event service — in-process against
// simulated hosts and a virtual clock. The same seed and scenario script
// produce a byte-identical event trace; scenario tests assert platform
// invariants (capacity, fencing, honest restore fallback) at scales and
// timings no single-node live harness can reach.
package sandboxlab

import (
	"container/heap"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/agent-sandbox/platform/domain"
)

// event is one scheduled simulation action. Ordering is total: virtual
// time, then FIFO sequence number — equal timestamps fire in schedule
// order, so a given seed and script produce exactly one interleaving.
type event struct {
	at     time.Duration // offset from simulation start
	seq    uint64
	parent uint64 // seq of the event whose execution scheduled this (0: driver)
	label  string
	fn     func()
}

type eventQueue []event

func (q eventQueue) Len() int { return len(q) }
func (q eventQueue) Less(i, j int) bool {
	if q[i].at != q[j].at {
		return q[i].at < q[j].at
	}
	return q[i].seq < q[j].seq
}
func (q eventQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *eventQueue) Push(x any)   { *q = append(*q, x.(event)) }
func (q *eventQueue) Pop() any {
	old := *q
	n := len(old)
	e := old[n-1]
	*q = old[:n-1]
	return e
}

// Kernel is the discrete-event core: one virtual clock (domain.ManualClock,
// the seam every control-plane component already accepts), one seeded RNG
// for all workload jitter, one priority queue, one trace. The kernel is
// single-threaded by design — determinism comes from the total event order.
type Kernel struct {
	clock   *domain.ManualClock
	elapsed time.Duration
	rng     *rand.Rand
	q       eventQueue
	seq     uint64
	curSeq  uint64 // seq of the event currently executing (0: driver context)
	entries []TraceEntry
	fired   uint64

	// OnTraceEntry, when set, observes every trace entry as it is recorded —
	// the flight recorder's seam (ADR-010 phase 5). Synchronous; keep it cheap.
	OnTraceEntry func(TraceEntry)

	// AfterEach, when set, runs after every fired event — the invariant
	// engine's observation point (ADR-010 phase 3): every scenario event is
	// followed by an event-stream drain and a state snapshot.
	AfterEach func()
}

// NewKernel starts a simulation at virtual time start with the given seed.
func NewKernel(seed int64, start time.Time) *Kernel {
	return &Kernel{
		clock: domain.NewManualClock(start),
		rng:   rand.New(rand.NewSource(seed)),
	}
}

// Clock returns the virtual clock handed to every control-plane component.
func (k *Kernel) Clock() *domain.ManualClock { return k.clock }

// Rand returns the scenario RNG; ALL jitter (arrival spacing, victim
// selection) draws from it so the trace is seed-reproducible.
func (k *Kernel) Rand() *rand.Rand { return k.rng }

// Now returns the elapsed virtual time since simulation start.
func (k *Kernel) Now() time.Duration { return k.elapsed }

// Advance moves virtual time forward (op-latency accounting; ADR-010 §4).
func (k *Kernel) Advance(d time.Duration) {
	k.clock.Advance(d)
	k.elapsed += d
}

// After schedules fn to fire d after the current virtual time.
func (k *Kernel) After(d time.Duration, label string, fn func()) {
	k.At(k.elapsed+d, label, fn)
}

// At schedules fn to fire at the given offset from simulation start.
func (k *Kernel) At(at time.Duration, label string, fn func()) {
	k.seq++
	heap.Push(&k.q, event{at: at, seq: k.seq, parent: k.curSeq, label: label, fn: fn})
}

// Note appends an outcome marker to the trace at the current virtual time
// (e.g. "create sb-17 ok host-3"), making behavior — not just schedule —
// part of the determinism artifact.
func (k *Kernel) Note(label string) {
	k.seq++
	k.record(TraceEntry{Seq: k.seq, At: k.elapsed, Kind: "note", Label: label, Parent: k.curSeq})
}

// TraceEntry is one recorded trace line in structured form (phase 5): the
// v1 text trace renders from these; the v2 flight-recorder artifact
// serializes them with world snapshots.
type TraceEntry struct {
	Seq    uint64
	At     time.Duration
	Kind   string // "fire" (scheduled event) or "note" (outcome/violation)
	Label  string
	Parent uint64 // causal parent: the event whose execution caused this entry
}

func (k *Kernel) record(e TraceEntry) {
	k.entries = append(k.entries, e)
	if k.OnTraceEntry != nil {
		k.OnTraceEntry(e)
	}
}

// Run drains the queue; see RunUntil.
func (k *Kernel) Run() {
	k.RunUntil(time.Duration(1<<63 - 1))
}

// RunUntil fires every event scheduled at or before the given offset and
// stops, leaving later events (e.g. recurring ticks past the scenario
// horizon) queued.
func (k *Kernel) RunUntil(limit time.Duration) {
	for len(k.q) > 0 {
		if k.q[0].at > limit {
			return
		}
		ev := heap.Pop(&k.q).(event)
		if ev.at > k.elapsed {
			k.Advance(ev.at - k.elapsed)
		}
		k.record(TraceEntry{Seq: ev.seq, At: k.elapsed, Kind: "fire", Label: ev.label, Parent: ev.parent})
		k.fired++
		k.curSeq = ev.seq
		ev.fn()
		if k.AfterEach != nil {
			k.AfterEach()
		}
		k.curSeq = 0
	}
}

// Pending reports whether any event is queued (the scenario driver uses it
// to keep the flat-latency sleep path byte-identical when no contention
// wake events exist).
func (k *Kernel) Pending() bool { return len(k.q) > 0 }

// RunUntilCond fires queued events in total order until cond holds or the
// queue empties (ADR-010 phase 6): contention-mode op completions are
// kernel wake events, and the scenario driver joins in-flight host work by
// draining them here. Never called from inside a manager operation —
// completion processing must not re-enter the control plane mid-call.
func (k *Kernel) RunUntilCond(cond func() bool) {
	for !cond() && len(k.q) > 0 {
		ev := heap.Pop(&k.q).(event)
		if ev.at > k.elapsed {
			k.Advance(ev.at - k.elapsed)
		}
		k.record(TraceEntry{Seq: ev.seq, At: k.elapsed, Kind: "fire", Label: ev.label, Parent: ev.parent})
		k.fired++
		k.curSeq = ev.seq
		ev.fn()
		if k.AfterEach != nil {
			k.AfterEach()
		}
		k.curSeq = 0
	}
}

// Trace returns the recorded event trace, one entry per fired event or
// outcome note, in total order (v1 text rendering).
func (k *Kernel) Trace() []string {
	out := make([]string, len(k.entries))
	for i, e := range k.entries {
		out[i] = e.text()
	}
	return out
}

// Entries returns the structured trace (phase 5).
func (k *Kernel) Entries() []TraceEntry { return append([]TraceEntry{}, k.entries...) }

func (e TraceEntry) text() string {
	return fmt.Sprintf("%06d %d %s %s", e.Seq, e.At.Nanoseconds(), e.Kind, e.Label)
}

// TraceBytes renders the trace as a single deterministic byte string.
func (k *Kernel) TraceBytes() []byte { return []byte(strings.Join(k.Trace(), "\n") + "\n") }

// Fired reports how many scheduled events have executed.
func (k *Kernel) Fired() uint64 { return k.fired }
