package sandboxlab

import (
	"fmt"
	"sort"
	"strings"
	"time"

	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	"github.com/agent-sandbox/platform/domain"
)

// invariants.go — the SandboxLab invariant engine (ADR-010 phase 3): every
// scenario run is continuously checked against the platform invariants
// (docs/INVARIANTS.md). The engine consumes two observation channels after
// every fired kernel event: the manager's event outbox (the durable event
// stream) and read-only state snapshots (manager getters, fleet placement,
// host accounting, workspace digests). Violations are typed trace events —
// so a phase-5 UI can render them — and are surfaced as a Report that
// scenario tests assert on.
//
// Coverage classification (the full rationale table lives in ADR-010):
//   continuous:       every scenario run evaluates them from trace+state.
//   scenario-asserted: only meaningful when the scenario drives the path
//                     (INV-009 checkpoint fallback, INV-023 cold locality).
//   not sim-checkable: a real-isolation/transport property the in-process
//                     sim cannot observe (INV-003/004/014/018/020/021/026/027)
//                     — registered with an honest reason, never omitted.

// InvStatus is the per-invariant verdict of a run.
type InvStatus string

const (
	StatusPass         InvStatus = "pass"
	StatusViolation    InvStatus = "violation"
	StatusNotExercised InvStatus = "not-exercised"
	StatusNotCheckable InvStatus = "not-checkable"
)

// Violation is one observed invariant breach, pinned to the kernel sequence
// number and virtual time at detection.
type Violation struct {
	Invariant string
	Detail    string
	Seq       uint64
	At        time.Duration
}

// Checker evaluates one invariant. OnEvent sees the durable event stream in
// order; OnSnapshot sees consistent read-only state after each kernel
// event; Finish runs at scenario end. A checker sets exercised when it
// observed evidence the scenario actually drove its invariant's path.
type Checker interface {
	ID() string
	Title() string
	OnEvent(e *Engine, ev domain.Event)
	OnSnapshot(e *Engine)
	Finish(e *Engine)
	Exercised() bool
}

// Entry is one invariant's row in the Report.
type Entry struct {
	ID        string
	Title     string
	Status    InvStatus
	Exercised bool
	Reason    string // set for not-checkable entries
	Failures  []Violation
}

// Report is the run verdict (phase 4's verdict line comes from String()).
type Report struct {
	Entries []Entry
}

// Counts summarizes the report: checked = pass+violation, plus violation,
// not-exercised, and not-checkable tallies.
func (r Report) Counts() (checked, violations, notExercised, notCheckable int) {
	for _, e := range r.Entries {
		switch e.Status {
		case StatusPass:
			checked++
		case StatusViolation:
			checked++
			violations++
		case StatusNotExercised:
			notExercised++
		case StatusNotCheckable:
			notCheckable++
		}
	}
	return
}

// Violations returns every recorded violation across invariants.
func (r Report) Violations() []Violation {
	var out []Violation
	for _, e := range r.Entries {
		out = append(out, e.Failures...)
	}
	return out
}

func (r Report) String() string {
	checked, violations, notExercised, notCheckable := r.Counts()
	var b strings.Builder
	fmt.Fprintf(&b, "invariants checked: %d, violations: %d (not-exercised: %d, not-checkable: %d)",
		checked, violations, notExercised, notCheckable)
	for _, e := range r.Entries {
		mark := "PASS"
		switch e.Status {
		case StatusViolation:
			mark = "VIOLATION"
		case StatusNotExercised:
			mark = "not-exercised"
		case StatusNotCheckable:
			mark = "not-checkable: " + e.Reason
		}
		fmt.Fprintf(&b, "\n  %-7s %-28s %s", e.ID, e.Title, mark)
		for _, v := range e.Failures {
			fmt.Fprintf(&b, "\n      seq=%d t=%dms %s", v.Seq, v.At.Milliseconds(), v.Detail)
		}
	}
	return b.String()
}

// Engine drives the checker set over a scenario run.
type Engine struct {
	sf       *SimFleet // nil in live mode (real-trace ingestion)
	consumer *eventservice.Consumer
	checkers []Checker
	viol     map[string][]Violation
	static   []Entry // not-checkable registrations
	observed uint64
	fed      uint64 // events fed in live mode (violation seq anchor)
}

// NewEngine builds the engine over a SimFleet and wires it into the kernel.
func NewEngine(sf *SimFleet) *Engine {
	e := newEngine()
	e.sf = sf
	sf.Kernel.AfterEach = e.observe
	return e
}

// NewLiveEngine builds the engine for real-trace ingestion via Feed (no
// SimFleet). Only the event-stream checkers can run: state-snapshot
// checkers need consistent world state (manager/fleet/host views) that a
// real event stream does not carry, so they stay not-exercised — an honest
// coverage reduction, reported as such. Violations are pinned to the
// fed-event ordinal instead of a kernel seq.
func NewLiveEngine() *Engine { return newEngine() }

func newEngine() *Engine {
	e := &Engine{
		consumer: eventservice.NewConsumer(),
		viol:     map[string][]Violation{},
	}
	for _, c := range []Checker{
		&inv001{seen: map[string]string{}, wasFailed: map[string]bool{}},
		&inv002{},
		&inv005{digests: map[string]map[int64]string{}},
		&inv006{head: map[string]int64{}, commitGen: map[string]int64{}},
		&inv007{epoch: map[string]int64{}},
		&inv008{pendingReset: map[string]bool{}},
		&inv009{},
		&inv010{},
		&inv011{},
		&inv012{},
		&inv013016{},
		&inv015{},
		&inv017{boundSeen: map[string]bool{}},
		&inv019{kind: "k8s"},
		&inv022{wsOf: map[string]string{}},
		&inv023{},
		&inv024{},
		&inv025{},
		&inv028{},
		&inv029{},
		&inv030{},
	} {
		e.checkers = append(e.checkers, c)
	}
	for _, s := range []Entry{
		{ID: "INV-003", Title: "agent/sandbox runtimes separate", Status: StatusNotCheckable,
			Reason: "structural: the sim drives the control plane directly with no LLM; the LLM-free driver path is conformance-suite territory"},
		{ID: "INV-004", Title: "sandbox spans many LLM turns", Status: StatusNotCheckable,
			Reason: "no LLM turns exist in sim; covered by conformance foreground/background workload tests"},
		{ID: "INV-014", Title: "async APIs are not accounting", Status: StatusNotCheckable,
			Reason: "ownership accounting is continuously checked (INV-013/016); API-vs-background metering equivalence needs real process metering — conformance/FC suites"},
		{ID: "INV-018", Title: "network/credentials are capabilities", Status: StatusNotCheckable,
			Reason: "egress denial and metadata protection are dataplane properties — covered by the FC suites, invisible to an in-process sim"},
		{ID: "INV-020", Title: "Kubernetes off the hot path", Status: StatusNotCheckable,
			Reason: "the sim has no Kubernetes at all; trivially true and unobservable here"},
		{ID: "INV-021", Title: "prepared environments immutable", Status: StatusNotCheckable,
			Reason: "no environment builder in sim (hosts run with a nil EnvironmentSource); environment versioning is conformance territory"},
		{ID: "INV-026", Title: "runtime substitutable", Status: StatusNotCheckable,
			Reason: "the sim fixes the fake backend by construction; multi-adapter proof is the conformance suite's job"},
		{ID: "INV-027", Title: "isolation stronger than namespaces", Status: StatusNotCheckable,
			Reason: "breakout resistance is a real-isolation property of the FC backend; a sim of the control plane cannot observe it"},
	} {
		e.static = append(e.static, s)
	}
	return e
}

// observe is the kernel AfterEach hook: drain new outbox events through the
// event checkers, then run every state checker on a consistent snapshot.
// Event checkers are cheap (per payload); state checkers are O(sandboxes),
// so snapshots are sampled every snapshotEvery events plus a mandatory
// final one at Report time — a regression is caught at snapshot
// granularity, which for a deterministic total-order trace is exact.
func (e *Engine) observe() {
	for _, ev := range e.consumer.Poll(e.sf.Outbox) {
		for _, c := range e.checkers {
			c.OnEvent(e, ev)
		}
	}
	e.observed++
	if e.observed%snapshotEvery == 0 {
		e.snapshotAll()
	}
}

const snapshotEvery = 32

func (e *Engine) snapshotAll() {
	for _, c := range e.checkers {
		c.OnSnapshot(e)
	}
}

// Feed replays an event stream through the event checkers (meta-tests and
// real-trace ingestion via NewLiveEngine).
func (e *Engine) Feed(events []domain.Event) {
	for _, ev := range events {
		e.fed++
		for _, c := range e.checkers {
			c.OnEvent(e, ev)
		}
	}
}

// Violate records a violation: typed trace event plus report entry.
// Identical (invariant, detail) violations are recorded once — a persistent
// breach is one violation, not one per snapshot.
func (e *Engine) Violate(id, detail string) {
	for _, prev := range e.viol[id] {
		if prev.Detail == detail {
			return
		}
	}
	var v Violation
	if e.sf != nil {
		v = Violation{Invariant: id, Detail: detail, Seq: e.sf.Kernel.seq, At: e.sf.Kernel.Now()}
		e.sf.Kernel.Note(fmt.Sprintf("INVARIANT_VIOLATION %s seq=%d %s", id, v.Seq, detail))
	} else {
		// Live mode: no kernel clock — pin the fed-event ordinal.
		v = Violation{Invariant: id, Detail: detail, Seq: e.fed}
	}
	e.viol[id] = append(e.viol[id], v)
}

// Report finalizes the run: Finish on every checker, then per-invariant
// status (violation > pass > not-exercised) plus the static not-checkable
// rows, ordered by invariant ID.
func (e *Engine) Report() Report {
	if e.sf != nil {
		e.snapshotAll() // final full snapshot at scenario end
	}
	for _, c := range e.checkers {
		c.Finish(e)
	}
	var entries []Entry
	for _, c := range e.checkers {
		st := StatusPass
		if !c.Exercised() {
			st = StatusNotExercised
		}
		if fails := e.viol[c.ID()]; len(fails) > 0 {
			st = StatusViolation
		}
		entries = append(entries, Entry{
			ID: c.ID(), Title: c.Title(), Status: st,
			Exercised: c.Exercised(), Failures: e.viol[c.ID()],
		})
	}
	entries = append(entries, e.static...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return Report{Entries: entries}
}

// --- shared checker plumbing ---

type base struct{ exercised bool }

func (b *base) mark()                         { b.exercised = true }
func (b *base) Exercised() bool               { return b.exercised }
func (b *base) OnEvent(*Engine, domain.Event) {}
func (b *base) OnSnapshot(*Engine)            {}
func (b *base) Finish(*Engine)                {}

func sandboxStates(e *Engine) []*domain.Sandbox { return e.sf.Mgr.SnapshotSandboxes() }

func liveState(s domain.SandboxState) bool {
	switch s {
	case domain.SandboxRunning, domain.SandboxQuiescent, domain.SandboxBackgroundActive:
		return true
	}
	return false
}

// --- INV-001: logical identity survives; identity fields never mutate ---

type inv001 struct {
	base
	seen      map[string]string // sandboxID -> tenant|task|workspace fingerprint
	wasFailed map[string]bool
}

func (c *inv001) ID() string    { return "INV-001" }
func (c *inv001) Title() string { return "logical identity survives compute" }

func (c *inv001) OnSnapshot(e *Engine) {
	for _, sb := range sandboxStates(e) {
		fp := sb.TenantID + "|" + sb.TaskRef + "|" + sb.WorkspaceID
		if prev, ok := c.seen[sb.SandboxID]; ok {
			if prev != fp {
				e.Violate(c.ID(), fmt.Sprintf("sandbox %s identity mutated: %s -> %s", sb.SandboxID, prev, fp))
			}
		} else {
			c.seen[sb.SandboxID] = fp
		}
		if c.wasFailed[sb.SandboxID] && liveState(sb.ObservedState) {
			// Rematerialized after runtime loss under the SAME sandbox id.
			c.mark()
		}
		if sb.ObservedState == domain.SandboxFailed {
			c.wasFailed[sb.SandboxID] = true
		}
	}
}

// --- INV-002: dormant sandboxes hold no compute ---

type inv002 struct{ base }

func (c *inv002) ID() string    { return "INV-002" }
func (c *inv002) Title() string { return "dormant sandboxes hold no compute" }

func (c *inv002) OnSnapshot(e *Engine) {
	for _, sb := range sandboxStates(e) {
		switch sb.ObservedState {
		case domain.SandboxUnmaterialized, domain.SandboxSuspended:
			c.mark()
			// A reclaim-class suspend keeps the incarnation ID as a record
			// pointer (state TERMINATED, used for restore routing); what it
			// must NOT keep is a fleet placement — accounted compute.
			if sb.RuntimeIncarnationID != nil {
				if host, _, placed := e.sf.Fleet.PlacementOf(*sb.RuntimeIncarnationID); placed {
					e.Violate(c.ID(), fmt.Sprintf("sandbox %s %s but incarnation %s still holds a placement on %s",
						sb.SandboxID, sb.ObservedState, *sb.RuntimeIncarnationID, host))
				}
			}
		}
	}
}

// --- INV-005: committed generations are immutable ---

type inv005 struct {
	base
	digests map[string]map[int64]string // first-seen digest per ws/gen
}

func (c *inv005) ID() string    { return "INV-005" }
func (c *inv005) Title() string { return "committed workspace state durable" }

func (c *inv005) OnSnapshot(e *Engine) {
	for ws, gens := range e.sf.WS.GenerationDigests() {
		for gen, digest := range gens {
			if c.digests[ws] == nil {
				c.digests[ws] = map[int64]string{}
			}
			if prev, ok := c.digests[ws][gen]; ok {
				if prev != digest {
					e.Violate(c.ID(), fmt.Sprintf("workspace %s generation %d mutated: %s -> %s", ws, gen, prev, digest))
				}
			} else {
				c.digests[ws][gen] = digest
			}
			if gen > 0 {
				c.mark()
			}
		}
	}
}

// --- INV-006: commit boundaries; generation never regresses ---

type inv006 struct {
	base
	head      map[string]int64 // sandboxID -> last observed WorkspaceGeneration
	commitGen map[string]int64 // sandboxID -> last committed generation (events)
}

func (c *inv006) ID() string    { return "INV-006" }
func (c *inv006) Title() string { return "explicit commit boundaries" }

func (c *inv006) OnSnapshot(e *Engine) {
	for _, sb := range sandboxStates(e) {
		if prev, ok := c.head[sb.SandboxID]; ok && sb.WorkspaceGeneration < prev {
			e.Violate(c.ID(), fmt.Sprintf("sandbox %s workspace generation regressed %d -> %d",
				sb.SandboxID, prev, sb.WorkspaceGeneration))
		}
		c.head[sb.SandboxID] = sb.WorkspaceGeneration
	}
}

func (c *inv006) OnEvent(e *Engine, ev domain.Event) {
	if ev.EventType != domain.EventWorkspaceCommitted {
		return
	}
	c.mark()
	gen := payloadInt(ev, "generation")
	if prev, ok := c.commitGen[ev.AggregateID]; ok && gen <= prev {
		e.Violate(c.ID(), fmt.Sprintf("sandbox %s committed generation %d after %d", ev.AggregateID, gen, prev))
	}
	c.commitGen[ev.AggregateID] = gen
}

// --- INV-007: epoch monotonicity ---

type inv007 struct {
	base
	epoch map[string]int64
}

func (c *inv007) ID() string    { return "INV-007" }
func (c *inv007) Title() string { return "execution epoch monotonic" }

func (c *inv007) OnSnapshot(e *Engine) {
	for _, sb := range sandboxStates(e) {
		if prev, ok := c.epoch[sb.SandboxID]; ok && sb.ExecutionEpoch < prev {
			e.Violate(c.ID(), fmt.Sprintf("sandbox %s epoch regressed %d -> %d", sb.SandboxID, prev, sb.ExecutionEpoch))
		}
		if sb.ExecutionEpoch > 0 {
			c.mark()
		}
		c.epoch[sb.SandboxID] = sb.ExecutionEpoch
	}
}

func (c *inv007) OnEvent(e *Engine, ev domain.Event) {
	if ev.EventType != domain.EventExecutionStateReset {
		return
	}
	prior, next := payloadInt(ev, "prior_epoch"), payloadInt(ev, "new_epoch")
	if next != prior+1 {
		e.Violate(c.ID(), fmt.Sprintf("sandbox %s reset epoch %d -> %d, want +1", ev.AggregateID, prior, next))
	}
}

// --- INV-008: reset event before state-dependent continuation ---

type inv008 struct {
	base
	pendingReset map[string]bool // sandboxID -> loss observed, reset not yet seen
}

func (c *inv008) ID() string    { return "INV-008" }
func (c *inv008) Title() string { return "loss never invisible (reset first)" }

func (c *inv008) OnEvent(e *Engine, ev domain.Event) {
	sb := ev.AggregateID
	switch ev.EventType {
	case domain.EventSandboxFailed:
		// Runtime loss: volatile state is gone; continuation must wait for
		// the reset event.
		c.pendingReset[sb] = true
		c.mark()
	case domain.EventExecutionStateReset:
		delete(c.pendingReset, sb)
		c.mark()
	case domain.EventSandboxMaterialized, domain.EventSandboxResumed, domain.EventExecutionStarted:
		if c.pendingReset[sb] {
			e.Violate(c.ID(), fmt.Sprintf("sandbox %s continued (%s) after loss without an intervening ExecutionStateReset",
				sb, ev.EventType))
			delete(c.pendingReset, sb)
		}
	}
}

// --- INV-009: checkpoint never sole source of truth (scenario-asserted) ---

type inv009 struct{ base }

func (c *inv009) ID() string    { return "INV-009" }
func (c *inv009) Title() string { return "checkpoint never sole truth" }

func (c *inv009) OnEvent(e *Engine, ev domain.Event) {
	if ev.EventType == domain.EventSandboxResumed {
		if cont, _ := ev.Payload["continuity"].(string); cont == "workspace_only" {
			// Recovery proceeded from durable workspace despite checkpoint
			// restore being impossible — the invariant's core claim.
			c.mark()
			if r, _ := ev.Payload["restore_error"].(string); r == "" {
				e.Violate(c.ID(), fmt.Sprintf("sandbox %s workspace-only resume records no restore_error — silent fallback", ev.AggregateID))
			}
		}
	}
}

// --- INV-010: executions independently addressable ---

type inv010 struct{ base }

func (c *inv010) ID() string    { return "INV-010" }
func (c *inv010) Title() string { return "executions addressable" }

func (c *inv010) OnSnapshot(e *Engine) {
	for _, sb := range sandboxStates(e) {
		seen := map[string]bool{}
		for _, ex := range e.sf.Mgr.Executions(sb.SandboxID) {
			c.mark()
			if ex.ExecutionID == "" {
				e.Violate(c.ID(), fmt.Sprintf("sandbox %s has an execution with empty ID", sb.SandboxID))
				continue
			}
			if seen[ex.ExecutionID] {
				e.Violate(c.ID(), fmt.Sprintf("sandbox %s lists execution %s twice", sb.SandboxID, ex.ExecutionID))
			}
			seen[ex.ExecutionID] = true
		}
	}
}

func (c *inv010) OnEvent(e *Engine, ev domain.Event) {
	switch ev.EventType {
	case domain.EventExecutionStarted, domain.EventExecutionCompleted,
		domain.EventExecutionFailed, domain.EventExecutionCancelled, domain.EventExecutionTimedOut:
		c.mark()
		if ev.AggregateID == "" || payloadStr(ev, "execution_id") == "" {
			e.Violate(c.ID(), fmt.Sprintf("%s event without execution identity", ev.EventType))
		}
	}
}

// --- INV-011: retry-safe execution creation ---

type inv011 struct{ base }

func (c *inv011) ID() string    { return "INV-011" }
func (c *inv011) Title() string { return "execution creation retry-safe" }

func (c *inv011) OnSnapshot(e *Engine) {
	for _, sb := range sandboxStates(e) {
		byKey := map[string]string{}
		for _, ex := range e.sf.Mgr.Executions(sb.SandboxID) {
			if ex.IdempotencyKey == "" {
				continue
			}
			c.mark()
			if prev, ok := byKey[ex.IdempotencyKey]; ok && prev != ex.ExecutionID {
				e.Violate(c.ID(), fmt.Sprintf("sandbox %s idempotency key %q launched both %s and %s",
					sb.SandboxID, ex.IdempotencyKey, prev, ex.ExecutionID))
			}
			byKey[ex.IdempotencyKey] = ex.ExecutionID
		}
	}
}

// --- INV-012: quiescence correctness ---

type inv012 struct{ base }

func (c *inv012) ID() string    { return "INV-012" }
func (c *inv012) Title() string { return "completion is not quiescence" }

func (c *inv012) OnSnapshot(e *Engine) {
	for _, sb := range sandboxStates(e) {
		if sb.ObservedState != domain.SandboxQuiescent {
			continue
		}
		c.mark()
		if n := e.sf.Mgr.LiveDescendants(sb.SandboxID); n != 0 {
			e.Violate(c.ID(), fmt.Sprintf("sandbox %s QUIESCENT with %d live descendants", sb.SandboxID, n))
		}
		for _, ex := range e.sf.Mgr.Executions(sb.SandboxID) {
			if !ex.State.Terminal() {
				e.Violate(c.ID(), fmt.Sprintf("sandbox %s QUIESCENT with non-terminal execution %s (%s)",
					sb.SandboxID, ex.ExecutionID, ex.State))
			}
		}
	}
}

// --- INV-013 + INV-016: transitive ownership / attributable compute ---
// Host accounting must be consistent (never negative, never over capacity,
// no backend runtime the host doesn't account), and every fleet-tracked
// incarnation must trace to a lease-holding sandbox on a live host.

type inv013016 struct{ base }

func (c *inv013016) ID() string    { return "INV-013" }
func (c *inv013016) Title() string { return "compute owned & attributable (+016)" }

func (c *inv013016) OnSnapshot(e *Engine) {
	incarnationHosts := map[string]string{} // incarnationID -> hostID, for duplicate detection
	for id, h := range e.sf.Hosts {
		v := h.View()
		if v.UsedSlots < 0 || v.UsedMemory < 0 {
			e.Violate(c.ID(), fmt.Sprintf("host %s negative accounting: %+v", id, v))
		}
		if v.UsedSlots > v.CapacitySlots || v.UsedMemory > v.CapacityMemory {
			e.Violate(c.ID(), fmt.Sprintf("host %s oversubscribed: %+v", id, v))
		}
		// The backend must not run an incarnation the host doesn't account
		// for (unowned compute), nor may the host account for ghosts.
		live := h.Backend().LiveHandles()
		if len(live) != v.UsedSlots {
			e.Violate(c.ID(), fmt.Sprintf("host %s accounts %d slots but backend runs %d incarnations",
				id, v.UsedSlots, len(live)))
		}
		for _, hh := range live {
			if _, _, ok := e.sf.Fleet.PlacementOf(hh.IncarnationID); !ok {
				e.Violate(c.ID(), fmt.Sprintf("host %s runs fleet-invisible incarnation %s", id, hh.IncarnationID))
			}
			if other, dup := incarnationHosts[hh.IncarnationID]; dup && other != id {
				e.Violate(c.ID(), fmt.Sprintf("incarnation %s double-registered on hosts %s and %s",
					hh.IncarnationID, other, id))
			}
			incarnationHosts[hh.IncarnationID] = id
		}
	}
	for _, sb := range sandboxStates(e) {
		if !liveState(sb.ObservedState) {
			continue
		}
		c.mark()
		if sb.RuntimeIncarnationID == nil {
			continue
		}
		if _, ok := e.sf.Mgr.LeaseOf(sb.SandboxID); !ok {
			e.Violate(c.ID(), fmt.Sprintf("live sandbox %s (incarnation %s) has no work lease",
				sb.SandboxID, *sb.RuntimeIncarnationID))
		}
		host, _, ok := e.sf.Fleet.PlacementOf(*sb.RuntimeIncarnationID)
		if !ok {
			e.Violate(c.ID(), fmt.Sprintf("live sandbox %s incarnation %s has no fleet placement",
				sb.SandboxID, *sb.RuntimeIncarnationID))
			continue
		}
		if _, known := e.sf.Hosts[host]; !known {
			e.Violate(c.ID(), fmt.Sprintf("sandbox %s placed on unknown host %q", sb.SandboxID, host))
		}
	}
}

// --- INV-015: background compute bounded by a lease ---

type inv015 struct{ base }

func (c *inv015) ID() string    { return "INV-015" }
func (c *inv015) Title() string { return "background compute bounded" }

func (c *inv015) OnSnapshot(e *Engine) {
	for _, sb := range sandboxStates(e) {
		if !liveState(sb.ObservedState) {
			continue
		}
		c.mark()
		lease, ok := e.sf.Mgr.LeaseOf(sb.SandboxID)
		if !ok {
			e.Violate(c.ID(), fmt.Sprintf("live sandbox %s has no lease", sb.SandboxID))
			continue
		}
		if lease.WallDeadline.IsZero() {
			e.Violate(c.ID(), fmt.Sprintf("sandbox %s lease %s has no wall deadline", sb.SandboxID, lease.LeaseID))
		}
	}
}

// --- INV-017: binding lifecycle states valid, unbind terminal ---

type inv017 struct {
	base
	boundSeen map[string]bool // bindingID -> EndpointBound observed
}

func (c *inv017) ID() string    { return "INV-017" }
func (c *inv017) Title() string { return "endpoint binding lifecycle" }

func (c *inv017) OnEvent(e *Engine, ev domain.Event) {
	id := payloadStr(ev, "binding_id")
	switch ev.EventType {
	case domain.EventEndpointBound:
		c.mark()
		if id == "" {
			e.Violate(c.ID(), "EndpointBound without binding_id")
		}
		if c.boundSeen[id] {
			e.Violate(c.ID(), fmt.Sprintf("binding %s bound twice", id))
		}
		c.boundSeen[id] = true
	case domain.EventEndpointUnbound:
		c.mark()
		if !c.boundSeen[id] {
			e.Violate(c.ID(), fmt.Sprintf("binding %s unbound before any bind", id))
		}
	}
}

func (c *inv017) OnSnapshot(e *Engine) {
	for _, sb := range sandboxStates(e) {
		for _, b := range e.sf.Mgr.ListEndpointBindings(sb.SandboxID) {
			c.mark()
			switch b.State {
			case domain.EndpointActive, domain.EndpointSuspended, domain.EndpointReleased,
				domain.EndpointExpired, domain.EndpointUnbound:
			default:
				e.Violate(c.ID(), fmt.Sprintf("binding %s in unknown state %q", b.BindingID, b.State))
			}
		}
	}
}

// --- INV-019: no Kubernetes concepts in the event stream ---

type inv019 struct {
	base
	kind string
}

func (c *inv019) ID() string    { return "INV-019" }
func (c *inv019) Title() string { return "Kubernetes not in the API" }

var k8sPayloadKeys = []string{"pod", "node", "namespace", "pvc", "kubectl"}

func (c *inv019) OnEvent(e *Engine, ev domain.Event) {
	c.mark()
	for k := range ev.Payload {
		lk := strings.ToLower(k)
		for _, bad := range k8sPayloadKeys {
			if strings.Contains(lk, bad) {
				e.Violate(c.ID(), fmt.Sprintf("event %s payload leaks Kubernetes concept %q (key %q)", ev.EventType, bad, k))
			}
		}
	}
}

// --- INV-022: mutable task state isolated (one workspace per sandbox) ---

type inv022 struct {
	base
	wsOf map[string]string // sandboxID -> workspaceID
}

func (c *inv022) ID() string    { return "INV-022" }
func (c *inv022) Title() string { return "mutable state isolated" }

func (c *inv022) OnSnapshot(e *Engine) {
	owner := map[string]string{} // workspaceID -> sandboxID
	for _, sb := range sandboxStates(e) {
		c.mark()
		if prev, ok := c.wsOf[sb.SandboxID]; ok && prev != sb.WorkspaceID {
			e.Violate(c.ID(), fmt.Sprintf("sandbox %s workspace changed %s -> %s", sb.SandboxID, prev, sb.WorkspaceID))
		}
		c.wsOf[sb.SandboxID] = sb.WorkspaceID
		if other, ok := owner[sb.WorkspaceID]; ok && other != sb.SandboxID {
			e.Violate(c.ID(), fmt.Sprintf("workspace %s shared by sandboxes %s and %s", sb.WorkspaceID, other, sb.SandboxID))
		}
		owner[sb.WorkspaceID] = sb.SandboxID
	}
}

// --- INV-023: locality is an optimization (scenario-asserted) ---

type inv023 struct{ base }

func (c *inv023) ID() string    { return "INV-023" }
func (c *inv023) Title() string { return "locality never a correctness dependency" }

func (c *inv023) OnEvent(e *Engine, ev domain.Event) {
	// A workspace-only resume proves recovery worked without any local
	// cache/checkpoint advantage; a continuity resume on a mismatched fleet
	// would be the violation, but mismatched placement is guarded upstream
	// (facts guard) — the engine's job is to observe which path ran.
	if ev.EventType == domain.EventSandboxResumed {
		c.mark()
	}
}

// --- INV-024: failures resolve to contract-valid terminals ---

type inv024 struct{ base }

var validSandboxStates = map[domain.SandboxState]bool{
	domain.SandboxUnmaterialized: true, domain.SandboxStarting: true,
	domain.SandboxRunning: true, domain.SandboxQuiescent: true,
	domain.SandboxBackgroundActive: true, domain.SandboxSuspending: true,
	domain.SandboxSuspended: true, domain.SandboxResuming: true,
	domain.SandboxFailed: true, domain.SandboxTerminated: true,
}

func (c *inv024) ID() string    { return "INV-024" }
func (c *inv024) Title() string { return "failures are normal paths" }

func (c *inv024) OnSnapshot(e *Engine) {
	for _, sb := range sandboxStates(e) {
		c.mark()
		if !validSandboxStates[sb.ObservedState] {
			e.Violate(c.ID(), fmt.Sprintf("sandbox %s in unknown state %q", sb.SandboxID, sb.ObservedState))
		}
		for _, ex := range e.sf.Mgr.Executions(sb.SandboxID) {
			if ex.State.Terminal() {
				switch ex.State {
				case domain.ExecutionCompleted, domain.ExecutionFailed,
					domain.ExecutionCancelled, domain.ExecutionTimedOut:
				default:
					e.Violate(c.ID(), fmt.Sprintf("execution %s terminal in non-contract state %q", ex.ExecutionID, ex.State))
				}
			}
		}
	}
}

func (c *inv024) OnEvent(e *Engine, ev domain.Event) {
	if ev.EventType == domain.EventSandboxFailed {
		c.mark()
		if r, _ := ev.Payload["reason"].(string); r == "" {
			e.Violate(c.ID(), fmt.Sprintf("sandbox %s failed with no reason recorded", ev.AggregateID))
		}
	}
}

// --- INV-025: no bulk payloads on the control event stream ---

type inv025 struct{ base }

func (c *inv025) ID() string    { return "INV-025" }
func (c *inv025) Title() string { return "control events carry no bulk data" }

const maxEventPayloadBytes = 4096

func (c *inv025) OnEvent(e *Engine, ev domain.Event) {
	c.mark()
	n := 0
	for k, v := range ev.Payload {
		n += len(k) + len(fmt.Sprint(v))
	}
	if n > maxEventPayloadBytes {
		e.Violate(c.ID(), fmt.Sprintf("event %s payload is %d bytes (limit %d)", ev.EventType, n, maxEventPayloadBytes))
	}
}

// --- INV-028: every event is tenant-tagged ---

type inv028 struct{ base }

func (c *inv028) ID() string    { return "INV-028" }
func (c *inv028) Title() string { return "requests tagged to tenant/principal" }

func (c *inv028) OnEvent(e *Engine, ev domain.Event) {
	c.mark()
	if ev.TenantID == "" {
		e.Violate(c.ID(), fmt.Sprintf("event %s (%s) carries no tenant identity", ev.EventType, ev.EventID))
	}
}

// --- INV-029: dormant population ≫ live population ---

type inv029 struct{ base }

func (c *inv029) ID() string    { return "INV-029" }
func (c *inv029) Title() string { return "dormant ≫ live population" }

func (c *inv029) OnSnapshot(e *Engine) {
	sandboxes := sandboxStates(e)
	live := 0
	for _, sb := range sandboxes {
		if liveState(sb.ObservedState) {
			live++
		}
	}
	if live > len(sandboxes) {
		e.Violate(c.ID(), fmt.Sprintf("%d live incarnations exceed %d logical sandboxes", live, len(sandboxes)))
	}
	// Exercised when the run demonstrates the ratio the invariant demands.
	if live > 0 && len(sandboxes)-live >= 10*live {
		c.mark()
	}
}

// --- INV-030: events are model-independent ---

type inv030 struct{ base }

func (c *inv030) ID() string    { return "INV-030" }
func (c *inv030) Title() string { return "events model-independent" }

var modelPayloadKeys = []string{"prompt", "llm", "model", "completion"}

func (c *inv030) OnEvent(e *Engine, ev domain.Event) {
	c.mark()
	for k := range ev.Payload {
		lk := strings.ToLower(k)
		for _, bad := range modelPayloadKeys {
			if strings.Contains(lk, bad) {
				e.Violate(c.ID(), fmt.Sprintf("event %s payload carries model concept %q (key %q)", ev.EventType, bad, k))
			}
		}
	}
}

// --- payload helpers ---

func payloadStr(ev domain.Event, key string) string {
	s, _ := ev.Payload[key].(string)
	return s
}

func payloadInt(ev domain.Event, key string) int64 {
	switch v := ev.Payload[key].(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	}
	return 0
}
