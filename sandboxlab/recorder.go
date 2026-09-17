package sandboxlab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// recorder.go — the enriched v2 trace recorder (ADR-010 phase 5). The v1
// text simtrace stays byte-identical for CI diffs; the v2 artifact is JSONL
// (`.simtrace.jsonl`) consumed by the replay UI:
//
//	{"type":"header","format":"sandboxlab-trace-jsonl v2","scenario":..,"seed":..}
//	{"type":"event","seq":..,"t_ns":..,"kind":"fire|note","label":"..","parent":..,
//	  "world":{hosts:[...],sandboxes:[...]},             — present per snapshot policy
//	  "violation":{"invariant":"INV-xxx","detail":".."}} — only on INVARIANT_VIOLATION notes
//	{"type":"report","world":{...},"entries":[{id,title,status,...}]} — final record
//
// World snapshots are the expensive part: a full copy is O(sandboxes), so
// per-event snapshots are only affordable for small scenarios. Snapshots
// are taken at kernel AfterEach points (after each fired event / driver
// step — never mid-operation, where manager locks are held and the world
// is mid-transition) and attached to the last trace entry of that batch.
// While the sandbox population is ≤ snapshotExactBudget every batch
// carries a snapshot (exact replay); beyond it the gap widens to
// ceil(S/32) batches, which bounds the artifact to ≈32 rows per trace
// entry regardless of population. The UI binary-searches snapshots and
// renders the world as of the latest snapshot ≤ the scrubbed seq — exact
// for small scenarios, bounded-coarse at scale.

const snapshotExactBudget = 512

// snapshotRowsPerEntry bounds total serialized world rows to ~32× the
// trace entry count once the population exceeds snapshotExactBudget.
const snapshotRowsPerEntry = 32

// HostSnap is one host's observable state at a point in the trace.
type HostSnap struct {
	ID           string   `json:"id"`
	UsedSlots    int      `json:"used_slots"`
	CapSlots     int      `json:"cap_slots"`
	UsedMem      int64    `json:"used_mem"`
	CapMem       int64    `json:"cap_mem"`
	Down         bool     `json:"down"`
	Incarnations []string `json:"incarnations,omitempty"`
}

// BindingSnap is one endpoint binding's observable state.
type BindingSnap struct {
	Name  string `json:"name"`
	State string `json:"state"`
	Port  int    `json:"port"`
}

// SandboxSnap is one sandbox's observable state at a point in the trace.
type SandboxSnap struct {
	ID          string        `json:"id"`
	Label       string        `json:"label"`
	State       string        `json:"state"`
	Epoch       int64         `json:"epoch"`
	WSGen       int64         `json:"ws_gen"`
	WorkspaceID string        `json:"ws"`
	Host        string        `json:"host,omitempty"`
	Fence       int64         `json:"fence,omitempty"`
	Incarnation string        `json:"incarnation,omitempty"`
	Checkpoint  string        `json:"checkpoint,omitempty"`
	Lease       bool          `json:"lease"`
	Bindings    []BindingSnap `json:"bindings,omitempty"`
}

// WorldSnap is a consistent read-only view of the whole simulated world.
type WorldSnap struct {
	Hosts     []HostSnap    `json:"hosts"`
	Sandboxes []SandboxSnap `json:"sandboxes"`
}

// ViolationNote is the parsed form of an INVARIANT_VIOLATION trace note.
type ViolationNote struct {
	Invariant string `json:"invariant"`
	Detail    string `json:"detail"`
}

// traceHeader is the first JSONL record.
type traceHeader struct {
	Type     string `json:"type"`
	Format   string `json:"format"`
	Scenario string `json:"scenario"`
	Seed     int64  `json:"seed"`
}

// eventRecord is one JSONL event record.
type eventRecord struct {
	Type      string         `json:"type"`
	Seq       uint64         `json:"seq"`
	Tns       int64          `json:"t_ns"`
	Kind      string         `json:"kind"`
	Label     string         `json:"label"`
	Parent    uint64         `json:"parent"`
	World     *WorldSnap     `json:"world,omitempty"`
	Violation *ViolationNote `json:"violation,omitempty"`
}

// reportEntry mirrors invariants.Entry with JSON tags.
type reportEntry struct {
	ID        string          `json:"id"`
	Title     string          `json:"title"`
	Status    InvStatus       `json:"status"`
	Exercised bool            `json:"exercised"`
	Reason    string          `json:"reason,omitempty"`
	Failures  []reportFailure `json:"failures,omitempty"`
}

type reportFailure struct {
	Invariant string `json:"invariant"`
	Detail    string `json:"detail"`
	Seq       uint64 `json:"seq"`
	AtNs      int64  `json:"at_ns"`
}

// reportRecord is the final JSONL record: the invariant report plus the
// world snapshot at end-of-run (the UI treats it as the snapshot at the
// last event's seq).
type reportRecord struct {
	Type    string        `json:"type"`
	World   *WorldSnap    `json:"world"`
	Entries []reportEntry `json:"entries"`
}

// TraceV2Format identifies the JSONL artifact in its header record.
const TraceV2Format = "sandboxlab-trace-jsonl v2"

// SnapshotWorld captures a consistent read-only view of the simulated
// world. The labeler maps sandbox IDs to scenario labels (nil: labels equal
// IDs). All map-derived slices are sorted, so equal worlds serialize to
// equal bytes.
func SnapshotWorld(sf *SimFleet, labeler func(string) string) *WorldSnap {
	w := &WorldSnap{}
	hostIDs := make([]string, 0, len(sf.Hosts))
	for id := range sf.Hosts {
		hostIDs = append(hostIDs, id)
	}
	sort.Strings(hostIDs)
	for _, id := range hostIDs {
		h := sf.Hosts[id]
		v := h.View()
		incs := h.IncarnationIDs()
		sort.Strings(incs)
		w.Hosts = append(w.Hosts, HostSnap{
			ID: id, UsedSlots: v.UsedSlots, CapSlots: v.CapacitySlots,
			UsedMem: v.UsedMemory, CapMem: v.CapacityMemory,
			Down:         sf.Fleet.HostDown(id),
			Incarnations: incs,
		})
	}
	sandboxes := sf.Mgr.SnapshotSandboxes()
	sort.Slice(sandboxes, func(i, j int) bool { return sandboxes[i].SandboxID < sandboxes[j].SandboxID })
	for _, sb := range sandboxes {
		snap := SandboxSnap{
			ID: sb.SandboxID, State: string(sb.ObservedState),
			Epoch: sb.ExecutionEpoch, WSGen: sb.WorkspaceGeneration,
			WorkspaceID: sb.WorkspaceID,
		}
		snap.Label = sb.SandboxID
		if labeler != nil {
			snap.Label = labeler(sb.SandboxID)
		}
		if sb.RuntimeIncarnationID != nil {
			snap.Incarnation = *sb.RuntimeIncarnationID
			if host, fence, ok := sf.Fleet.PlacementOf(*sb.RuntimeIncarnationID); ok {
				snap.Host = host
				snap.Fence = fence
			}
		}
		if sb.CheckpointRef != nil {
			snap.Checkpoint = *sb.CheckpointRef
		}
		_, snap.Lease = sf.Mgr.LeaseOf(sb.SandboxID)
		bindings := sf.Mgr.ListEndpointBindings(sb.SandboxID)
		sort.Slice(bindings, func(i, j int) bool { return bindings[i].BindingID < bindings[j].BindingID })
		for _, b := range bindings {
			snap.Bindings = append(snap.Bindings, BindingSnap{
				Name: b.LogicalName, State: string(b.State), Port: b.TargetPort,
			})
		}
		w.Sandboxes = append(w.Sandboxes, snap)
	}
	return w
}

// parseViolationNote decodes the Engine's INVARIANT_VIOLATION note label
// ("INVARIANT_VIOLATION <id> seq=<n> <detail>"); ok=false for other labels.
func parseViolationNote(label string) (ViolationNote, bool) {
	const pfx = "INVARIANT_VIOLATION "
	if !strings.HasPrefix(label, pfx) {
		return ViolationNote{}, false
	}
	rest := strings.TrimPrefix(label, pfx)
	parts := strings.SplitN(rest, " ", 3)
	if len(parts) < 3 || !strings.HasPrefix(parts[1], "seq=") {
		return ViolationNote{Invariant: parts[0]}, true
	}
	return ViolationNote{Invariant: parts[0], Detail: parts[2]}, true
}

// Recorder builds the v2 JSONL artifact. Trace entries are recorded
// synchronously from the kernel hook (cheap, append-only); world snapshots
// are taken at kernel AfterEach points, where no manager/fleet locks are
// held and the world is between transitions — the kernel's Note is called
// from inside manager operations, so snapshotting synchronously in the
// entry hook would deadlock on the manager mutex.
type Recorder struct {
	sf      *SimFleet
	labeler func(string) string

	recs             []eventRecord
	entriesSinceSnap uint64
	snapshots        int
}

// AttachRecorder wires a recorder into the kernel's hooks and returns it.
// Artifact produces the final artifact after the run.
func AttachRecorder(sf *SimFleet, labeler func(string) string) *Recorder {
	r := &Recorder{sf: sf, labeler: labeler}
	prevEntry := sf.Kernel.OnTraceEntry
	sf.Kernel.OnTraceEntry = func(e TraceEntry) {
		if prevEntry != nil {
			prevEntry(e)
		}
		r.observe(e)
	}
	prevEach := sf.Kernel.AfterEach
	sf.Kernel.AfterEach = func() {
		if prevEach != nil {
			prevEach()
		}
		r.snapshotPoint()
	}
	return r
}

func (r *Recorder) observe(e TraceEntry) {
	rec := eventRecord{
		Type: "event", Seq: e.Seq, Tns: int64(e.At),
		Kind: e.Kind, Label: e.Label, Parent: e.Parent,
	}
	if v, ok := parseViolationNote(e.Label); ok {
		rec.Violation = &v
	}
	r.recs = append(r.recs, rec)
	r.entriesSinceSnap++
}

// snapshotPoint runs at every kernel AfterEach: take a snapshot when the
// gap policy says one is due and attach it to the last recorded entry.
func (r *Recorder) snapshotPoint() {
	if r.entriesSinceSnap == 0 {
		return
	}
	s := uint64(r.sf.Mgr.SandboxCount())
	gap := uint64(1)
	if s > snapshotExactBudget {
		gap = (s + snapshotRowsPerEntry - 1) / snapshotRowsPerEntry
	}
	if r.entriesSinceSnap < gap {
		return
	}
	r.entriesSinceSnap = 0
	r.recs[len(r.recs)-1].World = SnapshotWorld(r.sf, r.labeler)
	r.snapshots++
}

// Artifact renders the complete JSONL artifact: header record, every event
// record observed, and the closing report record with the end-of-run world
// snapshot (taken unconditionally, so the final state is always exact).
func (r *Recorder) Artifact(scenario string, seed int64, report Report) []byte {
	var out bytes.Buffer
	hdr, _ := json.Marshal(traceHeader{
		Type: "header", Format: TraceV2Format, Scenario: scenario, Seed: seed,
	})
	out.Write(hdr)
	out.WriteByte('\n')
	for _, rec := range r.recs {
		data, err := json.Marshal(rec)
		if err != nil {
			panic(fmt.Sprintf("sandboxlab: trace v2 marshal: %v", err))
		}
		out.Write(data)
		out.WriteByte('\n')
	}
	rr := reportRecord{Type: "report", World: SnapshotWorld(r.sf, r.labeler)}
	for _, e := range report.Entries {
		re := reportEntry{
			ID: e.ID, Title: e.Title, Status: e.Status,
			Exercised: e.Exercised, Reason: e.Reason,
		}
		for _, f := range e.Failures {
			re.Failures = append(re.Failures, reportFailure{
				Invariant: f.Invariant, Detail: f.Detail, Seq: f.Seq, AtNs: int64(f.At),
			})
		}
		rr.Entries = append(rr.Entries, re)
	}
	rep, _ := json.Marshal(rr)
	out.Write(rep)
	out.WriteByte('\n')
	return out.Bytes()
}

// --- v2 artifact parsing (tests + replay/render share this) ---

// TraceV2 is a parsed v2 artifact.
type TraceV2 struct {
	Scenario string
	Seed     int64
	Events   []eventRecord
	Report   []reportEntry
	Final    *WorldSnap
}

// ParseTraceV2 decodes a JSONL artifact, validating record types.
func ParseTraceV2(data []byte) (*TraceV2, error) {
	t := &TraceV2{}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, fmt.Errorf("trace v2: empty artifact")
	}
	for i, line := range lines {
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(line), &probe); err != nil {
			return nil, fmt.Errorf("trace v2 line %d: %v", i+1, err)
		}
		switch probe.Type {
		case "header":
			var h traceHeader
			if err := json.Unmarshal([]byte(line), &h); err != nil {
				return nil, fmt.Errorf("trace v2 line %d: %v", i+1, err)
			}
			if h.Format != TraceV2Format {
				return nil, fmt.Errorf("trace v2 line %d: unknown format %q", i+1, h.Format)
			}
			t.Scenario, t.Seed = h.Scenario, h.Seed
		case "event":
			var ev eventRecord
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				return nil, fmt.Errorf("trace v2 line %d: %v", i+1, err)
			}
			t.Events = append(t.Events, ev)
		case "report":
			var rr reportRecord
			if err := json.Unmarshal([]byte(line), &rr); err != nil {
				return nil, fmt.Errorf("trace v2 line %d: %v", i+1, err)
			}
			t.Report, t.Final = rr.Entries, rr.World
		default:
			return nil, fmt.Errorf("trace v2 line %d: unknown record type %q", i+1, probe.Type)
		}
	}
	if t.Scenario == "" {
		return nil, fmt.Errorf("trace v2: no header record")
	}
	return t, nil
}
