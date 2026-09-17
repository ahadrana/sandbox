package sandboxlab

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/agent-sandbox/platform/api"
	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/runtime/hostfacts"
)

// scenario.go — declarative scenario files (ADR-010 phase 4). Scenarios are
// JSON, not YAML: Go 1.18 stdlib has no YAML parser and we are stdlib-only.
// A scenario declares hosts, an ordered step script, and assertions over
// observable outcomes. Execution is synchronous against the kernel clock:
// steps run in order, time advances only via sleep steps (which drive
// fleet/manager ticks at the configured cadence) and per-op latencies.
//
// Step vocabulary:
//   create_sandbox  {count?, save_as?, tenant?, materialize?, allow_fail?}
//   materialize     {sandbox}
//   exec            {sandbox, key?, command?, writes?}
//   commit_workspace {sandbox}
//   bind_endpoint   {sandbox, port, name}
//   suspend         {sandbox|"*"}
//   resume          {sandbox|"*"}
//   sleep           {ms}
//   parallel        {do:[steps]}        — sub-steps in one virtual instant
//   repeat          {times, do:[steps]}
//   terminate       {sandbox|"*"}
//   kill_host       {host|host_of}      — stall_heartbeats is an alias (the
//   stall_heartbeats {...}                control plane cannot distinguish);
//                                         host_of uses the sandbox's last
//                                         known placement (a reclaim-suspend
//                                         erases it from the fleet)
//   revive_host     {host}
//   traffic         {sandbox, requests} — N endpoint requests through the
//                                         resume path (proxy single-flight)
//
// Assertion vocabulary (fixed named predicates, no expression language):
//   {check:"sandbox_state", sandbox, eq:"RUNNING"}     — "*" = every pooled sandbox
//   {check:"sandbox_live", sandbox, eq:true}           — RUNNING/QUIESCENT/BACKGROUND_ACTIVE
//   {check:"epoch", sandbox, eq:N}
//   {check:"restore_rpcs", sandbox, eq:N}              — continuity-restore RPCs
//   {check:"live_incarnations", sandbox?, eq:N}        — fleet placements
//   {check:"resume_operations", eq:N}                  — total restore RPCs, fleet-wide
//   {check:"materialize_failures", eq:N}
//   {check:"traffic_all_status", eq:200}
//   {check:"violations", eq:0}                         — invariant engine report
//   {check:"max_live_vms", le:N}
//   {check:"hosts_capacity_within_limits", eq:true}

// Scenario is the parsed scenario file.
type Scenario struct {
	Name          string         `json:"name"`
	Seed          int64          `json:"seed"`
	TickCadenceMS int64          `json:"tick_cadence_ms"`
	Hosts         []ScenarioHost `json:"hosts"`
	Steps         []Step         `json:"steps"`
	Assert        []Assertion    `json:"assert"`
}

// ScenarioHost declares one host. vcpu/io_mbps/net_mbps/vm_idle_vcpu
// configure the phase-6 contention model; unset (vcpu 0) the host runs the
// legacy flat-latency model.
type ScenarioHost struct {
	ID         string  `json:"id"`
	Slots      int     `json:"slots"`
	Memory     int64   `json:"memory"`
	VCPU       float64 `json:"vcpu"`
	IOMBps     float64 `json:"io_mbps"`
	NetMBps    float64 `json:"net_mbps"`
	VMIdleVCPU float64 `json:"vm_idle_vcpu"`
	Facts      struct {
		Arch          string `json:"arch"`
		KernelRelease string `json:"kernel_release"`
		CPUPart       string `json:"cpu_part"`
	} `json:"facts"`
	Latencies struct {
		CreateMS    int64 `json:"create_ms"`
		SnapshotMS  int64 `json:"snapshot_ms"`
		RestoreMS   int64 `json:"restore_ms"`
		TerminateMS int64 `json:"terminate_ms"`
	} `json:"latencies"`
}

// Step is one script action. Op selects the verb; the remaining fields are
// verb-specific. Do carries sub-steps for parallel/repeat. Sandbox selectors
// are a create label, "*" (every pooled sandbox), or "$last" (most recently
// created — the loop-variable idiom for repeat blocks).
type Step struct {
	Op string `json:"op"`

	// common selectors
	Sandbox string `json:"sandbox"` // label or "*"
	Host    string `json:"host"`
	HostOf  string `json:"host_of"` // sandbox label: the host currently holding it

	// create_sandbox
	Count       int    `json:"count"`
	SaveAs      string `json:"save_as"`
	Tenant      string `json:"tenant"`
	Materialize bool   `json:"materialize"`
	AllowFail   bool   `json:"allow_fail"`

	// exec / bind_endpoint / commit
	Key     string            `json:"key"`
	Command string            `json:"command"`
	Writes  map[string]string `json:"writes"`
	Port    int               `json:"port"`
	Name    string            `json:"name"`

	// sleep / repeat / traffic
	MS       int64 `json:"ms"`
	Times    int   `json:"times"`
	Requests int   `json:"requests"`

	Do []Step `json:"do"`
}

// Assertion is one named predicate with arguments.
type Assertion struct {
	Check   string           `json:"check"`
	Sandbox string           `json:"sandbox"`
	Eq      *json.RawMessage `json:"eq"` // number, string, or bool
	Le      *int64           `json:"le"`
	Ge      *int64           `json:"ge"`
}

// Result is the outcome of a scenario run.
type Result struct {
	Scenario    *Scenario
	Fleet       *SimFleet
	Report      Report
	Trace       []byte // self-describing trace artifact (see TraceFormat)
	TraceV2     []byte // enriched JSONL artifact (phase 5, see recorder.go)
	VirtualTime time.Duration
	EventsFired uint64
	MaxLiveVMs  int
	ResumeOps   int
	// OpStats holds p50/p99 op durations per kind when the contention
	// model recorded any (phase 6); empty in flat-latency runs.
	OpStats       map[string][2]time.Duration
	AssertFailure []string
}

// Pass reports whether the scenario's assertions and invariants are clean.
func (r *Result) Pass() bool {
	_, v, _, _ := r.Report.Counts()
	return len(r.AssertFailure) == 0 && v == 0
}

// Verdict renders the runner's verdict block.
func (r *Result) Verdict() string {
	status := "PASS"
	if !r.Pass() {
		status = "FAIL"
	}
	checked, viol, notEx, notCheck := r.Report.Counts()
	var b strings.Builder
	fmt.Fprintf(&b, "scenario: %s (seed %d)\n%s\n", r.Scenario.Name, r.Scenario.Seed, status)
	fmt.Fprintf(&b, "virtual duration: %v   events fired: %d   max live VMs: %d   resume attempts: %d\n",
		r.VirtualTime, r.EventsFired, r.MaxLiveVMs, r.ResumeOps)
	for _, kind := range []string{"create", "restore", "snapshot", "terminate"} {
		if p, ok := r.OpStats[kind]; ok {
			fmt.Fprintf(&b, "%s latency p50: %v  p99: %v\n", kind, p[0], p[1])
		}
	}
	fmt.Fprintf(&b, "invariants checked: %d, violations: %d (not-exercised: %d, not-checkable: %d)",
		checked, viol, notEx, notCheck)
	for _, f := range r.AssertFailure {
		fmt.Fprintf(&b, "\nassertion failed: %s", f)
	}
	if viol > 0 {
		for _, v := range r.Report.Violations() {
			fmt.Fprintf(&b, "\nviolation %s seq=%d: %s", v.Invariant, v.Seq, v.Detail)
		}
	}
	return b.String()
}

// TraceFormat is the stable, documented trace artifact (phase 5 renders it):
//
//	# sandboxlab-trace v1
//	# scenario: <name>
//	# seed: <seed>
//	<seq> <ns> fire <label>            — one line per fired kernel event
//	<seq> <ns> note <label>            — outcome notes and INVARIANT_VIOLATION lines
//
// Byte-identical across runs of the same scenario and seed.
func traceArtifact(sc *Scenario, sf *SimFleet) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# sandboxlab-trace v1\n# scenario: %s\n# seed: %d\n", sc.Name, sc.Seed)
	b.Write(sf.Kernel.TraceBytes())
	return []byte(b.String())
}

// ParseScenario decodes and validates a scenario file. Parse errors are
// loud and specific.
func ParseScenario(data []byte) (*Scenario, error) {
	var sc Scenario
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sc); err != nil {
		return nil, fmt.Errorf("scenario JSON: %v", err)
	}
	if sc.Name == "" {
		return nil, fmt.Errorf("scenario: missing name")
	}
	if len(sc.Hosts) == 0 {
		return nil, fmt.Errorf("scenario %s: no hosts", sc.Name)
	}
	seen := map[string]bool{}
	for i, h := range sc.Hosts {
		if h.ID == "" {
			return nil, fmt.Errorf("scenario %s: hosts[%d] missing id", sc.Name, i)
		}
		if h.Slots <= 0 {
			return nil, fmt.Errorf("scenario %s: host %s slots must be > 0", sc.Name, h.ID)
		}
		if h.Memory <= 0 {
			return nil, fmt.Errorf("scenario %s: host %s memory must be > 0", sc.Name, h.ID)
		}
		if seen[h.ID] {
			return nil, fmt.Errorf("scenario %s: duplicate host id %q", sc.Name, h.ID)
		}
		seen[h.ID] = true
	}
	for i, st := range sc.Steps {
		if err := validateStep(&sc, st, fmt.Sprintf("steps[%d]", i)); err != nil {
			return nil, err
		}
	}
	for i, a := range sc.Assert {
		if err := validateAssert(a, fmt.Sprintf("assert[%d]", i)); err != nil {
			return nil, err
		}
	}
	return &sc, nil
}

var stepOps = map[string]bool{
	"create_sandbox": true, "materialize": true, "exec": true,
	"commit_workspace": true, "bind_endpoint": true, "suspend": true,
	"resume": true, "sleep": true, "parallel": true, "repeat": true,
	"kill_host": true, "stall_heartbeats": true, "revive_host": true,
	"traffic": true, "terminate": true,
}

var assertChecks = map[string]bool{
	"sandbox_state": true, "sandbox_live": true, "epoch": true, "restore_rpcs": true,
	"live_incarnations": true, "resume_operations": true,
	"materialize_failures": true, "traffic_all_status": true,
	"violations": true, "max_live_vms": true, "hosts_capacity_within_limits": true,
}

func validateStep(sc *Scenario, st Step, where string) error {
	if !stepOps[st.Op] {
		return fmt.Errorf("scenario %s: %s: unknown step op %q", sc.Name, where, st.Op)
	}
	if st.Host != "" && !hostDeclared(sc, st.Host) {
		return fmt.Errorf("scenario %s: %s: unknown host %q", sc.Name, where, st.Host)
	}
	for i, sub := range st.Do {
		if err := validateStep(sc, sub, fmt.Sprintf("%s.do[%d]", where, i)); err != nil {
			return err
		}
	}
	return nil
}

func validateAssert(a Assertion, where string) error {
	if !assertChecks[a.Check] {
		return fmt.Errorf("%s: unknown assert check %q", where, a.Check)
	}
	if a.Eq == nil && a.Le == nil && a.Ge == nil {
		return fmt.Errorf("%s: assert %q needs one of eq/le/ge", where, a.Check)
	}
	return nil
}

func hostDeclared(sc *Scenario, id string) bool {
	for _, h := range sc.Hosts {
		if h.ID == id {
			return true
		}
	}
	return false
}

// --- execution ---

type runner struct {
	sc  *Scenario
	sf  *SimFleet
	res *Result

	pool     []string                   // every created sandbox label, in order
	symbols  map[string]string          // label -> sandboxID
	incsOf   map[string]map[string]bool // label -> incarnation IDs ever seen
	lastHost map[string]string          // label -> last known placement host
	matFails int
	traffic  []int // statuses from the last traffic step

	opDurations []opDuration // contention-mode op durations, aggregated at end
}

type opDuration struct {
	kind string
	d    time.Duration
}

// percentile returns the p-th percentile (nearest-rank) of ds.
func percentile(ds []time.Duration, p int) time.Duration {
	sorted := append([]time.Duration{}, ds...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := (len(sorted)*p + 99) / 100 // nearest-rank, 1-based
	if idx > len(sorted) {
		idx = len(sorted)
	}
	return sorted[idx-1]
}

// RunScenario executes a scenario end to end and evaluates its assertions.
func RunScenario(sc *Scenario) (*Result, error) {
	cfg := Config{Seed: sc.Seed}
	for _, h := range sc.Hosts {
		cfg.Hosts = append(cfg.Hosts, HostSpec{
			ID: h.ID, MemCapacity: h.Memory, Slots: h.Slots,
			Pools: Pools{VCPU: h.VCPU, IOMBps: h.IOMBps, NetMBps: h.NetMBps, VMIdleVCPU: h.VMIdleVCPU},
			Facts: hostfacts.Facts{
				Arch:          orDefault(h.Facts.Arch, "arm64"),
				KernelRelease: orDefault(h.Facts.KernelRelease, "6.8.0-sim"),
				CPUPart:       orDefault(h.Facts.CPUPart, "0xd00"),
			},
			Latencies: Latencies{
				Create:    time.Duration(h.Latencies.CreateMS) * time.Millisecond,
				Snapshot:  time.Duration(h.Latencies.SnapshotMS) * time.Millisecond,
				Restore:   time.Duration(h.Latencies.RestoreMS) * time.Millisecond,
				Terminate: time.Duration(h.Latencies.TerminateMS) * time.Millisecond,
			},
		})
	}
	sf := New(cfg) // no kernel tick events; sleeps drive ticks
	r := &runner{
		sc: sc, sf: sf,
		symbols: map[string]string{}, incsOf: map[string]map[string]bool{},
		lastHost: map[string]string{},
	}
	r.res = &Result{Scenario: sc, Fleet: sf}

	// Phase-5 enriched trace: records every kernel trace entry as it is
	// written, with world snapshots under the adaptive-stride policy.
	rec := AttachRecorder(sf, r.labelOf)

	// Track the live-VM high-water mark alongside the engine's AfterEach.
	prev := sf.Kernel.AfterEach
	sf.Kernel.AfterEach = func() {
		prev()
		if n := r.liveVMs(); n > r.res.MaxLiveVMs {
			r.res.MaxLiveVMs = n
		}
	}

	for i, st := range sc.Steps {
		if err := r.step(st, fmt.Sprintf("steps[%d]", i)); err != nil {
			return nil, err
		}
		// Phase 6: join contention-mode ops started by the step — their
		// completions are kernel wake events. No-op in flat mode (no wakes
		// queued), so flat traces stay byte-identical.
		sf.JoinOps()
		// The driver is synchronous — no kernel queue — so the engine's
		// observation point is invoked explicitly after each step.
		if sf.Kernel.AfterEach != nil {
			sf.Kernel.AfterEach()
		}
	}
	r.trackIncs()

	r.res.VirtualTime = sf.Kernel.Now()
	r.res.EventsFired = uint64(len(sf.Kernel.Trace()))
	r.res.Report = sf.InvariantReport()
	r.res.Trace = traceArtifact(sc, sf)
	r.res.TraceV2 = rec.Artifact(sc.Name, sc.Seed, r.res.Report)
	for _, h := range sf.Hosts {
		for _, n := range h.Restores {
			r.res.ResumeOps += n
		}
	}
	// Phase 6: when any host ran the contention model, op durations are
	// meaningful — surface p50/p99 in the verdict.
	r.res.OpStats = map[string][2]time.Duration{}
	for _, h := range sf.Hosts {
		for kind, ds := range h.OpDur {
			for _, d := range ds {
				r.opDurations = append(r.opDurations, opDuration{kind: kind, d: d})
			}
		}
	}
	for _, kind := range []string{"create", "restore", "snapshot", "terminate"} {
		var ds []time.Duration
		for _, od := range r.opDurations {
			if od.kind == kind {
				ds = append(ds, od.d)
			}
		}
		if len(ds) > 0 {
			r.res.OpStats[kind] = [2]time.Duration{percentile(ds, 50), percentile(ds, 99)}
		}
	}
	for i, a := range sc.Assert {
		if msg := r.check(a); msg != "" {
			r.res.AssertFailure = append(r.res.AssertFailure, fmt.Sprintf("assert[%d] %s: %s", i, a.Check, msg))
		}
	}
	return r.res, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// liveVMs counts fleet-visible live incarnations via host accounting.
func (r *runner) liveVMs() int {
	n := 0
	for _, h := range r.sf.Hosts {
		n += h.View().UsedSlots
	}
	return n
}

// tickCadence returns the tick interval (default 100ms virtual).
func (r *runner) tickCadence() time.Duration {
	if r.sc.TickCadenceMS > 0 {
		return time.Duration(r.sc.TickCadenceMS) * time.Millisecond
	}
	return 100 * time.Millisecond
}

// resolve maps a sandbox label (or "*") to concrete sandbox IDs.
func (r *runner) resolve(sel string) ([]string, error) {
	if sel == "$last" {
		if len(r.pool) == 0 {
			return nil, fmt.Errorf("sandbox selector $last: no sandboxes created yet")
		}
		return []string{r.symbols[r.pool[len(r.pool)-1]]}, nil
	}
	if sel == "*" {
		if len(r.pool) == 0 {
			return nil, fmt.Errorf("sandbox selector *: no sandboxes created yet")
		}
		ids := make([]string, 0, len(r.pool))
		for _, label := range r.pool {
			ids = append(ids, r.symbols[label])
		}
		return ids, nil
	}
	id, ok := r.symbols[sel]
	if !ok {
		return nil, fmt.Errorf("unknown sandbox label %q", sel)
	}
	return []string{id}, nil
}

// labelOf returns the label for a sandbox ID (for trace notes).
func (r *runner) labelOf(id string) string {
	for l, s := range r.symbols {
		if s == id {
			return l
		}
	}
	return id
}

// trackIncs records the current incarnation of every pooled sandbox, so
// restore-RPC accounting covers every incarnation a sandbox ever had.
func (r *runner) trackIncs() {
	for _, label := range r.pool {
		id := r.symbols[label]
		info, err := r.sf.Mgr.GetSandbox(id)
		if err != nil || info.RuntimeIncarnationID == nil {
			continue
		}
		if r.incsOf[label] == nil {
			r.incsOf[label] = map[string]bool{}
		}
		r.incsOf[label][*info.RuntimeIncarnationID] = true
		if host, ok := r.sf.Mgr.HostOf(id); ok {
			r.lastHost[label] = host
		}
	}
}

// restoreRPCs sums host restore RPCs over every incarnation a label ever had.
func (r *runner) restoreRPCs(label string) int {
	n := 0
	for inc := range r.incsOf[label] {
		for _, h := range r.sf.Hosts {
			n += h.Restores[inc]
		}
	}
	return n
}

func (r *runner) step(st Step, where string) error {
	k := r.sf.Kernel
	switch st.Op {
	case "create_sandbox":
		count := st.Count
		if count == 0 {
			count = 1
		}
		tenant := orDefault(st.Tenant, "t1")
		for i := 0; i < count; i++ {
			label := st.SaveAs
			if count > 1 || label == "" {
				label = fmt.Sprintf("%s-%d", orDefault(st.SaveAs, "sb"), len(r.pool))
			}
			sb, err := r.sf.Mgr.CreateSandbox(api.CreateSandboxRequest{
				Version: api.SchemaVersionV1, TenantID: tenant, TaskRef: label,
			})
			if err != nil {
				return fmt.Errorf("%s: create_sandbox %s: %v", where, label, err)
			}
			r.symbols[label] = sb.SandboxID
			r.pool = append(r.pool, label)
			if st.Materialize {
				if _, err := r.sf.Mgr.Materialize(sb.SandboxID); err != nil {
					r.matFails++
					k.Note(fmt.Sprintf("materialize %s err %v", label, err))
					if !st.AllowFail {
						return fmt.Errorf("%s: materialize %s: %v", where, label, err)
					}
				} else {
					k.Note(fmt.Sprintf("live %s %s", label, sb.SandboxID))
				}
			}
		}
	case "materialize":
		ids, err := r.resolve(st.Sandbox)
		if err != nil {
			return fmt.Errorf("%s: %v", where, err)
		}
		for _, id := range ids {
			if _, err := r.sf.Mgr.Materialize(id); err != nil {
				return fmt.Errorf("%s: materialize %s: %v", where, r.labelOf(id), err)
			}
			k.Note("materialize " + r.labelOf(id))
		}
	case "exec":
		ids, err := r.resolve(st.Sandbox)
		if err != nil {
			return fmt.Errorf("%s: %v", where, err)
		}
		for _, id := range ids {
			cmd := orDefault(st.Command, "true")
			ex, err := r.sf.Mgr.StartExecution(api.StartExecutionRequest{
				Version: api.SchemaVersionV1, SandboxID: id, TenantID: "t1",
				PrincipalID: "p-sim", IdempotencyKey: st.Key,
				Operation: domain.Operation{Command: cmd, Writes: st.Writes},
			})
			if err != nil {
				return fmt.Errorf("%s: exec %s: %v", where, r.labelOf(id), err)
			}
			if _, err := r.sf.Mgr.CompleteExecution(ex.ExecutionID); err != nil {
				return fmt.Errorf("%s: complete exec %s: %v", where, r.labelOf(id), err)
			}
			k.Note(fmt.Sprintf("exec %s %s", r.labelOf(id), cmd))
		}
	case "commit_workspace":
		ids, err := r.resolve(st.Sandbox)
		if err != nil {
			return fmt.Errorf("%s: %v", where, err)
		}
		for _, id := range ids {
			if _, err := r.sf.Mgr.CommitWorkspace(api.CommitWorkspaceRequest{
				Version: api.SchemaVersionV1, SandboxID: id, TenantID: "t1",
			}); err != nil {
				return fmt.Errorf("%s: commit_workspace %s: %v", where, r.labelOf(id), err)
			}
			k.Note("commit " + r.labelOf(id))
		}
	case "bind_endpoint":
		ids, err := r.resolve(st.Sandbox)
		if err != nil {
			return fmt.Errorf("%s: %v", where, err)
		}
		for _, id := range ids {
			if _, err := r.sf.Mgr.CreateEndpointBinding(api.CreateEndpointBindingRequest{
				SandboxID: id, TenantID: "t1", TargetPort: st.Port,
				LogicalName: orDefault(st.Name, "web"), TTL: time.Hour,
			}); err != nil {
				return fmt.Errorf("%s: bind_endpoint %s: %v", where, r.labelOf(id), err)
			}
			k.Note(fmt.Sprintf("bind %s :%d", r.labelOf(id), st.Port))
		}
	case "suspend":
		ids, err := r.resolve(st.Sandbox)
		if err != nil {
			return fmt.Errorf("%s: %v", where, err)
		}
		for _, id := range ids {
			if err := r.sf.Mgr.Suspend(id); err != nil {
				return fmt.Errorf("%s: suspend %s: %v", where, r.labelOf(id), err)
			}
			k.Note("suspend " + r.labelOf(id))
		}
	case "resume":
		ids, err := r.resolve(st.Sandbox)
		if err != nil {
			return fmt.Errorf("%s: %v", where, err)
		}
		for _, id := range ids {
			if _, err := r.sf.Mgr.Resume(id); err != nil {
				return fmt.Errorf("%s: resume %s: %v", where, r.labelOf(id), err)
			}
			k.Note("resume " + r.labelOf(id))
		}
	case "terminate":
		ids, err := r.resolve(st.Sandbox)
		if err != nil {
			return fmt.Errorf("%s: %v", where, err)
		}
		for _, id := range ids {
			if err := r.sf.Mgr.Terminate(id); err != nil {
				return fmt.Errorf("%s: terminate %s: %v", where, r.labelOf(id), err)
			}
			k.Note("terminate " + r.labelOf(id))
		}
	case "sleep":
		// Advance virtual time in cadence chunks, driving ticks. Drain the
		// kernel queue per chunk first (contention wake events due inside
		// the chunk), then advance the remainder — in flat mode the queue
		// is empty and this reduces to the legacy bare Advance.
		remaining := time.Duration(st.MS) * time.Millisecond
		cad := r.tickCadence()
		for remaining > 0 {
			d := cad
			if d > remaining {
				d = remaining
			}
			end := k.Now() + d
			if k.Pending() {
				k.RunUntil(end)
			}
			if k.Now() < end {
				k.Advance(end - k.Now())
			}
			_ = r.sf.Mgr.Tick(0)
			k.Note(fmt.Sprintf("tick t=%dms", k.Now().Milliseconds()))
			remaining -= d
		}
		r.trackIncs()
	case "parallel", "repeat":
		times := 1
		if st.Op == "repeat" {
			times = st.Times
			if times <= 0 {
				return fmt.Errorf("%s: repeat needs times > 0", where)
			}
		}
		if len(st.Do) == 0 {
			return fmt.Errorf("%s: %s needs do[]", where, st.Op)
		}
		k.Note(fmt.Sprintf("%s begin (%d sub-steps x%d)", st.Op, len(st.Do), times))
		for t := 0; t < times; t++ {
			for i, sub := range st.Do {
				if err := r.step(sub, fmt.Sprintf("%s.do[%d]", where, i)); err != nil {
					return err
				}
			}
		}
		k.Note(st.Op + " end")
	case "kill_host", "stall_heartbeats":
		host, err := r.resolveHost(st, where)
		if err != nil {
			return err
		}
		r.sf.KillHost(host)
	case "revive_host":
		host, err := r.resolveHost(st, where)
		if err != nil {
			return err
		}
		r.sf.Fleet.HostSeen(host)
		k.Note("revive " + host)
	case "traffic":
		// N endpoint requests at a (possibly suspended) sandbox, through the
		// resume path: the proxy's semantics are resume-then-forward. One
		// virtual instant — requests race; the manager's single-flight must
		// produce exactly one restore.
		ids, err := r.resolve(st.Sandbox)
		if err != nil {
			return fmt.Errorf("%s: %v", where, err)
		}
		n := st.Requests
		if n == 0 {
			n = 1
		}
		r.traffic = nil
		for _, id := range ids {
			for i := 0; i < n; i++ {
				status := 200
				_, err := r.sf.Mgr.Resume(id)
				if err != nil {
					status = 503
				} else if info, _ := r.sf.Mgr.GetSandbox(id); !liveState(info.ObservedState) {
					// 200 means the request was served: the sandbox is live
					// (RUNNING, or QUIESCENT once idle — the proxy's success
					// semantics), not wedged mid-resume.
					status = 502
				}
				r.traffic = append(r.traffic, status)
			}
			k.Note(fmt.Sprintf("traffic %s requests=%d all-200=%v", r.labelOf(id), n, all200(r.traffic)))
		}
	default:
		return fmt.Errorf("%s: unknown step op %q", where, st.Op)
	}
	r.trackIncs()
	return nil
}

func (r *runner) resolveHost(st Step, where string) (string, error) {
	if st.Host != "" {
		if _, ok := r.sf.Hosts[st.Host]; !ok {
			return "", fmt.Errorf("%s: unknown host %q", where, st.Host)
		}
		return st.Host, nil
	}
	if st.HostOf != "" {
		id, ok := r.symbols[st.HostOf]
		if !ok {
			return "", fmt.Errorf("%s: unknown sandbox label %q", where, st.HostOf)
		}
		host, ok := r.sf.Mgr.HostOf(id)
		if !ok {
			// A reclaim-suspend erases the placement; the "origin host" is
			// the last one we observed holding the sandbox.
			host, ok = r.lastHost[st.HostOf]
			if !ok {
				return "", fmt.Errorf("%s: sandbox %s has no known host", where, st.HostOf)
			}
		}
		return host, nil
	}
	return "", fmt.Errorf("%s: %s needs host or host_of", where, st.Op)
}

func all200(ss []int) bool {
	for _, s := range ss {
		if s != 200 {
			return false
		}
	}
	return true
}

// --- assertions ---

func (r *runner) check(a Assertion) string {
	intVal := func() int64 {
		if a.Eq == nil {
			return 0
		}
		var n int64
		if err := json.Unmarshal(*a.Eq, &n); err != nil {
			return -1 << 62 // never equal: malformed eq caught by parse validation of JSON
		}
		return n
	}
	strVal := func() string {
		if a.Eq == nil {
			return ""
		}
		var s string
		if err := json.Unmarshal(*a.Eq, &s); err != nil {
			return "\x00"
		}
		return s
	}
	boolVal := func() bool {
		if a.Eq == nil {
			return false
		}
		var b bool
		if err := json.Unmarshal(*a.Eq, &b); err != nil {
			return false
		}
		return b
	}

	// numeric comparison against eq/le/ge
	cmp := func(got int64) (bool, string) {
		if a.Eq != nil && got != intVal() {
			return false, fmt.Sprintf("got %d, want eq %d", got, intVal())
		}
		if a.Le != nil && got > *a.Le {
			return false, fmt.Sprintf("got %d, want le %d", got, *a.Le)
		}
		if a.Ge != nil && got < *a.Ge {
			return false, fmt.Sprintf("got %d, want ge %d", got, *a.Ge)
		}
		return true, ""
	}

	switch a.Check {
	case "sandbox_state":
		ids, err := r.resolve(a.Sandbox)
		if err != nil {
			return err.Error()
		}
		for _, id := range ids {
			info, err := r.sf.Mgr.GetSandbox(id)
			if err != nil {
				return err.Error()
			}
			if string(info.ObservedState) != strVal() {
				return fmt.Sprintf("sandbox %s state %s, want %s", r.labelOf(id), info.ObservedState, strVal())
			}
		}
	case "sandbox_live":
		ids, err := r.resolve(a.Sandbox)
		if err != nil {
			return err.Error()
		}
		for _, id := range ids {
			info, err := r.sf.Mgr.GetSandbox(id)
			if err != nil {
				return err.Error()
			}
			if liveState(info.ObservedState) != boolVal() {
				return fmt.Sprintf("sandbox %s live=%v (state %s), want %v",
					r.labelOf(id), liveState(info.ObservedState), info.ObservedState, boolVal())
			}
		}
	case "epoch":
		ids, err := r.resolve(a.Sandbox)
		if err != nil {
			return err.Error()
		}
		for _, id := range ids {
			info, err := r.sf.Mgr.GetSandbox(id)
			if err != nil {
				return err.Error()
			}
			if ok, msg := cmp(info.ExecutionEpoch); !ok {
				return fmt.Sprintf("sandbox %s epoch %s", r.labelOf(id), msg)
			}
		}
	case "restore_rpcs":
		labels := []string{a.Sandbox}
		if a.Sandbox == "*" {
			labels = r.pool
		}
		for _, label := range labels {
			if ok, msg := cmp(int64(r.restoreRPCs(label))); !ok {
				return fmt.Sprintf("sandbox %s restore_rpcs %s", label, msg)
			}
		}
	case "live_incarnations":
		var got int64
		if a.Sandbox != "" {
			ids, err := r.resolve(a.Sandbox)
			if err != nil {
				return err.Error()
			}
			for _, id := range ids {
				info, err := r.sf.Mgr.GetSandbox(id)
				if err != nil {
					return err.Error()
				}
				if info.RuntimeIncarnationID != nil {
					if _, _, placed := r.sf.Fleet.PlacementOf(*info.RuntimeIncarnationID); placed {
						got++
					}
				}
			}
		} else {
			got = int64(r.liveVMs())
		}
		if ok, msg := cmp(got); !ok {
			return fmt.Sprintf("live_incarnations %s", msg)
		}
	case "resume_operations":
		if ok, msg := cmp(int64(r.res.ResumeOps)); !ok {
			return fmt.Sprintf("resume_operations %s", msg)
		}
	case "materialize_failures":
		if ok, msg := cmp(int64(r.matFails)); !ok {
			return fmt.Sprintf("materialize_failures %s", msg)
		}
	case "traffic_all_status":
		for i, s := range r.traffic {
			if int64(s) != intVal() {
				return fmt.Sprintf("request %d status %d, want %d", i, s, intVal())
			}
		}
		if len(r.traffic) == 0 {
			return "no traffic step ran"
		}
	case "violations":
		_, v, _, _ := r.res.Report.Counts()
		if ok, msg := cmp(int64(v)); !ok {
			return fmt.Sprintf("violations %s", msg)
		}
	case "max_live_vms":
		if ok, msg := cmp(int64(r.res.MaxLiveVMs)); !ok {
			return fmt.Sprintf("max_live_vms %s", msg)
		}
	case "hosts_capacity_within_limits":
		got := true
		for id, h := range r.sf.Hosts {
			v := h.View()
			if v.UsedSlots < 0 || v.UsedSlots > v.CapacitySlots || v.UsedMemory < 0 || v.UsedMemory > v.CapacityMemory {
				got = false
				return fmt.Sprintf("host %s outside limits: %+v", id, v)
			}
		}
		if got != boolVal() {
			return fmt.Sprintf("hosts_capacity_within_limits %v, want %v", got, boolVal())
		}
	default:
		return fmt.Sprintf("unknown check %q", a.Check)
	}
	return ""
}

// ScenarioNames lists the built-in scenario library (embedded).
func ScenarioNames() []string {
	names, _ := builtinNames()
	return names
}

// LoadScenario resolves a scenario by file path or built-in name.
func LoadScenario(nameOrPath string) (*Scenario, error) {
	if strings.HasSuffix(nameOrPath, ".json") || strings.Contains(nameOrPath, "/") {
		data, err := readFile(nameOrPath)
		if err != nil {
			return nil, err
		}
		return ParseScenario(data)
	}
	data, err := builtinScenario(nameOrPath)
	if err != nil {
		return nil, err
	}
	return ParseScenario(data)
}
