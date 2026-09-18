package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// serverScript is the per-sandbox guest workload: an HTTP server on port
// 8000 answering "hello from sandbox <name> counter=<n>" where n comes from
// a tmpfs file (RAM-resident: a genuine continuity marker across
// checkpoint/restore).
const serverScript = `import http.server
MSG = "hello from sandbox %s"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            c = open('/tmp/sim-counter').read().strip()
        except Exception:
            c = '?'
        b = (MSG + " counter=" + c + "\n").encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def log_message(self, *a):
        pass
http.server.HTTPServer(('', %d), H).serve_forever()
`

const (
	counterPath = "/tmp/sim-counter"
)

// tickCommand increments the tmpfs counter (the sim's periodic exec tick).
const tickCommand = `n=$(( $(cat /tmp/sim-counter 2>/dev/null || echo 0) + 1 )); echo $n > /tmp/sim-counter`

// Event is one recorded sim action/result.
type Event struct {
	Time    time.Time `json:"time"`
	Sandbox string    `json:"sandbox,omitempty"`
	Kind    string    `json:"kind"` // CREATE/BIND/EXEC/CURL/SUSPEND/RESTORE/REFRESH/ERROR/INFO
	Detail  string    `json:"detail"`
	DurMs   int64     `json:"dur_ms,omitempty"`
	OK      bool      `json:"ok"`
}

// ring is a bounded FIFO of events (last ringSize kept).
type ring struct {
	buf  []Event
	cap  int
	next int
	len  int
}

func newRing(capacity int) *ring { return &ring{buf: make([]Event, capacity), cap: capacity} }

func (r *ring) add(e Event) {
	r.buf[r.next] = e
	r.next = (r.next + 1) % r.cap
	if r.len < r.cap {
		r.len++
	}
}

// snapshot returns the events oldest-first.
func (r *ring) snapshot() []Event {
	out := make([]Event, 0, r.len)
	for i := 0; i < r.len; i++ {
		out = append(out, r.buf[(r.next-r.len+r.cap+i)%r.cap])
	}
	return out
}

// SandboxRec is the sim's per-sandbox record.
type SandboxRec struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	BindingID       string `json:"binding_id"`
	State           string `json:"state"`
	Epoch           int64  `json:"epoch"`
	WorkspaceGen    int64  `json:"workspace_generation"`
	LastAction      string `json:"last_action"`
	Continuity      string `json:"continuity"` // PASS | FAIL | ""
	Counter         int    `json:"counter"`
	preSuspendCount int
	preSuspendEpoch int64
}

// Stats aggregates across all sandboxes and actions.
type Stats struct {
	ByState        map[string]int `json:"by_state"`
	Restores       int            `json:"restores"`
	RestoreFails   int            `json:"restore_fails"`
	ContinuityPass int            `json:"continuity_pass"`
	ContinuityFail int            `json:"continuity_fail"`
	ExecOK         int            `json:"exec_ok"`
	ExecFail       int            `json:"exec_fail"`
	CurlOK         int            `json:"curl_ok"`
	CurlFail       int            `json:"curl_fail"`
	AvgLatencyMs   int64          `json:"avg_latency_ms"`
	P95LatencyMs   int64          `json:"p95_latency_ms"`
	CPHealthy      bool           `json:"cp_healthy"`
	UptimeSeconds  int64          `json:"uptime_seconds"`
}

const (
	ringSize     = 500
	latencyCap   = 512
	execStateOK  = "COMPLETED"
	stateRunning = "RUNNING"
	stateSuspd   = "SUSPENDED"
)

// liveStates are observed states where exec ticks and curls make sense
// (BACKGROUND_ACTIVE is a running sandbox whose activity is baseline-only).
var liveStates = map[string]bool{"RUNNING": true, "BACKGROUND_ACTIVE": true, "QUIESCENT": true}

func isLive(state string) bool { return liveStates[state] }

// Sim drives the scenario and records everything.
type Sim struct {
	cp       CPClient
	scenario string
	started  time.Time
	PortBase int // target-port base for per-sandbox workloads (default 8000)

	mu        sync.Mutex
	sandboxes []*SandboxRec
	events    *ring
	stats     Stats
	latencies []int64 // recent endpoint-curl durations, ms
	stop      chan struct{}
	stopped   sync.Once
}

func NewSim(cp CPClient, scenario string) *Sim {
	return &Sim{
		cp: cp, scenario: scenario, started: time.Now(), PortBase: 8000,
		events: newRing(ringSize), stop: make(chan struct{}),
		stats: Stats{ByState: map[string]int{}},
	}
}

// record appends an event and folds it into the aggregate stats.
func (s *Sim) record(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events.add(e)
	switch e.Kind {
	case "EXEC":
		if e.OK {
			s.stats.ExecOK++
		} else {
			s.stats.ExecFail++
		}
	case "CURL":
		if e.OK {
			s.stats.CurlOK++
		} else {
			s.stats.CurlFail++
		}
		if e.DurMs > 0 {
			s.latencies = append(s.latencies, e.DurMs)
			if len(s.latencies) > latencyCap {
				s.latencies = s.latencies[1:]
			}
		}
	case "RESTORE":
		if e.OK {
			s.stats.Restores++
		} else {
			s.stats.RestoreFails++
		}
	}
}

// timed runs fn, records an event with its duration and outcome.
func (s *Sim) timed(sb *SandboxRec, kind, detail string, fn func() error) error {
	start := time.Now()
	err := fn()
	ev := Event{Time: start, Kind: kind, Detail: detail, DurMs: time.Since(start).Milliseconds(), OK: err == nil}
	if sb != nil {
		ev.Sandbox = sb.Name
		s.mu.Lock()
		sb.LastAction = fmt.Sprintf("%s %s (%dms)", kind, detail, ev.DurMs)
		s.mu.Unlock()
	}
	if err != nil {
		ev.Detail = detail + ": " + err.Error()
	}
	s.record(ev)
	return err
}

// Setup creates, materializes, workloads, and binds N sandboxes. Sandbox i
// serves on target port PortBase+i (host ports are per-binding
// published, so each sandbox needs its own).
func (s *Sim) Setup(n int) error {
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("sim-%d", i)
		port := s.PortBase + i
		rec := &SandboxRec{Name: name, Continuity: ""}
		err := s.timed(rec, "CREATE", "create+materialize+workload", func() error {
			info, err := s.cp.CreateSandbox("sandbox-sim-" + name)
			if err != nil {
				return err
			}
			rec.ID = info.SandboxID
			if err := s.cp.Materialize(rec.ID); err != nil {
				return err
			}
			// Install + start the workload: counter file in tmpfs, python
			// HTTP server on the sandbox's port in the background.
			ex, err := s.cp.Exec(rec.ID,
				"echo 0 > "+counterPath+" && (python3 sim_server.py > /tmp/sim-server.log 2>&1 &) && echo ok",
				map[string]string{"sim_server.py": fmt.Sprintf(serverScript, name, port)})
			if err != nil {
				return err
			}
			if ex.State != execStateOK {
				return fmt.Errorf("workload start exec state %s (exit %d)", ex.State, ex.ExitCode)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := s.timed(rec, "BIND", "endpoint binding "+name+":"+strconv.Itoa(port), func() error {
			id, err := s.cp.CreateBinding(rec.ID, port, name)
			rec.BindingID = id
			return err
		}); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		s.mu.Lock()
		s.sandboxes = append(s.sandboxes, rec)
		s.mu.Unlock()
	}
	s.Refresh()
	// The data path is live once the workload listens; verify each binding.
	for _, rec := range s.sandboxes {
		s.curlOnce(rec)
	}
	return nil
}

// curlOnce performs one endpoint GET through the proxy and records it; a
// 200 with the sandbox's hello message is a pass. Returns body+ok.
func (s *Sim) curlOnce(rec *SandboxRec) (string, bool) {
	var body string
	var status int
	err := s.timed(rec, "CURL", "endpoint GET", func() error {
		var err error
		status, body, err = s.cp.EndpointGet(rec.BindingID)
		if err != nil {
			return err
		}
		if status != 200 {
			return fmt.Errorf("status %d: %.120s", status, body)
		}
		if !strings.Contains(body, "hello from sandbox "+rec.Name) {
			return fmt.Errorf("unexpected body %.120s", body)
		}
		return nil
	})
	if err == nil {
		if n := parseCounter(body); n >= 0 {
			s.mu.Lock()
			rec.Counter = n
			s.mu.Unlock()
		}
	}
	return body, err == nil
}

// parseCounter extracts the counter value from a hello body, -1 if absent.
func parseCounter(body string) int {
	i := strings.LastIndex(body, "counter=")
	if i < 0 {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(body[i+len("counter="):]))
	if err != nil {
		return -1
	}
	return n
}

// execTick increments one sandbox's tmpfs counter via the exec API.
func (s *Sim) execTick(rec *SandboxRec) {
	s.timed(rec, "EXEC", "counter tick", func() error {
		ex, err := s.cp.Exec(rec.ID, tickCommand, nil)
		if err != nil {
			return err
		}
		if ex.State != execStateOK {
			return fmt.Errorf("exec state %s (exit %d)", ex.State, ex.ExitCode)
		}
		return nil
	})
}

// churnOnce suspends rec, resumes it via the API, and checks continuity:
// epoch preserved (continuity restore, not the epoch-bumping snapshot
// resume) AND the tmpfs counter (guest RAM) still at/above its pre-suspend
// value. Snapshot resume is a supported path (ADR-011), just not what this
// check measures.
func (s *Sim) churnOnce(rec *SandboxRec) {
	// Snapshot the pre-suspend continuity facts.
	if _, ok := s.curlOnce(rec); !ok {
		return // already unhealthy; skip this cycle
	}
	s.mu.Lock()
	rec.preSuspendCount = rec.Counter
	rec.preSuspendEpoch = rec.Epoch
	s.mu.Unlock()

	if err := s.timed(rec, "SUSPEND", "checkpoint suspend", func() error {
		return s.cp.Suspend(rec.ID)
	}); err != nil {
		return
	}
	s.setState(rec, stateSuspd)

	var rep *ResumeReport
	restoreErr := s.timed(rec, "RESTORE", "routed restore", func() error {
		var err error
		rep, err = s.cp.Resume(rec.ID)
		return err
	})
	s.setState(rec, stateRunning)
	if restoreErr != nil {
		s.mu.Lock()
		rec.Continuity = "FAIL"
		s.stats.ContinuityFail++
		s.mu.Unlock()
		return
	}
	// Continuity verdict.
	pass := true
	var why []string
	if rep.NewEpoch != rep.PriorEpoch {
		pass = false
		why = append(why, fmt.Sprintf("epoch bumped %d->%d (snapshot resume, no continuity)", rep.PriorEpoch, rep.NewEpoch))
	}
	body, ok := s.curlOnce(rec)
	if !ok {
		pass = false
		why = append(why, "endpoint not serving after resume")
	} else if got := parseCounter(body); got >= 0 && got < rec.preSuspendCount {
		pass = false
		why = append(why, fmt.Sprintf("tmpfs counter regressed %d->%d", rec.preSuspendCount, got))
	}
	s.mu.Lock()
	if pass {
		rec.Continuity = "PASS"
		s.stats.ContinuityPass++
	} else {
		rec.Continuity = "FAIL"
		s.stats.ContinuityFail++
	}
	s.mu.Unlock()
	s.record(Event{Time: time.Now(), Sandbox: rec.Name, Kind: "INFO",
		Detail: "continuity check: " + map[bool]string{true: "PASS", false: "FAIL — " + strings.Join(why, "; ")}[pass], OK: pass})
}

// stormOnce suspends rec, then fires a burst of concurrent endpoint
// requests at it: the resume proxy must single-flight one resume and answer
// every waiter with the guest's 200.
func (s *Sim) stormOnce(rec *SandboxRec, burst int) {
	if _, ok := s.curlOnce(rec); !ok {
		return
	}
	s.mu.Lock()
	rec.preSuspendCount = rec.Counter
	s.mu.Unlock()
	if err := s.timed(rec, "SUSPEND", "storm suspend", func() error {
		return s.cp.Suspend(rec.ID)
	}); err != nil {
		return
	}
	s.setState(rec, stateSuspd)

	start := time.Now()
	var wg sync.WaitGroup
	okCount := 0
	var okMu sync.Mutex
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status, body, err := s.cp.EndpointGet(rec.BindingID)
			ok := err == nil && status == 200 && strings.Contains(body, "hello from sandbox "+rec.Name)
			if ok {
				if n := parseCounter(body); n >= 0 && n < rec.preSuspendCount {
					ok = false // RAM regressed: not a continuity pass
				}
			}
			okMu.Lock()
			if ok {
				okCount++
			}
			okMu.Unlock()
		}(i)
	}
	wg.Wait()
	dur := time.Since(start).Milliseconds()
	pass := okCount == burst
	s.mu.Lock()
	if pass {
		s.stats.ContinuityPass++
		rec.Continuity = "PASS"
		s.stats.Restores++
	} else {
		s.stats.ContinuityFail++
		rec.Continuity = "FAIL"
		s.stats.RestoreFails++
	}
	rec.Counter = rec.preSuspendCount
	s.mu.Unlock()
	s.record(Event{Time: time.Now(), Sandbox: rec.Name, Kind: "RESTORE",
		Detail: fmt.Sprintf("storm resume: %d/%d burst requests 200 after single-flight resume", okCount, burst),
		DurMs:  dur, OK: pass})
	s.setState(rec, stateRunning)
}

func (s *Sim) setState(rec *SandboxRec, st string) {
	s.mu.Lock()
	rec.State = st
	s.mu.Unlock()
}

// Refresh pulls ground truth per sandbox (no list endpoint exists) plus
// control-plane health.
func (s *Sim) Refresh() {
	healthy := s.cp.Healthy()
	s.mu.Lock()
	s.stats.CPHealthy = healthy
	s.mu.Unlock()
	if !healthy {
		s.record(Event{Time: time.Now(), Kind: "ERROR", Detail: "control plane /healthz failing", OK: false})
		return
	}
	for _, rec := range s.sandboxesSnapshot() {
		info, err := s.cp.GetSandbox(rec.ID)
		if err != nil {
			s.record(Event{Time: time.Now(), Sandbox: rec.Name, Kind: "ERROR", Detail: "state refresh: " + err.Error(), OK: false})
			continue
		}
		s.mu.Lock()
		rec.State = info.ObservedState
		rec.Epoch = info.ExecutionEpoch
		rec.WorkspaceGen = info.WorkspaceGeneration
		s.mu.Unlock()
	}
}

func (s *Sim) sandboxesSnapshot() []*SandboxRec {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*SandboxRec{}, s.sandboxes...)
}

// Run starts the scenario goroutines.
func (s *Sim) Run() {
	// Ground-truth refresh.
	go s.loop(5*time.Second, 2*time.Second, func() { s.Refresh() })
	// Steady exec ticks, staggered per sandbox.
	for _, rec := range s.sandboxesSnapshot() {
		rec := rec
		go s.loop(4*time.Second, time.Duration(rand.Intn(3000))*time.Millisecond, func() {
			s.mu.Lock()
			st := rec.State
			s.mu.Unlock()
			if isLive(st) {
				s.execTick(rec)
			}
		})
		// Steady endpoint curls.
		go s.loop(7*time.Second, time.Duration(rand.Intn(4000))*time.Millisecond, func() {
			s.mu.Lock()
			st := rec.State
			s.mu.Unlock()
			if isLive(st) {
				s.curlOnce(rec)
			}
		})
	}
	switch s.scenario {
	case "churn":
		go s.loop(14*time.Second, 8*time.Second, func() {
			recs := s.sandboxesSnapshot()
			s.churnOnce(recs[rand.Intn(len(recs))])
		})
	case "storm":
		go s.loop(25*time.Second, 12*time.Second, func() {
			recs := s.sandboxesSnapshot()
			s.stormOnce(recs[rand.Intn(len(recs))], 6)
		})
	}
}

// loop runs fn every period+rand(period/2) with an initial delay.
func (s *Sim) loop(period, initialDelay time.Duration, fn func()) {
	t := time.NewTimer(initialDelay)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
		fn()
		jitter := time.Duration(rand.Int63n(int64(period)/2 + 1))
		t.Reset(period + jitter)
	}
}

// Stop halts all scenario goroutines.
func (s *Sim) Stop() { s.stopped.Do(func() { close(s.stop) }) }

// Summary renders the final soak-relevant tally (start, uptime, cycles,
// continuity pass/fail) for the log.
func (s *Sim) Summary() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("SUMMARY scenario=%s started=%s uptime=%ds restores=%d restore_fails=%d continuity_pass=%d continuity_fail=%d exec_ok=%d exec_fail=%d curl_ok=%d curl_fail=%d",
		s.scenario, s.started.Format(time.RFC3339), int64(time.Since(s.started).Seconds()),
		s.stats.Restores, s.stats.RestoreFails, s.stats.ContinuityPass, s.stats.ContinuityFail,
		s.stats.ExecOK, s.stats.ExecFail, s.stats.CurlOK, s.stats.CurlFail)
}

// StateJSON renders the /api/state payload.
func (s *Sim) StateJSON() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	byState := map[string]int{}
	for _, rec := range s.sandboxes {
		byState[rec.State]++
	}
	s.stats.ByState = byState
	s.stats.UptimeSeconds = int64(time.Since(s.started).Seconds())
	if len(s.latencies) > 0 {
		sorted := append([]int64{}, s.latencies...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		var sum int64
		for _, v := range sorted {
			sum += v
		}
		s.stats.AvgLatencyMs = sum / int64(len(sorted))
		s.stats.P95LatencyMs = sorted[(len(sorted)*95)/100]
	}
	payload := map[string]interface{}{
		"scenario":  s.scenario,
		"sandboxes": s.sandboxes,
		"events":    s.events.snapshot(),
		"stats":     s.stats,
	}
	data, _ := json.Marshal(payload)
	return data
}
