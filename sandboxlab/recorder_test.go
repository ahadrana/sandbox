package sandboxlab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-sandbox/platform/api"
)

// recorder_test.go — phase-5 artifact tests: JSONL well-formedness,
// snapshot reconstruction against live engine state, render self-
// containment, JS syntax (when node is available), the traffic-resume-race
// round-trip, and the scale smoke with the recorder attached.

func mustRun(t *testing.T, name string) *Result {
	t.Helper()
	sc, err := LoadScenario(name)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	res, err := RunScenario(sc)
	if err != nil {
		t.Fatalf("run %s: %v", name, err)
	}
	return res
}

// Every line of the v2 artifact parses as JSON, the record-type sequence is
// header, events, report, and seq numbers are monotonic.
func TestTraceV2JSONLParses(t *testing.T) {
	res := mustRun(t, "traffic-resume-race")
	lines := strings.Split(strings.TrimRight(string(res.TraceV2), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("trace v2 has %d lines, want >= 3", len(lines))
	}
	var prevSeq uint64
	for i, line := range lines {
		var probe struct {
			Type string `json:"type"`
			Seq  uint64 `json:"seq"`
		}
		if err := json.Unmarshal([]byte(line), &probe); err != nil {
			t.Fatalf("line %d not JSON: %v", i+1, err)
		}
		switch i {
		case 0:
			if probe.Type != "header" {
				t.Fatalf("line 1 type %q, want header", probe.Type)
			}
		case len(lines) - 1:
			if probe.Type != "report" {
				t.Fatalf("last line type %q, want report", probe.Type)
			}
		default:
			if probe.Type != "event" {
				t.Fatalf("line %d type %q, want event", i+1, probe.Type)
			}
			if probe.Seq < prevSeq {
				t.Fatalf("line %d seq regressed %d -> %d", i+1, prevSeq, probe.Seq)
			}
			prevSeq = probe.Seq
		}
	}
	if _, err := ParseTraceV2(res.TraceV2); err != nil {
		t.Fatalf("ParseTraceV2: %v", err)
	}
}

// The recorder's snapshots must reconstruct the live engine state at that
// point: spot-check the suspend/resume sequence of traffic-resume-race, and
// compare the report record's world against a fresh snapshot taken after
// the run.
func TestTraceV2Reconstruction(t *testing.T) {
	res := mustRun(t, "traffic-resume-race")
	tr, err := ParseTraceV2(res.TraceV2)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	find := func(labelPrefix string) *WorldSnap {
		t.Helper()
		for _, ev := range tr.Events {
			if strings.HasPrefix(ev.Label, labelPrefix) && ev.World != nil {
				return ev.World
			}
		}
		t.Fatalf("no snapshot-bearing event with label prefix %q", labelPrefix)
		return nil
	}
	sandboxByLabel := func(w *WorldSnap, label string) SandboxSnap {
		t.Helper()
		for _, sb := range w.Sandboxes {
			if sb.Label == label {
				return sb
			}
		}
		t.Fatalf("sandbox %q not in snapshot", label)
		return SandboxSnap{}
	}
	// traffic-resume-race suspends "web" then races traffic into a resume.
	atSuspend := sandboxByLabel(find("suspend web"), "web")
	if atSuspend.State != "SUSPENDED" {
		t.Fatalf("at 'suspend web' web is %s, want SUSPENDED", atSuspend.State)
	}
	if atSuspend.Checkpoint == "" {
		t.Fatalf("suspended web carries no checkpoint ref")
	}
	if atSuspend.Host != "" {
		t.Fatalf("suspended web still placed on %s (INV-002)", atSuspend.Host)
	}
	atTraffic := sandboxByLabel(find("traffic web"), "web")
	switch atTraffic.State {
	case "RUNNING", "QUIESCENT", "BACKGROUND_ACTIVE":
	default:
		t.Fatalf("at 'traffic web' web is %s, want live", atTraffic.State)
	}
	if atTraffic.Epoch != atSuspend.Epoch {
		t.Fatalf("web epoch %d after clean resume, want preserved %d", atTraffic.Epoch, atSuspend.Epoch)
	}

	// The report record's world equals a fresh post-run snapshot.
	fresh := SnapshotWorld(res.Fleet, nil)
	if len(tr.Final.Sandboxes) != len(fresh.Sandboxes) {
		t.Fatalf("final world has %d sandboxes, live has %d", len(tr.Final.Sandboxes), len(fresh.Sandboxes))
	}
	for i, sb := range fresh.Sandboxes {
		got := tr.Final.Sandboxes[i]
		if got.ID != sb.ID || got.State != sb.State || got.Epoch != sb.Epoch ||
			got.WSGen != sb.WSGen || got.Host != sb.Host || got.Incarnation != sb.Incarnation {
			t.Fatalf("final world sandbox %d mismatch: recorded %+v live %+v", i, got, sb)
		}
	}
	if len(tr.Final.Hosts) != len(fresh.Hosts) {
		t.Fatalf("final world has %d hosts, live has %d", len(tr.Final.Hosts), len(fresh.Hosts))
	}
	for i, h := range fresh.Hosts {
		got := tr.Final.Hosts[i]
		if got.ID != h.ID || got.UsedSlots != h.UsedSlots || got.UsedMem != h.UsedMem || got.Down != h.Down {
			t.Fatalf("final world host %d mismatch: recorded %+v live %+v", i, got, h)
		}
	}
}

// Single-flight round-trip: the v2 trace of traffic-resume-race carries the
// resume sequence and zero violations, its report record carries the
// engine's verdict, and every causal parent resolves to an earlier seq.
func TestTraceV2RoundTrip(t *testing.T) {
	res := mustRun(t, "traffic-resume-race")
	tr, err := ParseTraceV2(res.TraceV2)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sawSuspend, sawTraffic := false, false
	for _, ev := range tr.Events {
		if ev.Violation != nil {
			t.Fatalf("unexpected violation record at seq %d: %+v", ev.Seq, ev.Violation)
		}
		if strings.HasPrefix(ev.Label, "suspend web") {
			sawSuspend = true
		}
		if strings.HasPrefix(ev.Label, "traffic web") {
			sawTraffic = true
			if !strings.Contains(ev.Label, "all-200=true") {
				t.Fatalf("traffic note %q does not record all-200", ev.Label)
			}
		}
	}
	if !sawSuspend || !sawTraffic {
		t.Fatalf("resume sequence incomplete in trace (suspend=%v traffic=%v)", sawSuspend, sawTraffic)
	}
	if res.ResumeOps != 1 {
		t.Fatalf("resume ops %d, want 1 (single-flight)", res.ResumeOps)
	}
	if len(tr.Report) == 0 {
		t.Fatalf("report record carries no entries")
	}
	for _, e := range tr.Report {
		if e.Status == StatusViolation {
			t.Fatalf("report entry %s is a violation in a clean run", e.ID)
		}
	}
	seqs := map[uint64]bool{}
	for _, ev := range tr.Events {
		seqs[ev.Seq] = true
	}
	for _, ev := range tr.Events {
		if ev.Parent != 0 && (!seqs[ev.Parent] || ev.Parent >= ev.Seq) {
			t.Fatalf("event seq %d has dangling parent %d", ev.Seq, ev.Parent)
		}
	}
}

// The baked replay page must be fully self-contained: no external URLs, no
// <link>, no <script src>, and the trace data embedded.
func TestRenderSelfContained(t *testing.T) {
	res := mustRun(t, "traffic-resume-race")
	page, err := RenderReplayHTML(res.TraceV2)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(page)
	for _, bad := range []string{"http://", "https://", "<link", "<script src", "src=\"//", "href=\"//"} {
		if strings.Contains(s, bad) {
			t.Fatalf("rendered page references external resource %q", bad)
		}
	}
	if !strings.Contains(s, "sandboxlab-trace-jsonl v2") {
		t.Fatalf("rendered page does not embed the trace")
	}
	if strings.Contains(s, traceMarker) {
		t.Fatalf("rendered page still contains the injection marker")
	}
	// ReplayHandler serves the identical bytes.
	h, err := ReplayHandler(res.TraceV2)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	rec := &fakeResponseWriter{header: http.Header{}}
	h.ServeHTTP(rec, nil)
	if !bytes.Equal(rec.body, page) {
		t.Fatalf("handler serves different bytes than render")
	}
}

type fakeResponseWriter struct {
	header http.Header
	body   []byte
}

func (w *fakeResponseWriter) Header() http.Header { return w.header }
func (w *fakeResponseWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}
func (w *fakeResponseWriter) WriteHeader(int) {}

// The inline script must be syntactically valid JS. Skipped without node.
func TestReplayJSSyntax(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available")
	}
	res := mustRun(t, "traffic-resume-race")
	page, err := RenderReplayHTML(res.TraceV2)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(page)
	start := strings.Index(s, "<script>")
	end := strings.LastIndex(s, "</script>")
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("no script block found")
	}
	js := s[start+len("<script>") : end]
	tmp := filepath.Join(t.TempDir(), "inline.js")
	if err := os.WriteFile(tmp, []byte(js), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "--check", tmp).CombinedOutput()
	if err != nil {
		t.Fatalf("node --check: %v\n%s", err, out)
	}
}

// The recorder at scale: 10k sandboxes must stay under the 60s smoke
// budget with the recorder attached. This mirrors TestScaleSmoke; the
// phase-3 engine's per-event snapshot blowup is the failure mode the
// adaptive stride guards against.
func TestScaleSmokeWithRecorder(t *testing.T) {
	const logical, liveN = 10000, 200
	sf := New(Config{
		Seed:        17,
		Hosts:       hostSpecs(20, 10, 1<<20, factsA, Latencies{}),
		TickCadence: time.Second,
	})
	rec := AttachRecorder(sf, nil)
	wallStart := time.Now()
	rng := sf.Kernel.Rand()
	at := time.Duration(0)
	var created []string
	for i := 0; i < logical; i++ {
		at += time.Duration(rng.Intn(100)) * time.Microsecond
		sf.Kernel.At(at, fmt.Sprintf("create-%d", i), func() {
			sb, err := sf.Mgr.CreateSandbox(api.CreateSandboxRequest{Version: api.SchemaVersionV1, TenantID: "t1", TaskRef: "bulk"})
			if err != nil {
				t.Errorf("create: %v", err)
				return
			}
			created = append(created, sb.SandboxID)
		})
	}
	sf.Kernel.RunUntil(10 * time.Minute)
	live := created[:liveN]
	for _, sbID := range live {
		if _, err := sf.Mgr.Materialize(sbID); err != nil {
			t.Fatalf("materialize %s: %v", sbID, err)
		}
	}
	for _, id := range live {
		if err := sf.Mgr.Suspend(id); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range live {
		if _, err := sf.Mgr.Resume(id); err != nil {
			t.Fatal(err)
		}
	}
	report := sf.InvariantReport()
	artifact := rec.Artifact("scale-smoke", 17, report)
	wall := time.Since(wallStart)
	t.Logf("scale smoke with recorder: %d logical, %d live, %d events, artifact %d bytes in %v wall",
		logical, liveN, sf.Kernel.Fired(), len(artifact), wall)
	if wall > 60*time.Second {
		t.Fatalf("scale smoke with recorder took %v wall, want < 60s", wall)
	}
	tr, err := ParseTraceV2(artifact)
	if err != nil {
		t.Fatalf("artifact parses: %v", err)
	}
	if len(tr.Final.Sandboxes) != logical {
		t.Fatalf("final world has %d sandboxes, want %d", len(tr.Final.Sandboxes), logical)
	}
	if _, v, _, _ := report.Counts(); v != 0 {
		t.Fatalf("%d invariant violations", v)
	}
}
