package sandboxlab

import (
	"fmt"
	"testing"
	"time"
)

// contention_test.go — phase-6 proofs (ADR-010): the resource-contention
// model makes simulated timing reflect load. (1) N concurrent identical
// ops on a saturated host each stretch ~N×; (2) sharing is fair;
// (3) flat mode is unchanged (covered by the existing determinism test —
// all built-ins have no pools); (4) idle-VM background load slows ops;
// (5) an imbalanced resume storm produces p99 >> p50. The invariant
// engine stays clean everywhere.

// contentionScenario renders a one-host scenario JSON: create n materialized
// sandboxes, suspend them all, then resume them all in one parallel burst.
func contentionScenario(name string, n int, hosts string) *Scenario {
	sc := fmt.Sprintf(`{
  "name": %q, "seed": 7,
  "hosts": [%s],
  "steps": [
    {"op":"create_sandbox","count":%d,"save_as":"sb","materialize":true},
    {"op":"suspend","sandbox":"*"},
    {"op":"parallel","do":[{"op":"resume","sandbox":"*"}]}
  ],
  "assert": [
    {"check":"sandbox_live","sandbox":"*","eq":true},
    {"check":"violations","eq":0}
  ]
}`, name, hosts, n)
	s, err := ParseScenario([]byte(sc))
	if err != nil {
		panic(err)
	}
	return s
}

func restoreDurations(t *testing.T, res *Result, hostID string) []time.Duration {
	t.Helper()
	h, ok := res.Fleet.Hosts[hostID]
	if !ok {
		t.Fatalf("no host %s", hostID)
	}
	ds := h.OpDur["restore"]
	if len(ds) == 0 {
		t.Fatalf("host %s recorded no restore durations", hostID)
	}
	return ds
}

// (1) Serialization stretch: 8 concurrent restores on a 1-vCPU host each
// take ~8× the uncontended 40ms (vs the flat model's 1×).
func TestContentionStretch(t *testing.T) {
	host := `"id":"h1","slots":16,"memory":268435456,"vcpu":1,"vm_idle_vcpu":0,"latencies":{"create_ms":20,"snapshot_ms":30,"restore_ms":40,"terminate_ms":10}`
	single, err := RunScenario(contentionScenario("stretch-single", 1, "{"+host+"}"))
	if err != nil {
		t.Fatal(err)
	}
	base := restoreDurations(t, single, "h1")[0]
	if base != 40*time.Millisecond {
		t.Fatalf("uncontended restore %v, want exactly 40ms (flat-latency compat)", base)
	}
	storm, err := RunScenario(contentionScenario("stretch-8", 8, "{"+host+"}"))
	if err != nil {
		t.Fatal(err)
	}
	if !storm.Pass() {
		t.Fatalf("storm scenario failed: %v", storm.AssertFailure)
	}
	ds := restoreDurations(t, storm, "h1")
	if len(ds) != 8 {
		t.Fatalf("8 restores, got %d", len(ds))
	}
	for _, d := range ds {
		f := float64(d) / float64(base)
		if f < 7.5 || f > 8.5 {
			t.Fatalf("restore %v: stretch %.2f×, want ~8×", d, f)
		}
	}
	t.Logf("stretch: uncontended %v, 8 concurrent each %v (%.1f×)", base, ds[0], float64(ds[0])/float64(base))
}

// (2) Fairness: two overlapping restores get ~equal share — equal work,
// equal start ⇒ equal completion.
func TestContentionFairness(t *testing.T) {
	host := `"id":"h1","slots":4,"memory":268435456,"vcpu":1,"vm_idle_vcpu":0,"latencies":{"restore_ms":40,"create_ms":20,"snapshot_ms":30}`
	res, err := RunScenario(contentionScenario("fair-2", 2, "{"+host+"}"))
	if err != nil {
		t.Fatal(err)
	}
	ds := restoreDurations(t, res, "h1")
	if len(ds) != 2 {
		t.Fatalf("2 restores, got %d", len(ds))
	}
	skew := float64(ds[0]-ds[1]) / float64(ds[0])
	if skew < -0.02 || skew > 0.02 {
		t.Fatalf("unfair: %v vs %v (skew %.3f)", ds[0], ds[1], skew)
	}
	if ds[0] < 75*time.Millisecond || ds[0] > 85*time.Millisecond {
		t.Fatalf("2-way shared restore %v, want ~80ms", ds[0])
	}
}

// (4) Background load: a host with idle VMs restores slower than an empty
// one (idle VMs consume vCPU share).
func TestContentionIdleLoad(t *testing.T) {
	host := `"id":"h1","slots":8,"memory":268435456,"vcpu":1,"vm_idle_vcpu":0.1,"latencies":{"restore_ms":40,"create_ms":20,"snapshot_ms":30}`
	// Empty-ish host: the only VM is the one being restored.
	solo, err := RunScenario(contentionScenario("idle-solo", 1, "{"+host+"}"))
	if err != nil {
		t.Fatal(err)
	}
	base := restoreDurations(t, solo, "h1")[0]
	// Loaded host: 5 sandboxes created, 4 stay live (idle load 0.4 cores),
	// one is suspended and resumed.
	sc := `{
  "name": "idle-loaded", "seed": 7,
  "hosts": [{` + host + `}],
  "steps": [
    {"op":"create_sandbox","count":5,"save_as":"sb","materialize":true},
    {"op":"suspend","sandbox":"sb-4"},
    {"op":"resume","sandbox":"sb-4"}
  ],
  "assert": [{"check":"violations","eq":0}]
}`
	loaded, err := RunScenario(mustParse(t, sc))
	if err != nil {
		t.Fatal(err)
	}
	d := restoreDurations(t, loaded, "h1")[0]
	// share = 1/(1+0.4) → 56ms expected
	if d < time.Duration(float64(base)*1.3) {
		t.Fatalf("restore under idle load %v, want > 1.3× uncontended %v", d, base)
	}
	t.Logf("idle load: uncontended %v, with 4 idle VMs %v (%.2f×)", base, d, float64(d)/float64(base))
}

// (5) Resume storm with contention on imbalanced hosts: restores on the
// saturated host stretch far beyond those on the big host ⇒ p99 ≫ p50.
func TestContentionResumeStormStats(t *testing.T) {
	hosts := `{"id":"h-slow","slots":60,"memory":268435456,"vcpu":1,"vm_idle_vcpu":0,"latencies":{"restore_ms":40,"create_ms":20,"snapshot_ms":30}},
	          {"id":"h-fast","slots":60,"memory":268435456,"vcpu":64,"io_mbps":50000,"net_mbps":50000,"vm_idle_vcpu":0,"latencies":{"restore_ms":40,"create_ms":20,"snapshot_ms":30}}`
	res, err := RunScenario(contentionScenario("storm-contention", 100, hosts))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Pass() {
		t.Fatalf("storm failed: %v", res.AssertFailure)
	}
	p := res.OpStats["restore"]
	t.Logf("resume-storm with contention: restore p50=%v p99=%v (%d ops, slow host %d, fast host %d)",
		p[0], p[1],
		len(res.Fleet.Hosts["h-slow"].OpDur["restore"])+len(res.Fleet.Hosts["h-fast"].OpDur["restore"]),
		len(res.Fleet.Hosts["h-slow"].OpDur["restore"]), len(res.Fleet.Hosts["h-fast"].OpDur["restore"]))
	if p[1] < p[0]*3 {
		t.Fatalf("p99 %v not >= 3× p50 %v — contention produced no spread", p[1], p[0])
	}
	if len(res.Fleet.Hosts["h-slow"].OpDur["restore"]) == 0 || len(res.Fleet.Hosts["h-fast"].OpDur["restore"]) == 0 {
		t.Fatalf("storm did not spread across both hosts")
	}
}

// Determinism: contention traces are seed-identical across runs.
func TestContentionDeterminism(t *testing.T) {
	host := `"id":"h1","slots":16,"memory":268435456,"vcpu":1,"latencies":{"restore_ms":40,"create_ms":20,"snapshot_ms":30}`
	a, err := RunScenario(contentionScenario("det", 8, "{"+host+"}"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := RunScenario(contentionScenario("det", 8, "{"+host+"}"))
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Trace) != string(b.Trace) {
		t.Fatalf("contention traces diverge")
	}
}

func mustParse(t *testing.T, s string) *Scenario {
	t.Helper()
	sc, err := ParseScenario([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return sc
}
