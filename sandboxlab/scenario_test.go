package sandboxlab

import (
	"bytes"
	"strings"
	"testing"
)

// TestBuiltinScenariosPass runs every embedded scenario through the
// declarative runner — so `go test ./...` exercises the whole library.
func TestBuiltinScenariosPass(t *testing.T) {
	names := ScenarioNames()
	if len(names) == 0 {
		t.Fatal("no built-in scenarios embedded")
	}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			sc, err := LoadScenario(n)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			res, err := RunScenario(sc)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			t.Logf("\n%s", res.Verdict())
			if !res.Pass() {
				t.Fatalf("scenario failed:\n%s", res.Verdict())
			}
		})
	}
}

// TestScenarioParseErrors: malformed scenarios fail loudly and specifically.
func TestScenarioParseErrors(t *testing.T) {
	cases := []struct {
		name, json, wantErr string
	}{
		{"bad json", `{`, "scenario JSON"},
		{"no name", `{"hosts":[{"id":"h","slots":1,"memory":1024}]}`, "missing name"},
		{"no hosts", `{"name":"x"}`, "no hosts"},
		{"dup host", `{"name":"x","hosts":[{"id":"h","slots":1,"memory":1024},{"id":"h","slots":1,"memory":1024}]}`, "duplicate host"},
		{"no slots", `{"name":"x","hosts":[{"id":"h","memory":1024}]}`, "slots"},
		{"unknown field", `{"name":"x","hosts":[{"id":"h","slots":1,"memory":1024}],"bogus":1}`, "unknown field"},
		{"unknown step", `{"name":"x","hosts":[{"id":"h","slots":1,"memory":1024}],"steps":[{"op":"nuke"}]}`, `unknown step op "nuke"`},
		{"bad host ref", `{"name":"x","hosts":[{"id":"h","slots":1,"memory":1024}],"steps":[{"op":"kill_host","host":"ghost"}]}`, `unknown host "ghost"`},
		{"unknown assert", `{"name":"x","hosts":[{"id":"h","slots":1,"memory":1024}],"assert":[{"check":"vibes","eq":0}]}`, `unknown assert check "vibes"`},
		{"assert no operator", `{"name":"x","hosts":[{"id":"h","slots":1,"memory":1024}],"assert":[{"check":"violations"}]}`, "needs one of eq/le/ge"},
	}
	for _, tc := range cases {
		_, err := ParseScenario([]byte(tc.json))
		if err == nil {
			t.Fatalf("%s: expected error containing %q, got nil", tc.name, tc.wantErr)
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: error %q does not contain %q", tc.name, err, tc.wantErr)
		}
	}
}

// TestScenarioAssertionFailureReadable: a deliberately wrong assertion
// fails the run with a readable message naming the check and the values.
func TestScenarioAssertionFailureReadable(t *testing.T) {
	sc, err := ParseScenario([]byte(`{
	  "name": "failing-on-purpose", "seed": 1,
	  "hosts": [{"id": "h1", "slots": 2, "memory": 1048576}],
	  "steps": [{"op": "create_sandbox", "save_as": "v", "materialize": true}],
	  "assert": [{"check": "epoch", "sandbox": "v", "eq": 99}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunScenario(sc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Pass() {
		t.Fatal("scenario with epoch==99 assertion passed")
	}
	if len(res.AssertFailure) != 1 || !strings.Contains(res.AssertFailure[0], "epoch") ||
		!strings.Contains(res.AssertFailure[0], "99") {
		t.Fatalf("unreadable assertion failure: %+v", res.AssertFailure)
	}
	if !strings.Contains(res.Verdict(), "FAIL") {
		t.Fatalf("verdict should say FAIL: %s", res.Verdict())
	}
}

// TestScenarioTraceDeterminism: the same scenario file runs twice to a
// byte-identical trace artifact (header included).
func TestScenarioTraceDeterminism(t *testing.T) {
	run := func() []byte {
		sc, err := LoadScenario("resume-storm")
		if err != nil {
			t.Fatal(err)
		}
		res, err := RunScenario(sc)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Pass() {
			t.Fatalf("resume-storm failed:\n%s", res.Verdict())
		}
		return res.Trace
	}
	a, b := run(), run()
	if !bytes.Equal(a, b) {
		la, lb := strings.Split(string(a), "\n"), strings.Split(string(b), "\n")
		for i := 0; i < len(la) && i < len(lb); i++ {
			if la[i] != lb[i] {
				t.Fatalf("trace diverged at line %d:\n a: %s\n b: %s", i, la[i], lb[i])
			}
		}
		t.Fatalf("trace length diverged: %d vs %d", len(a), len(b))
	}
	if !strings.HasPrefix(string(a), "# sandboxlab-trace v1\n# scenario: resume-storm\n# seed: 11\n") {
		t.Fatal("trace artifact missing self-describing header")
	}
}
