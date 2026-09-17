package sandboxlab

import (
	"embed"
	"fmt"
	"os"
	"sort"
	"strings"
)

// builtins.go — the embedded scenario library: sandboxlab/scenarios/*.json,
// compiled into both the test suite and the sandbox-lab runner.

//go:embed scenarios
var scenarioFS embed.FS

// builtinNames lists the embedded scenario names (file basename minus .json).
func builtinNames() ([]string, error) {
	entries, err := scenarioFS.ReadDir("scenarios")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			out = append(out, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	sort.Strings(out)
	return out, nil
}

// builtinScenario returns the raw JSON of an embedded scenario by name.
func builtinScenario(name string) ([]byte, error) {
	data, err := scenarioFS.ReadFile("scenarios/" + name + ".json")
	if err != nil {
		names, _ := builtinNames()
		return nil, fmt.Errorf("unknown built-in scenario %q (have: %s)", name, strings.Join(names, ", "))
	}
	return data, nil
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
