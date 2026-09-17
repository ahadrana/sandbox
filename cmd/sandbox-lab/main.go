// sandbox-lab is the SandboxLab CI runner (ADR-010 phase 4): it executes
// declarative scenario files against the real control plane on a virtual
// clock and prints a verdict block.
//
//	sandbox-lab run <scenario.json|builtin-name> [-trace out.simtrace] [-trace2 out.simtrace.jsonl]
//	sandbox-lab run-all <dir>
//	sandbox-lab list
//	sandbox-lab render <trace.simtrace.jsonl> -o out.html
//	sandbox-lab replay <trace.simtrace.jsonl> [-addr :8080]
//
// Exit code 0 = PASS, 1 = FAIL or error.
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/agent-sandbox/platform/sandboxlab"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 1
	}
	switch args[0] {
	case "run":
		return cmdRun(args[1:])
	case "run-all":
		return cmdRunAll(args[1:])
	case "render":
		return cmdRender(args[1:])
	case "replay":
		return cmdReplay(args[1:])
	case "list", "-list", "--list":
		for _, n := range sandboxlab.ScenarioNames() {
			fmt.Println(n)
		}
		return 0
	default:
		usage()
		return 1
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  sandbox-lab run <scenario.json|builtin-name> [-trace out.simtrace] [-trace2 out.simtrace.jsonl]
  sandbox-lab run-all <dir>
  sandbox-lab list
  sandbox-lab render <trace.simtrace.jsonl> -o out.html   bake a self-contained replay page
  sandbox-lab replay <trace.simtrace.jsonl> [-addr :8080] serve the replay page over HTTP`)
}

func cmdRun(args []string) int {
	var target, tracePath, trace2Path string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-trace":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "-trace needs a path")
				return 1
			}
			tracePath = args[i]
		case "-trace2":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "-trace2 needs a path")
				return 1
			}
			trace2Path = args[i]
		default:
			target = args[i]
		}
	}
	if target == "" {
		usage()
		return 1
	}
	res, code := runOne(target)
	if tracePath != "" && res != nil {
		if err := os.WriteFile(tracePath, res.Trace, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "write trace: %v\n", err)
			return 1
		}
		fmt.Printf("trace written: %s (%d bytes)\n", tracePath, len(res.Trace))
	}
	if trace2Path != "" && res != nil {
		if err := os.WriteFile(trace2Path, res.TraceV2, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "write trace2: %v\n", err)
			return 1
		}
		fmt.Printf("trace v2 written: %s (%d bytes)\n", trace2Path, len(res.TraceV2))
	}
	return code
}

// cmdRender bakes a v2 trace into a self-contained HTML replay page that
// works from file:// (no server, no external resources).
func cmdRender(args []string) int {
	var target, out string
	for i := 0; i < len(args); i++ {
		if args[i] == "-o" {
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "-o needs a path")
				return 1
			}
			out = args[i]
		} else {
			target = args[i]
		}
	}
	if target == "" || out == "" {
		usage()
		return 1
	}
	data, err := os.ReadFile(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	page, err := sandboxlab.RenderReplayHTML(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "render: %v\n", err)
		return 1
	}
	if err := os.WriteFile(out, page, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		return 1
	}
	fmt.Printf("replay page written: %s (%d bytes) — open in any browser\n", out, len(page))
	return 0
}

// cmdReplay serves the baked replay page over HTTP.
func cmdReplay(args []string) int {
	var target, addr string
	for i := 0; i < len(args); i++ {
		if args[i] == "-addr" {
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "-addr needs a value")
				return 1
			}
			addr = args[i]
		} else {
			target = args[i]
		}
	}
	if target == "" {
		usage()
		return 1
	}
	if addr == "" {
		addr = ":8080"
	}
	data, err := os.ReadFile(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	h, err := sandboxlab.ReplayHandler(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: %v\n", err)
		return 1
	}
	fmt.Printf("serving replay of %s on http://localhost%s\n", target, addr)
	if err := http.ListenAndServe(addr, h); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runOne(target string) (*sandboxlab.Result, int) {
	sc, err := sandboxlab.LoadScenario(target)
	if err != nil {
		fmt.Printf("--- %s\nFAIL\nload: %v\n", target, err)
		return nil, 1
	}
	res, err := sandboxlab.RunScenario(sc)
	if err != nil {
		fmt.Printf("--- %s\nFAIL\nrun: %v\n", target, err)
		return nil, 1
	}
	fmt.Println("---", sc.Name)
	fmt.Println(res.Verdict())
	if !res.Pass() {
		return res, 1
	}
	return res, 0
}

func cmdRunAll(args []string) int {
	if len(args) != 1 {
		usage()
		return 1
	}
	dir := args[0]
	var names []string
	if dir == "builtin" || dir == "builtins" {
		names = sandboxlab.ScenarioNames()
	} else {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") {
				names = append(names, filepath.Join(dir, e.Name()))
			}
		}
		sort.Strings(names)
	}
	if len(names) == 0 {
		fmt.Println("no scenarios found")
		return 1
	}
	failures := 0
	for _, n := range names {
		_, code := runOne(n)
		if code != 0 {
			failures++
		}
	}
	fmt.Printf("=== run-all: %d scenarios, %d failed\n", len(names), failures)
	if failures > 0 {
		return 1
	}
	return 0
}
