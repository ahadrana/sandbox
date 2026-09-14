package integration

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	eventservice "github.com/agent-sandbox/platform/control-plane/event-service"
	"github.com/agent-sandbox/platform/domain"
	"time"
)

// --- OpenHands-style execution adapter (PLAN §15.2) ---

// OHAction is an OpenHands-ish action: cmd / write / read / finish.
type OHAction struct {
	Kind    string // "cmd" | "write" | "read" | "finish"
	Command string
	Path    string
	Content string
}

// RunActions maps actions onto sandbox operations until a finish action.
// File writes go through workspace writes; shell runs as executions; read
// returns the workspace view via the public API.
func (a *AgentRuntime) RunActions(sandboxID string, actions []OHAction) ([]Observation, error) {
	var out []Observation
	for _, act := range actions {
		switch act.Kind {
		case "cmd":
			_, obs, err := a.ExecShell(sandboxID, act.Command)
			if err != nil {
				return out, err
			}
			out = append(out, obs)
		case "write":
			_, obs, err := a.WriteFiles(sandboxID, map[string]string{act.Path: act.Content})
			if err != nil {
				return out, err
			}
			out = append(out, obs)
		case "read":
			files, err := a.Mgr.RuntimeFiles(sandboxID)
			if err != nil {
				return out, err
			}
			content, ok := files[act.Path]
			if !ok {
				out = append(out, Observation{Note: fmt.Sprintf("read: %s not found", act.Path)})
				continue
			}
			out = append(out, Observation{Output: truncate(content, a.budget())})
		case "finish":
			return out, nil
		default:
			return out, fmt.Errorf("unknown action kind %q", act.Kind)
		}
	}
	return out, nil
}

// --- Shell workload trace replay (PLAN §15.3) ---

// TraceStep is one JSON-lines trace record.
type TraceStep struct {
	Op         string `json:"op"` // "shell" | "write" | "expect_file"
	Command    string `json:"command,omitempty"`
	Path       string `json:"path,omitempty"`
	Content    string `json:"content,omitempty"`
	Contains   string `json:"contains,omitempty"`
	ExpectExit *int   `json:"expect_exit,omitempty"`
}

// ReplayTrace executes a recorded shell workload against a sandbox,
// verifying declared expectations as it goes.
func (a *AgentRuntime) ReplayTrace(sandboxID string, r io.Reader) ([]Observation, error) {
	var out []Observation
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		var step TraceStep
		if err := json.Unmarshal(sc.Bytes(), &step); err != nil {
			return out, fmt.Errorf("trace line %d: %w", line, err)
		}
		switch step.Op {
		case "shell":
			_, obs, err := a.ExecShell(sandboxID, step.Command)
			if err != nil {
				return out, fmt.Errorf("trace line %d: %w", line, err)
			}
			if step.ExpectExit != nil && obs.ExitCode != *step.ExpectExit {
				return out, fmt.Errorf("trace line %d: exit = %d, want %d", line, obs.ExitCode, *step.ExpectExit)
			}
			out = append(out, obs)
		case "write":
			if _, _, err := a.WriteFiles(sandboxID, map[string]string{step.Path: step.Content}); err != nil {
				return out, fmt.Errorf("trace line %d: %w", line, err)
			}
		case "expect_file":
			files, err := a.Mgr.RuntimeFiles(sandboxID)
			if err != nil {
				return out, fmt.Errorf("trace line %d: %w", line, err)
			}
			content, ok := files[step.Path]
			if !ok {
				return out, fmt.Errorf("trace line %d: %s missing", line, step.Path)
			}
			if step.Contains != "" && !Contains(content, step.Contains) {
				return out, fmt.Errorf("trace line %d: %s does not contain %q", line, step.Path, step.Contains)
			}
		default:
			return out, fmt.Errorf("trace line %d: unknown op %q", line, step.Op)
		}
	}
	return out, sc.Err()
}

// --- A2A-style notification (PLAN §15.4) ---

// WaitForEvent blocks the AGENT side on its durable event cursor until a
// matching event arrives — the Atlassian-style wake: the platform never
// polls; the agent sleeps on its consumer and wakes on the event.
func WaitForEvent(c *eventservice.Consumer, o *eventservice.Outbox, timeout time.Duration, pred func(domain.Event) bool) (domain.Event, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, ev := range c.Poll(o) {
			if pred(ev) {
				return ev, nil
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	return domain.Event{}, fmt.Errorf("timed out waiting for event")
}

// --- Cursor-like coordinator (PLAN §15.5) ---

// CoordinatorTask is one unit of coordinator work.
type CoordinatorTask struct {
	TaskID       string
	ShareSandbox bool   // policy: share the group sandbox vs separate
	Group        string // share group key
}

// Coordinator fans tasks out over sandboxes per the shared/separate
// policy, driven purely by event subscriptions.
type Coordinator struct {
	Runtime *AgentRuntime
	shared  map[string]string // group -> sandboxID
}

func NewCoordinator(rt *AgentRuntime) *Coordinator {
	return &Coordinator{Runtime: rt, shared: map[string]string{}}
}

// SandboxFor resolves the sandbox for a task: shared-group tasks reuse the
// group sandbox; others get their own.
func (c *Coordinator) SandboxFor(task CoordinatorTask, existing map[string]string, create func() (string, error)) (sandboxID string, shared bool, err error) {
	if task.ShareSandbox {
		if id, ok := c.shared[task.Group]; ok {
			return id, true, nil
		}
		id, err := create()
		if err != nil {
			return "", false, err
		}
		c.shared[task.Group] = id
		return id, true, nil
	}
	if id, ok := existing[task.TaskID]; ok {
		return id, false, nil
	}
	id, err := create()
	if err != nil {
		return "", false, err
	}
	return id, false, nil
}
