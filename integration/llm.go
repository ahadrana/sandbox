// Package integration holds the real-agent compatibility adapters (PLAN
// §15). THE SEAM: every adapter operates exclusively against the sandbox
// manager's public API (CreateSandbox/Materialize/StartExecution/
// CompleteExecution/CancelExecution/Suspend/Resume/RuntimeFiles/Outbox)
// plus the event consumer — no adapter ever references runtime-incarnation
// IDs, backend handles, or backend specifics. The prompt/context layer
// stays model- and backend-independent (INV-019, INV-020).
package integration

import (
	"fmt"
	"strings"

	"github.com/agent-sandbox/platform/api"
	sandboxmanager "github.com/agent-sandbox/platform/control-plane/sandbox-manager"
	"github.com/agent-sandbox/platform/domain"
)

// ToolCall is one model-requested action.
type ToolCall struct {
	Name    string            // "shell" | "write_file"
	Command string            // shell command
	Writes  map[string]string // write_file payload
}

// Turn is one scripted/model step: either a tool call or Done.
type Turn struct {
	Call *ToolCall
	Done bool
	Note string
}

// Observation is what the adapter returns to the model after a tool call.
type Observation struct {
	ExitCode int
	Output   string
	Note     string
}

// LLM is the model seam; ScriptedLLM stands in for a real model (no API
// calls exist in this environment).
type LLM interface {
	Next(obs *Observation) Turn
}

// ScriptedLLM replays a queue of turns and records observations.
type ScriptedLLM struct {
	Queue []Turn
	Seen  []Observation
	i     int
}

func (s *ScriptedLLM) Next(obs *Observation) Turn {
	if obs != nil {
		s.Seen = append(s.Seen, *obs)
	}
	if s.i >= len(s.Queue) {
		return Turn{Done: true}
	}
	t := s.Queue[s.i]
	s.i++
	return t
}

// AgentRuntime is the adapter runtime above the manager's public API.
type AgentRuntime struct {
	Mgr          *sandboxmanager.Manager
	TenantID     string
	PrincipalID  string
	OutputBudget int // max observation output bytes (0 = 4096)
}

const captureFile = "agent-last-output.txt"

func (a *AgentRuntime) budget() int {
	if a.OutputBudget > 0 {
		return a.OutputBudget
	}
	return 4096
}

// ExecShell maps a shell tool call to an execution and captures its output
// (redirected into the workspace, read back via the public API, truncated
// to the observation budget).
func (a *AgentRuntime) ExecShell(sandboxID, command string) (*domain.Execution, Observation, error) {
	op := domain.Operation{
		Command: fmt.Sprintf("( %s ) > %s 2>&1", command, captureFile),
	}
	return a.execOp(sandboxID, op)
}

// WriteFiles maps a write_file tool call.
func (a *AgentRuntime) WriteFiles(sandboxID string, writes map[string]string) (*domain.Execution, Observation, error) {
	return a.execOp(sandboxID, domain.Operation{Writes: writes})
}

func (a *AgentRuntime) execOp(sandboxID string, op domain.Operation) (*domain.Execution, Observation, error) {
	ex, err := a.Mgr.StartExecution(api.StartExecutionRequest{
		Version: api.SchemaVersionV1, SandboxID: sandboxID, TenantID: a.TenantID, PrincipalID: a.PrincipalID,
		Operation: op,
	})
	if err != nil {
		return nil, Observation{}, err
	}
	ex, err = a.Mgr.CompleteExecution(ex.ExecutionID)
	if err != nil {
		return nil, Observation{}, err
	}
	obs := Observation{}
	if ex.ExitCode != nil {
		obs.ExitCode = *ex.ExitCode
	}
	files, err := a.Mgr.RuntimeFiles(sandboxID)
	if err == nil {
		if out, ok := files[captureFile]; ok {
			obs.Output = truncate(out, a.budget())
			if len(out) > a.budget() {
				obs.Note = fmt.Sprintf("output truncated to %d bytes", a.budget())
			}
		} else if op.Command != "" {
			obs.Note = "command output unavailable on this backend"
		}
	}
	return ex, obs, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// RunLoop drives the model tool loop until the model is Done.
func (a *AgentRuntime) RunLoop(sandboxID string, llm LLM) ([]Observation, error) {
	var obs *Observation
	var out []Observation
	for {
		turn := llm.Next(obs)
		if turn.Done || turn.Call == nil {
			return out, nil
		}
		var o Observation
		var err error
		switch turn.Call.Name {
		case "shell":
			_, o, err = a.ExecShell(sandboxID, turn.Call.Command)
		case "write_file":
			_, o, err = a.WriteFiles(sandboxID, turn.Call.Writes)
		default:
			err = fmt.Errorf("unknown tool %q", turn.Call.Name)
		}
		if err != nil {
			return out, err
		}
		out = append(out, o)
		obs = &out[len(out)-1]
	}
}

// Steer cancels a running execution at a tool boundary (user steering);
// the model loop observes the cancellation on its next turn.
func (a *AgentRuntime) Steer(executionID string) (Observation, error) {
	ex, err := a.Mgr.CancelExecution(executionID)
	if err != nil {
		return Observation{}, err
	}
	return Observation{Note: "cancelled by user steer", ExitCode: exitCodeOf(ex)}, nil
}

func exitCodeOf(ex *domain.Execution) int {
	if ex.ExitCode != nil {
		return *ex.ExitCode
	}
	return -1
}

// TranslateEvent surfaces platform events to the agent runtime as
// actionable observations. An ExecutionStateReset becomes a "your
// processes are gone, restart services" descriptor (FR-EP-006).
func TranslateEvent(ev domain.Event) *Observation {
	switch ev.EventType {
	case domain.EventExecutionStateReset:
		return &Observation{Note: fmt.Sprintf(
			"execution state reset (epoch %v -> %v): volatile state lost (%v) — your processes are gone; restart services and re-establish listeners",
			ev.Payload["prior_epoch"], ev.Payload["new_epoch"], ev.Payload["lost_classes"])}
	case domain.EventSandboxSuspended:
		return &Observation{Note: "sandbox suspended: processes are paused or gone"}
	case domain.EventResourceLimitExceeded:
		return &Observation{Note: fmt.Sprintf("resource limit exceeded (%v): background processes were terminated", ev.Payload["resource"])}
	}
	return nil
}

// contains is a tiny helper for adapters that check file content.
func Contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
