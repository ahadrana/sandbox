// Package network is the simulated gateway routing layer and the egress
// policy engine (PLAN §12). The gateway is the routing DECISION layer only —
// no real TCP proxy; the fail-closed decision is the contract. Egress
// evaluation produces allow/deny decisions plus an audit record; host-level
// packet enforcement for the local backend is a declared capability gap
// (the isolated backend denies all egress via bwrap --unshare-net).
package network

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/agent-sandbox/platform/domain"
)

// EgressPolicy is an allow/deny host-list policy with a default action.
type EgressPolicy struct {
	DefaultAllow bool
	Allow        []string
	Deny         []string
}

// AlwaysDenied destinations are cloud metadata and cluster API endpoints;
// no policy may permit them (FR-SEC-001).
var AlwaysDenied = []string{"169.254.169.254", "kubernetes.default.svc"}

// EgressDecision is one evaluated destination plus its audit record.
type EgressDecision struct {
	Destination string    `json:"destination"`
	Allowed     bool      `json:"allowed"`
	Reason      string    `json:"reason"`
	At          time.Time `json:"at"`
}

func hostMatches(list []string, dest string) bool {
	for _, entry := range list {
		if entry == "*" || entry == dest {
			return true
		}
		// Suffix match: ".example.com" covers api.example.com.
		if strings.HasPrefix(entry, ".") && strings.HasSuffix(dest, entry) {
			return true
		}
	}
	return false
}

// EvaluateEgress decides allow/deny for a destination at time now.
func EvaluateEgress(p EgressPolicy, dest string, now time.Time) EgressDecision {
	d := EgressDecision{Destination: dest, At: now}
	if hostMatches(AlwaysDenied, dest) {
		d.Reason = "metadata/cluster endpoint always denied"
		return d
	}
	if hostMatches(p.Deny, dest) {
		d.Reason = "deny list"
		return d
	}
	if hostMatches(p.Allow, dest) {
		d.Allowed = true
		d.Reason = "allow list"
		return d
	}
	if p.DefaultAllow {
		d.Allowed = true
		d.Reason = "default allow"
	} else {
		d.Reason = "default deny"
	}
	return d
}

// Serialize renders a policy for transport to sandboxed processes via env.
func Serialize(p EgressPolicy) string {
	data, _ := json.Marshal(p)
	return string(data)
}

// AuditEntry is one network/credential audit record.
type AuditEntry struct {
	Kind    string    `json:"kind"`
	Subject string    `json:"subject"`
	Detail  string    `json:"detail"`
	At      time.Time `json:"at"`
}

// AuditLog is an in-memory audit trail optionally mirrored to a durable
// JSON-lines file.
type AuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
	file    *os.File
}

// NewAuditLog opens an audit log; path "" means memory-only.
func NewAuditLog(path string) (*AuditLog, error) {
	l := &AuditLog{}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		l.file = f
	}
	return l, nil
}

func (l *AuditLog) Record(kind, subject, detail string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := AuditEntry{Kind: kind, Subject: subject, Detail: detail, At: at}
	l.entries = append(l.entries, entry)
	if l.file != nil {
		data, _ := json.Marshal(entry)
		l.file.Write(append(data, '\n'))
	}
}

func (l *AuditLog) Entries() []AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]AuditEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

func (l *AuditLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// BindingView is the gateway's read model of one endpoint binding.
type BindingView struct {
	Binding       domain.EndpointBinding
	CurrentEpoch  int64
	SandboxActive bool
	Now           time.Time
}

// BindingSource supplies binding views to the gateway (the sandbox
// manager implements it).
type BindingSource interface {
	BindingView(bindingID string) (BindingView, bool)
}

// RouteDecision is the gateway's fail-closed routing verdict.
type RouteDecision struct {
	Allowed   bool
	Reason    string
	SandboxID string
	Epoch     int64
	Port      int
}

// Gateway resolves bindings to (sandbox, epoch, port). It fails CLOSED on
// every doubt: unknown binding, non-ACTIVE state, TTL expiry, or an epoch
// fence mismatch (binding created before an execution-epoch reset).
type Gateway struct {
	src BindingSource
}

func NewGateway(src BindingSource) *Gateway { return &Gateway{src: src} }

func (g *Gateway) Route(bindingID string) RouteDecision {
	view, ok := g.src.BindingView(bindingID)
	if !ok {
		return RouteDecision{Reason: "unknown binding"}
	}
	b := view.Binding
	deny := func(reason string) RouteDecision {
		return RouteDecision{Reason: reason, SandboxID: b.SandboxID, Epoch: b.ExecutionEpoch, Port: b.TargetPort}
	}
	if b.State != domain.EndpointActive {
		return deny(fmt.Sprintf("binding %s", b.State))
	}
	if !view.Now.IsZero() && !b.ExpiresAt.IsZero() && view.Now.After(b.ExpiresAt) {
		return deny("binding expired")
	}
	if b.ExecutionEpoch != view.CurrentEpoch {
		return deny(fmt.Sprintf("stale epoch fence: binding epoch %d, sandbox epoch %d", b.ExecutionEpoch, view.CurrentEpoch))
	}
	if !view.SandboxActive {
		return deny("sandbox not live")
	}
	return RouteDecision{Allowed: true, Reason: "bound", SandboxID: b.SandboxID, Epoch: b.ExecutionEpoch, Port: b.TargetPort}
}
