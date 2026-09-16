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
	"net"
	"os"
	"strconv"
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
// no policy may permit them (FR-SEC-001). Matching normalizes case, trailing
// dots, cluster-domain suffixes, and alternate IP encodings so bypass
// variants fail closed (see isAlwaysDenied).
var AlwaysDenied = []string{"169.254.169.254", "kubernetes.default.svc"}

// EgressDecision is one evaluated destination plus its audit record.
type EgressDecision struct {
	Destination string    `json:"destination"`
	Allowed     bool      `json:"allowed"`
	Reason      string    `json:"reason"`
	At          time.Time `json:"at"`
}

// normalizeHost canonicalizes a destination for policy matching: lowercase,
// no trailing dot.
func normalizeHost(dest string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(dest)), ".")
}

// metadataIP is 169.254.169.254.
const metadataIPv4 = 0xA9FEA9FE

// isMetadataIP reports whether dest names the link-local cloud metadata
// address in any encoding: dotted quad, IPv6-mapped, decimal, or hex.
func isMetadataIP(dest string) bool {
	if ip := net.ParseIP(dest); ip != nil {
		v4 := ip.To4() // also unwraps IPv6-mapped forms
		return v4 != nil && uint32(v4[0])<<24|uint32(v4[1])<<16|uint32(v4[2])<<8|uint32(v4[3]) == metadataIPv4
	}
	var n uint64
	var err error
	if strings.HasPrefix(dest, "0x") || strings.HasPrefix(dest, "0X") {
		n, err = strconv.ParseUint(dest[2:], 16, 32)
	} else {
		n, err = strconv.ParseUint(dest, 10, 32)
	}
	return err == nil && uint32(n) == metadataIPv4
}

// isAlwaysDenied reports whether dest is a metadata/cluster endpoint in any
// normalized form; these may never be permitted by policy.
func isAlwaysDenied(dest string) bool {
	d := normalizeHost(dest)
	if isMetadataIP(d) {
		return true
	}
	const clusterAPI = "kubernetes.default.svc"
	return d == clusterAPI || strings.HasPrefix(d, clusterAPI+".")
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
	if isAlwaysDenied(dest) {
		d.Reason = "metadata/cluster endpoint always denied"
		return d
	}
	norm := normalizeHost(dest)
	if hostMatches(p.Deny, norm) {
		d.Reason = "deny list"
		return d
	}
	if hostMatches(p.Allow, norm) {
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

// AuditLog is an audit trail optionally mirrored to a durable JSON-lines
// file. In-memory growth is bounded: when the cap is reached the oldest
// entries are dropped and counted (see Dropped).
type AuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
	dropped int
	file    *os.File
}

// maxAuditEntries bounds in-memory retention; the file mirror is uncapped.
const maxAuditEntries = 10000

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

// Record appends an audit entry, mirroring it to the durable file when
// configured. File write failures are surfaced to the caller — an audit
// component must not silently lose audit records.
func (l *AuditLog) Record(kind, subject, detail string, at time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := AuditEntry{Kind: kind, Subject: subject, Detail: detail, At: at}
	l.entries = append(l.entries, entry)
	if len(l.entries) > maxAuditEntries {
		excess := len(l.entries) - maxAuditEntries
		l.entries = append([]AuditEntry{}, l.entries[excess:]...)
		l.dropped += excess
	}
	if l.file != nil {
		data, _ := json.Marshal(entry)
		if _, err := l.file.Write(append(data, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// Dropped reports how many in-memory entries were evicted by the retention
// cap (file-mirrored entries are never lost).
func (l *AuditLog) Dropped() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
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
	// Resumable marks a deny that a resume can cure (binding SUSPENDED or
	// sandbox not live) — the typed replacement for reason-string matching
	// at the proxy (review M2).
	Resumable bool
	// LookupError marks a verdict manufactured client-side after a transport
	// or server failure talking to the control plane — never a routing
	// decision, never resumable; the proxy surfaces 502 (review M2).
	LookupError bool
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
		d := deny(fmt.Sprintf("binding %s", b.State))
		// A SUSPENDED binding becomes routable again via resume (ADR-007).
		d.Resumable = b.State == domain.EndpointSuspended
		return d
	}
	// Fail closed whenever expiry cannot be evaluated, and at the exact
	// expiry instant (routable strictly before ExpiresAt only).
	if view.Now.IsZero() {
		return deny("cannot evaluate expiry: no clock")
	}
	if b.ExpiresAt.IsZero() {
		return deny("cannot evaluate expiry: binding has no TTL")
	}
	if !view.Now.Before(b.ExpiresAt) {
		return deny("binding expired")
	}
	if b.ExecutionEpoch != view.CurrentEpoch {
		return deny(fmt.Sprintf("stale epoch fence: binding epoch %d, sandbox epoch %d", b.ExecutionEpoch, view.CurrentEpoch))
	}
	if !view.SandboxActive {
		d := deny("sandbox not live")
		d.Resumable = true
		return d
	}
	return RouteDecision{Allowed: true, Reason: "bound", SandboxID: b.SandboxID, Epoch: b.ExecutionEpoch, Port: b.TargetPort}
}
