package firecrackerbackend

// Endpoint port publishing (ADR-007 data plane): DNAT a host TCP port to
// an incarnation's guestIP:guestPort so endpoint bindings are reachable as
// host:port. Same discipline as the Batch-1 egress machinery: rules live
// in a per-incarnation chain (FC-PUB-<slot>, nat table) hooked from
// PREROUTING (external/routed clients, including same-node pods) and
// OUTPUT (host-local clients), every appended rule is verified with
// iptables -C before it is considered installed, and teardown removes the
// whole chain plus jumps — nothing leaks across Terminate/KillRuntime or a
// restore onto a different host (the old host's backend tears the rules
// down with the old networking; the new host publishes fresh).
//
// Hairpin: the OUTPUT hook excludes loopback DESTINATIONS (! -d
// 127.0.0.0/8) rather than the lo interface — traffic to the host's own
// uplink address is also routed via lo and must still DNAT, while a
// 127.0.0.1 client could DNAT but the guest cannot reply to a loopback
// source, so loopback clients fail fast (connection refused) instead of
// hanging.
// Non-loopback clients need no MASQUERADE: replies traverse the host
// (the guest's default route is the tap host address) and conntrack
// reverses the DNAT. A MASQUERADE would put the host TAP IP
// (192.168.0.0/16) on the reply path, which the guest egress chain DROPs
// by design.
//
// Conflict semantics: the host port is fixed (no dynamic remapping, so the
// address a client holds never lies); a process-local registry keyed by
// host port fails a port owned by another live incarnation with
// backendinterface.ErrPortConflict. A published host port maps to exactly
// ONE guest port: re-publishing the same host port with a different guest
// port is rejected (typed ErrPortConflict) — unpublish first to remap.
//
// Port policy (review H1): the well-known floor (<1024) is never
// publishable, and a deny-list (Config.PublishDenyPorts, defaulting to the
// platform's own service ports) rejects ports bound by node services —
// publishing one would DNAT that service's traffic into tenant code. Both
// fail with a typed ErrPortConflict, enforced HERE in the backend so
// in-process runtimes are covered too (the host agent's ProtectPorts is
// the agent's additional self-protection for its RPC port).
//
// Traffic scoping (review C1): both hooks match `-m addrtype --dst-type
// LOCAL`, so only traffic destined to the host's OWN addresses enters the
// publish chain. Without it, dport-only matching would redirect outbound
// host connections to any remote service on the same port (and, via
// PREROUTING, forwarded/routed traffic) into an untrusted guest.
//
// Stateless-policy note: DNAT'd reply packets are guest-originated flows
// to the client IP, evaluated by the incarnation's egress chain like any
// other flow — publishing composes with default-allow policies; under
// default-deny the client destinations must be in the policy Allow set.

import (
	"fmt"
	"strconv"
	"sync"

	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
)

const pubChainPfx = "FC-PUB-"

// pubSudo/pubNetRun indirection mirrors flushGuestConntrack and
// chainInstallFault: the publish path's command execution is overridable
// in KVM-free tests.
var (
	pubSudo   = sudo
	pubNetRun = netRun
)

func pubChainName(slot int) string { return fmt.Sprintf("%s%d", pubChainPfx, slot) }

// pubPorts is the process-local host-port registry (hostPort -> slot), the
// port-level analog of slotAlloc: it covers every Backend instance in the
// process. Teardown frees a slot's ports even without per-port unpublish.
var pubPorts = struct {
	sync.Mutex
	byPort map[int]int
}{byPort: map[int]int{}}

// dnatRule renders the publish rule for one port mapping.
func dnatRule(guestIP string, guestPort, hostPort int) []string {
	return []string{
		"-p", "tcp", "--dport", strconv.Itoa(hostPort),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", guestIP, guestPort),
	}
}

// publishFloor is the well-known-port floor: host ports below it are never
// publishable (review H1).
const publishFloor = 1024

// DefaultPublishDenyPorts are the platform/node service ports a binding may
// never claim (review H1): the k3s apiserver, the platform services' dev
// port (host-agent RPC, control-plane, endpoint-proxyd all serve :8080 in
// this topology), and the kubelet. SSH (22) is covered by the floor.
// Config.PublishDenyPorts overrides; host-agentd extends via env.
var DefaultPublishDenyPorts = []int{6443, 8080, 10250}

// pubHooks are the nat hooks the publish chain hangs from. Both match only
// traffic destined to the host's own addresses (dst-type LOCAL, review C1);
// OUTPUT additionally excludes loopback (see the package comment above).
var pubHooks = []struct {
	name  string
	extra []string
}{
	{"PREROUTING", []string{"-m", "addrtype", "--dst-type", "LOCAL"}},
	{"OUTPUT", []string{"-m", "addrtype", "--dst-type", "LOCAL", "!", "-d", "127.0.0.0/8"}},
}

// checkPortAllowed enforces the floor and deny-list on the host port
// (review H1): rejections are typed ErrPortConflict so callers can
// distinguish policy from plumbing.
func (b *Backend) checkPortAllowed(hostPort int) error {
	if hostPort < publishFloor {
		return fmt.Errorf("host port %d is below the well-known port floor %d: %w", hostPort, publishFloor, backendinterface.ErrPortConflict)
	}
	deny := b.cfg.PublishDenyPorts
	if deny == nil {
		deny = DefaultPublishDenyPorts
	}
	for _, p := range deny {
		if p == hostPort {
			return fmt.Errorf("host port %d is deny-listed (platform/system service port): %w", hostPort, backendinterface.ErrPortConflict)
		}
	}
	return nil
}

// ensurePubChain makes the incarnation's publish chain and its hooks exist
// (idempotent via -N-tolerate-EEXIST + -C-first).
func ensurePubChain(ns *netState) error {
	chain := pubChainName(ns.slot)
	if err := pubSudo("iptables", "-t", "nat", "-N", chain).Run(); err != nil {
		// Possibly EEXIST (re-publish across a process restart found kernel
		// state); any other error surfaces when the chain is listed.
		if out, verr := pubSudo("iptables", "-t", "nat", "-S", chain).CombinedOutput(); verr != nil {
			return fmt.Errorf("create %s: %v: %s", chain, err, out)
		}
	}
	for _, hook := range pubHooks {
		check := append(append([]string{"-t", "nat", "-C", hook.name}, hook.extra...), "-j", chain)
		if pubSudo(append([]string{"iptables"}, check...)...).Run() == nil {
			continue
		}
		add := append(append([]string{"-t", "nat", "-A", hook.name}, hook.extra...), "-j", chain)
		if err := pubNetRun(append([]string{"iptables"}, add...)...); err != nil {
			return err
		}
	}
	return nil
}

// PublishPort implements backendinterface.PortPublisher.
func (b *Backend) PublishPort(h backendinterface.Handle, guestPort, hostPort int) error {
	if guestPort < 1 || guestPort > 65535 || hostPort < 1 || hostPort > 65535 {
		return fmt.Errorf("invalid port mapping %d -> %d", hostPort, guestPort)
	}
	if err := b.checkPortAllowed(hostPort); err != nil {
		return err
	}
	b.mu.Lock()
	inc, err := b.get(h)
	ns := (*netState)(nil)
	if err == nil {
		ns = inc.net
	}
	b.mu.Unlock()
	if err != nil {
		return err
	}
	if ns == nil {
		return fmt.Errorf("port publish requires guest networking (incarnation %s has none)", inc.id)
	}
	// One guest port per host port (review L2): a same-slot re-publish with a
	// CHANGED guest port would append a shadowed second rule that unpublish
	// only half-removes — reject it typed; unpublish first to remap.
	ns.mu.Lock()
	prevGuest, prevPublished := ns.published[hostPort]
	ns.mu.Unlock()
	if prevPublished && prevGuest != guestPort {
		return fmt.Errorf("host port %d already published to guest port %d (unpublish to remap): %w", hostPort, prevGuest, backendinterface.ErrPortConflict)
	}
	pubPorts.Lock()
	owner, taken := pubPorts.byPort[hostPort]
	if taken && owner != ns.slot {
		pubPorts.Unlock()
		return fmt.Errorf("host port %d (slot %d): %w", hostPort, owner, backendinterface.ErrPortConflict)
	}
	pubPorts.byPort[hostPort] = ns.slot
	pubPorts.Unlock()

	ns.installMu.Lock()
	defer ns.installMu.Unlock()
	if err := ensurePubChain(ns); err != nil {
		freePubPort(ns.slot, hostPort)
		return err
	}
	chain := pubChainName(ns.slot)
	rule := dnatRule(ns.guestIP, guestPort, hostPort)
	check := append([]string{"-t", "nat", "-C", chain}, rule...)
	if pubSudo(append([]string{"iptables"}, check...)...).Run() == nil {
		// Idempotent re-publish (resume republish): the rule is in the
		// kernel — still record the bookkeeping (review L1), or a later
		// unpublish would miss the -D.
		ns.mu.Lock()
		if ns.published == nil {
			ns.published = map[int]int{}
		}
		ns.published[hostPort] = guestPort
		ns.mu.Unlock()
		return nil
	}
	add := append([]string{"-t", "nat", "-A", chain}, rule...)
	if err := pubNetRun(append([]string{"iptables"}, add...)...); err != nil {
		freePubPort(ns.slot, hostPort)
		return err
	}
	// P0.5 discipline: verify before declaring installed; a verify failure
	// removes the rule again, never a half-published port.
	verify := append([]string{"-t", "nat", "-C", chain}, rule...)
	if err := pubNetRun(append([]string{"iptables"}, verify...)...); err != nil {
		del := append([]string{"-t", "nat", "-D", chain}, rule...)
		pubSudo(append([]string{"iptables"}, del...)...).Run()
		freePubPort(ns.slot, hostPort)
		return fmt.Errorf("verify publish: %w", err)
	}
	ns.mu.Lock()
	if ns.published == nil {
		ns.published = map[int]int{}
	}
	ns.published[hostPort] = guestPort
	ns.mu.Unlock()
	return nil
}

// UnpublishPort implements backendinterface.PortPublisher. Unknown ports
// and torn-down networking are no-ops (teardown is the backstop).
func (b *Backend) UnpublishPort(h backendinterface.Handle, hostPort int) error {
	b.mu.Lock()
	inc, err := b.get(h)
	ns := (*netState)(nil)
	if err == nil {
		ns = inc.net
	}
	b.mu.Unlock()
	if err != nil || ns == nil {
		return nil
	}
	ns.installMu.Lock()
	defer ns.installMu.Unlock()
	ns.mu.Lock()
	guestPort, known := ns.published[hostPort]
	delete(ns.published, hostPort)
	ns.mu.Unlock()
	freePubPort(ns.slot, hostPort)
	if !known {
		return nil
	}
	rule := dnatRule(ns.guestIP, guestPort, hostPort)
	del := append([]string{"-t", "nat", "-D", pubChainName(ns.slot)}, rule...)
	// Best-effort: the rule may already be gone (teardown rebuilt state);
	// the chain removal at teardown is the backstop.
	_ = pubNetRun(append([]string{"iptables"}, del...)...)
	return nil
}

// freePubPort releases the registry entry if the slot still owns it.
func freePubPort(slot, hostPort int) {
	pubPorts.Lock()
	defer pubPorts.Unlock()
	if pubPorts.byPort[hostPort] == slot {
		delete(pubPorts.byPort, hostPort)
	}
}

// cleanupPubRules removes the incarnation's publish chain, its hooks, and
// its registry entries. Called from cleanupNetDevices; safe on partial
// state, never touches other slots. Serialized with PublishPort under
// installMu (review M7): a concurrent publish must not recreate the chain
// after teardown removed it.
func cleanupPubRules(ns *netState) {
	ns.installMu.Lock()
	defer ns.installMu.Unlock()
	chain := pubChainName(ns.slot)
	for _, hook := range pubHooks {
		del := append(append([]string{"-t", "nat", "-D", hook.name}, hook.extra...), "-j", chain)
		pubSudo(append([]string{"iptables"}, del...)...).Run()
	}
	pubSudo("iptables", "-t", "nat", "-F", chain).Run()
	pubSudo("iptables", "-t", "nat", "-X", chain).Run()
	pubPorts.Lock()
	for p, s := range pubPorts.byPort {
		if s == ns.slot {
			delete(pubPorts.byPort, p)
		}
	}
	pubPorts.Unlock()
	ns.mu.Lock()
	ns.published = nil
	ns.mu.Unlock()
}
