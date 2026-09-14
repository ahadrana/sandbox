package firecrackerbackend

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agent-sandbox/platform/network"
	"github.com/agent-sandbox/platform/runtime/backend-interface"
)

// This file implements host-enforced guest networking (FR-NET-006): a
// per-incarnation TAP device, host NAT, and per-incarnation iptables chains
// translating network.EgressPolicy semantics into packet rules. Requires
// passwordless sudo (`sudo -n ip`, `sudo -n iptables/ip6tables`); when
// Config.Networking is off no NIC is attached at all (fail-closed, and
// NetworkIsolated is declared false).
//
// Isolation rules per incarnation (FM1/FM2, CODE-REVIEW-FC-2026-09-14):
//   - anti-spoofing: tap-ingress packets whose source is not the VM's
//     assigned /30 IP are DROPped before anything else;
//   - cross-VM: destinations in 192.168.0.0/16 (every VM /30, including the
//     host tap side) and 169.254.0.0/16 (link-local) are DROPped — guests
//     cannot reach each other or host tap services; 169.254.169.254 (cloud
//     metadata) is always first;
//   - IPv6: disabled in-guest via sysctl AND all tap-ingress IPv6 dropped
//     host-side in ip6tables (host-enforced, survives guest re-enabling).
//   - DNS: the base rootfs ships an empty /etc/resolv.conf (no resolver);
//     the guest network unit points it at a public resolver, so DNS is
//     ordinary egress traffic subject to the same policy (blocked under
//     default-deny, like everything else).

const (
	metadataIP      = "169.254.169.254"
	linkLocalCIDR   = "169.254.0.0/16"
	vmSubnetCIDR    = "192.168.0.0/16"
	egressChainPfx  = "FC-EGR-"
	egressChain6Pfx = "FC-EGR6-"
	tapPfx          = "fc-tap-"
	// guestResolver is written into the guest's (empty) resolv.conf.
	guestResolver = "8.8.8.8"
)

// netSlotSpace bounds the slot allocator (slot n owns the /30 at offset
// 8n from 192.168.0.0 — 8192 slots span the whole 192.168.0.0/16). Tests
// shrink it to force collisions.
var netSlotSpace = 8192

// masqueradeCIDR covers exactly the slot space: the uplink NAT rule never
// matches unrelated host networks (FL8).
func masqueradeCIDR() string {
	span := 16 // minimum: a /28 covers one slot's 8-address stride with slack
	for need := netSlotSpace * 8; span < need; span <<= 1 {
	}
	prefix := 0
	for s := span; s > 1; s >>= 1 {
		prefix++
	}
	return fmt.Sprintf("192.168.0.0/%d", 32-prefix)
}

// netState is one incarnation's host-side network plumbing.
type netState struct {
	slot    int
	tap     string
	hostIP  string
	guestIP string
	chain   string
	chain6  string
	mac     string
	// stopReresolve stops the hostname re-resolver goroutine (FM4); nil
	// when the policy has no hostname entries.
	stopReresolve chan struct{}
}

// slotNames derives the kernel-visible names and addresses of a slot.
func slotNames(n int) *netState {
	a := n / 32
	third := (n % 32) * 8
	return &netState{
		slot:    n,
		tap:     fmt.Sprintf("%s%d", tapPfx, n),
		hostIP:  fmt.Sprintf("192.168.%d.%d", a, third+1),
		guestIP: fmt.Sprintf("192.168.%d.%d", a, third+2),
		chain:   fmt.Sprintf("%s%d", egressChainPfx, n),
		chain6:  fmt.Sprintf("%s%d", egressChain6Pfx, n),
		mac:     fmt.Sprintf("06:00:%02x:%02x:%02x:%02x", 0xAC, byte(n>>8), byte(n), 0x01),
	}
}

// preferredSlot hashes the incarnation ID for spread; collisions are
// resolved by linear scan in allocateSlot (FM3).
func preferredSlot(incarnationID string) int {
	h := fnv.New32a()
	h.Write([]byte(incarnationID))
	return int(h.Sum32() % uint32(netSlotSpace))
}

// slotAllocator is a process-local slot registry; it covers every Backend
// instance in the process and never hands out a slot owned by another live
// incarnation. A slot whose TAP exists but is not registered here belongs
// to another process (or a crashed one — crash sweep is FM11) and is
// skipped, never deleted.
var slotAlloc = struct {
	sync.Mutex
	used map[int]string // slot -> incarnationID
}{used: map[int]string{}}

// allocateSlot reserves a slot for incID, scanning from preferred.
func allocateSlot(incID string, preferred int) (*netState, error) {
	slotAlloc.Lock()
	defer slotAlloc.Unlock()
	for i := 0; i < netSlotSpace; i++ {
		n := (preferred + i) % netSlotSpace
		if owner, taken := slotAlloc.used[n]; taken && owner != incID {
			continue
		}
		ns := slotNames(n)
		if exec.Command("ip", "link", "show", ns.tap).Run() == nil {
			// The TAP exists. Only reclaim it when it is provably ours
			// (registered to this very incarnation, i.e. a leftover from a
			// failed setup); otherwise the slot is occupied.
			if slotAlloc.used[n] != incID {
				continue
			}
			sudo("ip", "link", "del", ns.tap).Run()
		}
		slotAlloc.used[n] = incID
		return ns, nil
	}
	return nil, fmt.Errorf("no free network slot for incarnation %q (space %d)", incID, netSlotSpace)
}

// releaseSlot frees the slot if it is still registered to incID.
func releaseSlot(incID string, ns *netState) {
	slotAlloc.Lock()
	defer slotAlloc.Unlock()
	if slotAlloc.used[ns.slot] == incID {
		delete(slotAlloc.used, ns.slot)
	}
}

// sudo runs a privileged command, requiring passwordless sudo.
func sudo(args ...string) *exec.Cmd {
	return exec.Command("sudo", append([]string{"-n"}, args...)...)
}

// checkNetPrereqs verifies the host can do TAP+iptables plumbing.
func checkNetPrereqs() error {
	if out, err := sudo("true").CombinedOutput(); err != nil {
		return fmt.Errorf("networking requires passwordless sudo (ip tuntap/iptables): %v: %s", err, out)
	}
	for _, bin := range []string{"ip", "iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("networking requires %s in PATH", bin)
		}
	}
	return nil
}

// Global uplink NAT state: success is cached for the process; a FAILURE is
// not cached — the next incarnation retries (FL8, transient sysctl/iptables
// failures must not disable networking forever).
var globalNet struct {
	sync.Mutex
	done bool
}

// ensureGlobalNet sets up ip_forward and uplink NAT exactly once per
// process; failures surface on first use and are retried on the next call.
// IPv6 forwarding is deliberately never enabled (guest IPv6 is dropped
// host-side regardless).
func (b *Backend) ensureGlobalNet() error {
	globalNet.Lock()
	defer globalNet.Unlock()
	if globalNet.done {
		return nil
	}
	if out, err := sudo("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
		return fmt.Errorf("enable ip_forward: %v: %s", err, out)
	}
	uplink, err := defaultUplink()
	if err != nil {
		return err
	}
	subnet := masqueradeCIDR()
	// -C first: idempotent across backend instances.
	check := sudo("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-o", uplink, "-j", "MASQUERADE")
	if err := check.Run(); err != nil {
		if out, err := sudo("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", uplink, "-j", "MASQUERADE").CombinedOutput(); err != nil {
			return fmt.Errorf("add MASQUERADE: %v: %s", err, out)
		}
	}
	globalNet.done = true
	return nil
}

func defaultUplink() (string, error) {
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("no default route: %v: %s", err, out)
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("cannot parse default route: %s", out)
}

// egressPolicyFor extracts the serialized network.EgressPolicy the manager
// places in Spec.Env (AGENT_SANDBOX_EGRESS); absent means the platform
// default: deny metadata, allow the rest.
func egressPolicyFor(spec backendinterface.Spec) (network.EgressPolicy, error) {
	raw := spec.Env["AGENT_SANDBOX_EGRESS"]
	if raw == "" {
		return network.EgressPolicy{DefaultAllow: true}, nil
	}
	var p network.EgressPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return network.EgressPolicy{}, fmt.Errorf("malformed AGENT_SANDBOX_EGRESS: %w", err)
	}
	return p, nil
}

// destCIDRs translates a policy host list into iptables destinations: IPs
// and CIDRs directly, hostnames via DNS resolution. A deny-list entry that
// cannot be translated fails closed (error); an unresolvable allow entry
// simply grants nothing (also fail closed).
func destCIDRs(entries []string, failOnError bool) ([]string, error) {
	var out []string
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" || e == "*" {
			if e == "*" {
				out = append(out, "0.0.0.0/0")
			}
			continue
		}
		if ip := net.ParseIP(strings.TrimPrefix(e, ".")); ip != nil {
			out = append(out, e)
			continue
		}
		if _, _, err := net.ParseCIDR(e); err == nil {
			out = append(out, e)
			continue
		}
		host := strings.TrimPrefix(e, ".")
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			if failOnError {
				return nil, fmt.Errorf("egress deny entry %q does not resolve; failing closed", e)
			}
			continue
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				out = append(out, v4.String())
			}
		}
	}
	return out, nil
}

// allocateNetworkingLocked reserves a network slot for the incarnation
// (called at Create, so the guest network unit baked into the rootfs
// matches the TAP the VM will get at Start). Caller holds b.mu.
func (b *Backend) allocateNetworkingLocked(inc *incarnation, preferred int) error {
	ns, err := allocateSlot(inc.id, preferred)
	if err != nil {
		return err
	}
	inc.net = ns
	return nil
}

// netOf reads inc.net under b.mu (FL12: all inc.net access is locked).
func (b *Backend) netOf(inc *incarnation) *netState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return inc.net
}

// setupNetworking creates the TAP and the egress chains for inc; the slot
// must already be reserved (allocateNetworkingLocked). Called without b.mu.
func (b *Backend) setupNetworking(inc *incarnation) error {
	if err := b.ensureGlobalNet(); err != nil {
		return err
	}
	ns := b.netOf(inc)
	if ns == nil {
		return fmt.Errorf("networking not allocated for incarnation %q", inc.id)
	}
	pol, err := egressPolicyFor(inc.spec)
	if err != nil {
		return err
	}
	// Best-effort cleanup of partial device state from a previous failed
	// setup of THIS slot (leftovers of other incarnations are never
	// touched; the slot reservation is kept).
	cleanupNetDevices(ns)

	setupErr := func(err error) error {
		b.teardownNetworking(inc)
		return err
	}
	if err := netRun("ip", "tuntap", "add", "dev", ns.tap, "mode", "tap"); err != nil {
		return setupErr(err)
	}
	if err := netRun("ip", "addr", "add", ns.hostIP+"/30", "dev", ns.tap); err != nil {
		return setupErr(err)
	}
	if err := netRun("ip", "link", "set", ns.tap, "up"); err != nil {
		return setupErr(err)
	}
	if err := buildEgressChain(ns.chain, pol); err != nil {
		return setupErr(err)
	}
	// Anti-spoofing DROP must precede the chain jump; the chain jump also
	// carries the source match as defense in depth. The chain is hooked
	// into both FORWARD (routed/NAT'd traffic) and INPUT (services on the
	// host itself) so host-bound traffic is governed by the same policy.
	for _, hook := range []string{"FORWARD", "INPUT"} {
		if err := netRun("iptables", "-I", hook, "-i", ns.tap, "!", "-s", ns.guestIP, "-j", "DROP"); err != nil {
			return setupErr(err)
		}
		if err := netRun("iptables", "-I", hook, "-i", ns.tap, "-s", ns.guestIP, "-j", ns.chain); err != nil {
			return setupErr(err)
		}
	}
	// IPv6: drop everything from this TAP host-side (belt and braces with
	// the in-guest sysctl disable).
	if err := netRun("ip6tables", "-N", ns.chain6); err != nil {
		return setupErr(err)
	}
	if err := netRun("ip6tables", "-A", ns.chain6, "-j", "DROP"); err != nil {
		return setupErr(err)
	}
	for _, hook := range []string{"FORWARD", "INPUT"} {
		if err := netRun("ip6tables", "-I", hook, "-i", ns.tap, "-j", ns.chain6); err != nil {
			return setupErr(err)
		}
	}
	// FM4: hostname policy entries go stale (DNS rebinding / TTL expiry);
	// re-resolve them periodically and atomically swap the chain.
	if b.cfg.ReResolveInterval > 0 && policyHasHostnames(pol) {
		ns.stopReresolve = make(chan struct{})
		go b.reResolveLoop(ns, pol)
	}
	return nil
}

func netRun(args ...string) error {
	if out, err := sudo(args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

// buildEgressChain creates chain and populates it from the policy. Rule
// order (first match wins): 1. cloud metadata, always; 2. link-local + the
// whole VM /16 (cross-VM and host tap side); 3. policy denies; 4. policy
// allows; 5. default-deny.
func buildEgressChain(chain string, pol network.EgressPolicy) error {
	if err := netRun("iptables", "-N", chain); err != nil {
		return err
	}
	for _, rule := range [][2]string{{"-d", metadataIP}, {"-d", linkLocalCIDR}, {"-d", vmSubnetCIDR}} {
		if err := netRun("iptables", "-A", chain, rule[0], rule[1], "-j", "DROP"); err != nil {
			return err
		}
	}
	denies, err := destCIDRs(pol.Deny, true)
	if err != nil {
		return err
	}
	for _, d := range denies {
		if err := netRun("iptables", "-A", chain, "-d", d, "-j", "DROP"); err != nil {
			return err
		}
	}
	allows, err := destCIDRs(pol.Allow, false)
	if err != nil {
		return err
	}
	for _, a := range allows {
		if err := netRun("iptables", "-A", chain, "-d", a, "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	if !pol.DefaultAllow {
		if err := netRun("iptables", "-A", chain, "-j", "DROP"); err != nil {
			return err
		}
	}
	return nil
}

// policyHasHostnames reports whether any policy entry needs DNS resolution
// (not an IP, CIDR, "*", or empty).
func policyHasHostnames(pol network.EgressPolicy) bool {
	for _, list := range [][]string{pol.Deny, pol.Allow} {
		for _, e := range list {
			e = strings.TrimSpace(e)
			if e == "" || e == "*" {
				continue
			}
			if net.ParseIP(strings.TrimPrefix(e, ".")) != nil {
				continue
			}
			if _, _, err := net.ParseCIDR(e); err == nil {
				continue
			}
			return true
		}
	}
	return false
}

// reResolveLoop periodically re-resolves the policy's hostname entries and
// atomically swaps the incarnation's chain (FM4): build a fully-populated
// tmp chain, retarget the FORWARD/INPUT jumps at it, then flush+delete the
// old chain and rename tmp into place. A failure keeps the old rules.
func (b *Backend) reResolveLoop(ns *netState, pol network.EgressPolicy) {
	t := time.NewTicker(b.cfg.ReResolveInterval)
	defer t.Stop()
	for {
		select {
		case <-ns.stopReresolve:
			return
		case <-t.C:
			if err := reResolveChain(ns, pol); err != nil {
				fmt.Fprintf(os.Stderr, "firecrackerbackend: egress re-resolve %s: %v (keeping old rules)\n", ns.chain, err)
			}
		}
	}
}

func reResolveChain(ns *netState, pol network.EgressPolicy) error {
	tmp := ns.chain + ".tmp"
	sudo("iptables", "-F", tmp).Run()
	sudo("iptables", "-X", tmp).Run()
	if err := buildEgressChain(tmp, pol); err != nil {
		return err
	}
	for _, hook := range []string{"FORWARD", "INPUT"} {
		pos, err := findJumpRule(hook, ns.tap, ns.chain)
		if err != nil {
			return err
		}
		if err := netRun("iptables", "-R", hook, strconv.Itoa(pos), "-i", ns.tap, "-s", ns.guestIP, "-j", tmp); err != nil {
			return err
		}
	}
	if err := netRun("iptables", "-F", ns.chain); err != nil {
		return err
	}
	if err := netRun("iptables", "-X", ns.chain); err != nil {
		return err
	}
	return netRun("iptables", "-E", tmp, ns.chain)
}

// findJumpRule returns the 1-based position of the rule jumping to chain
// for tap within hook (position counts the -A lines of `iptables -S hook`).
func findJumpRule(hook, tap, chain string) (int, error) {
	out, err := sudo("iptables", "-S", hook).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("iptables -S %s: %v: %s", hook, err, out)
	}
	pos := 0
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		pos++
		if strings.Contains(line, "-i "+tap+" ") && strings.HasSuffix(line, "-j "+chain) {
			return pos, nil
		}
	}
	return 0, fmt.Errorf("jump rule for %s in %s not found", chain, hook)
}

// cleanupNetDevices removes the TAP, egress rules, and chains of ns.
// Best-effort; safe on partial state; never touches other slots. Also
// stops the re-resolver (FM4) if one is running.
func cleanupNetDevices(ns *netState) {
	if ns.stopReresolve != nil {
		select {
		case <-ns.stopReresolve:
		default:
			close(ns.stopReresolve)
		}
	}
	for _, hook := range []string{"FORWARD", "INPUT"} {
		sudo("iptables", "-D", hook, "-i", ns.tap, "!", "-s", ns.guestIP, "-j", "DROP").Run()
		sudo("iptables", "-D", hook, "-i", ns.tap, "-s", ns.guestIP, "-j", ns.chain).Run()
		sudo("iptables", "-D", hook, "-i", ns.tap, "-s", ns.guestIP, "-j", ns.chain+".tmp").Run()
		sudo("ip6tables", "-D", hook, "-i", ns.tap, "-j", ns.chain6).Run()
	}
	sudo("iptables", "-F", ns.chain).Run()
	sudo("iptables", "-X", ns.chain).Run()
	sudo("iptables", "-F", ns.chain+".tmp").Run()
	sudo("iptables", "-X", ns.chain+".tmp").Run()
	sudo("ip6tables", "-F", ns.chain6).Run()
	sudo("ip6tables", "-X", ns.chain6).Run()
	sudo("ip", "link", "del", ns.tap).Run()
}

// teardownNetworking removes the incarnation's TAP, egress rules, and slot
// reservation. Safe on partial state; never touches other slots. The
// inc.net swap happens under b.mu (FL12); the blocking sudo calls do not
// (FL7).
func (b *Backend) teardownNetworking(inc *incarnation) {
	b.mu.Lock()
	ns := inc.net
	inc.net = nil
	b.mu.Unlock()
	if ns == nil {
		return
	}
	cleanupNetDevices(ns)
	releaseSlot(inc.id, ns)
}

// networkUnit is injected (only when networking is enabled) to bring up the
// guest NIC with the static /30 pair. It also disables IPv6 in the guest
// (the host-side ip6tables DROP is the enforcing layer) and points the
// (empty) stock resolv.conf at a public resolver.
const networkUnitTemplate = `[Unit]
Description=agent-sandbox guest network
Before=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'rm -f /etc/resolv.conf && echo nameserver ` + guestResolver + ` > /etc/resolv.conf; sysctl -w net.ipv6.conf.all.disable_ipv6=1; sysctl -w net.ipv6.conf.eth0.disable_ipv6=1; ip link set eth0 up && ip addr add %s/30 dev eth0 && ip route add default via %s && echo AGENT_NET_READY > /dev/ttyS0'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`

// sweepStaleNetworking reclaims TAPs and egress chains leaked by a previous
// (crashed) backend process (FM11). Only resources matching this platform's
// exact naming conventions are touched, and a slot still registered to a
// live incarnation of THIS process is never swept (defense in depth: a
// fresh New has none, but a second Backend in the same process might).
// Errors are logged loudly, never fatal.
func sweepStaleNetworking() {
	slots := map[int]bool{}
	if out, err := exec.Command("ip", "-o", "link", "show").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "firecrackerbackend: crash sweep: ip link: %v: %s\n", err, out)
	} else {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			name := strings.SplitN(strings.TrimSuffix(fields[1], ":"), "@", 2)[0]
			if n, ok := parseSlotSuffix(name, tapPfx); ok {
				slots[n] = true
			}
		}
	}
	for _, spec := range []struct{ bin, pfx string }{{"iptables", egressChainPfx}, {"ip6tables", egressChain6Pfx}} {
		out, err := sudo(spec.bin, "-S").CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "firecrackerbackend: crash sweep: %s -S: %v: %s\n", spec.bin, err, out)
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "-N ") {
				if n, found := parseSlotSuffix(line[3:], spec.pfx); found {
					slots[n] = true
				}
			}
		}
	}
	for n := range slots {
		slotAlloc.Lock()
		_, live := slotAlloc.used[n]
		slotAlloc.Unlock()
		if live {
			continue
		}
		ns := slotNames(n)
		fmt.Fprintf(os.Stderr, "firecrackerbackend: crash sweep: removing stale %s / %s / %s\n", ns.tap, ns.chain, ns.chain6)
		cleanupNetDevices(ns)
	}
}

// parseSlotSuffix parses "<prefix><number>" names; the number must be a
// valid slot index so lookalike names are never matched.
func parseSlotSuffix(name, pfx string) (int, bool) {
	if !strings.HasPrefix(name, pfx) {
		return 0, false
	}
	s := name[len(pfx):]
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n >= netSlotSpace {
		return 0, false
	}
	return n, true
}
