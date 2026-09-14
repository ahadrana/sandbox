package firecrackerbackend

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"os/exec"
	"strings"
	"sync"

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
	metadataIP       = "169.254.169.254"
	linkLocalCIDR    = "169.254.0.0/16"
	vmSubnetCIDR     = "192.168.0.0/16"
	egressChainPfx   = "FC-EGR-"
	egressChain6Pfx  = "FC-EGR6-"
	tapPfx           = "fc-tap-"
	masqueradeSubnet = "192.168.0.0/16"
	// guestResolver is written into the guest's (empty) resolv.conf.
	guestResolver = "8.8.8.8"
)

// netSlotSpace bounds the slot allocator (each slot owns one /30 in
// 192.168.0.0/19). Tests shrink it to force collisions.
var netSlotSpace = 8192

// netState is one incarnation's host-side network plumbing.
type netState struct {
	slot    int
	tap     string
	hostIP  string
	guestIP string
	chain   string
	chain6  string
	mac     string
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

var netOnce struct {
	sync.Once
	err error
}

// ensureGlobalNet sets up ip_forward and uplink NAT exactly once per
// process; failures surface on first use. IPv6 forwarding is deliberately
// never enabled (guest IPv6 is dropped host-side regardless).
func (b *Backend) ensureGlobalNet() error {
	netOnce.Do(func() {
		if out, err := sudo("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
			netOnce.err = fmt.Errorf("enable ip_forward: %v: %s", err, out)
			return
		}
		uplink, err := defaultUplink()
		if err != nil {
			netOnce.err = err
			return
		}
		// -C first: idempotent across backend instances.
		check := sudo("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", masqueradeSubnet, "-o", uplink, "-j", "MASQUERADE")
		if err := check.Run(); err != nil {
			if out, err := sudo("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", masqueradeSubnet, "-o", uplink, "-j", "MASQUERADE").CombinedOutput(); err != nil {
				netOnce.err = fmt.Errorf("add MASQUERADE: %v: %s", err, out)
			}
		}
	})
	return netOnce.err
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

// allocateNetworking reserves a network slot for the incarnation (called at
// Create, so the guest network unit baked into the rootfs matches the TAP
// the VM will get at Start).
func (b *Backend) allocateNetworking(inc *incarnation, preferred int) error {
	ns, err := allocateSlot(inc.id, preferred)
	if err != nil {
		return err
	}
	inc.net = ns
	return nil
}

// setupNetworking creates the TAP and the egress chains for inc; the slot
// must already be reserved (allocateNetworking).
func (b *Backend) setupNetworking(inc *incarnation) error {
	if err := b.ensureGlobalNet(); err != nil {
		return err
	}
	ns := inc.net
	if ns == nil {
		return fmt.Errorf("networking not allocated for incarnation %q", inc.id)
	}
	pol, err := egressPolicyFor(inc.spec)
	if err != nil {
		return err
	}
	run := func(args ...string) error {
		if out, err := sudo(args...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, out)
		}
		return nil
	}
	// Best-effort cleanup of partial device state from a previous failed
	// setup of THIS slot (leftovers of other incarnations are never
	// touched; the slot reservation is kept).
	b.cleanupNetDevices(ns)

	setupErr := func(err error) error {
		b.teardownNetworking(inc)
		return err
	}
	if err := run("ip", "tuntap", "add", "dev", ns.tap, "mode", "tap"); err != nil {
		return setupErr(err)
	}
	if err := run("ip", "addr", "add", ns.hostIP+"/30", "dev", ns.tap); err != nil {
		return setupErr(err)
	}
	if err := run("ip", "link", "set", ns.tap, "up"); err != nil {
		return setupErr(err)
	}
	// Egress chain order (first match wins):
	//  1. cloud metadata, always;
	//  2. link-local + the whole VM /16 (cross-VM and host tap side);
	//  3. policy denies, 4. policy allows, 5. default-deny.
	if err := run("iptables", "-N", ns.chain); err != nil {
		return setupErr(err)
	}
	for _, rule := range [][2]string{{"-d", metadataIP}, {"-d", linkLocalCIDR}, {"-d", vmSubnetCIDR}} {
		if err := run("iptables", "-A", ns.chain, rule[0], rule[1], "-j", "DROP"); err != nil {
			return setupErr(err)
		}
	}
	denies, err := destCIDRs(pol.Deny, true)
	if err != nil {
		return setupErr(err)
	}
	for _, d := range denies {
		if err := run("iptables", "-A", ns.chain, "-d", d, "-j", "DROP"); err != nil {
			return setupErr(err)
		}
	}
	allows, err := destCIDRs(pol.Allow, false)
	if err != nil {
		return setupErr(err)
	}
	for _, a := range allows {
		if err := run("iptables", "-A", ns.chain, "-d", a, "-j", "ACCEPT"); err != nil {
			return setupErr(err)
		}
	}
	if !pol.DefaultAllow {
		if err := run("iptables", "-A", ns.chain, "-j", "DROP"); err != nil {
			return setupErr(err)
		}
	}
	// Anti-spoofing DROP must precede the chain jump; the chain jump also
	// carries the source match as defense in depth. The chain is hooked
	// into both FORWARD (routed/NAT'd traffic) and INPUT (services on the
	// host itself) so host-bound traffic is governed by the same policy.
	for _, hook := range []string{"FORWARD", "INPUT"} {
		if err := run("iptables", "-I", hook, "-i", ns.tap, "!", "-s", ns.guestIP, "-j", "DROP"); err != nil {
			return setupErr(err)
		}
		if err := run("iptables", "-I", hook, "-i", ns.tap, "-s", ns.guestIP, "-j", ns.chain); err != nil {
			return setupErr(err)
		}
	}
	// IPv6: drop everything from this TAP host-side (belt and braces with
	// the in-guest sysctl disable).
	if err := run("ip6tables", "-N", ns.chain6); err != nil {
		return setupErr(err)
	}
	if err := run("ip6tables", "-A", ns.chain6, "-j", "DROP"); err != nil {
		return setupErr(err)
	}
	for _, hook := range []string{"FORWARD", "INPUT"} {
		if err := run("ip6tables", "-I", hook, "-i", ns.tap, "-j", ns.chain6); err != nil {
			return setupErr(err)
		}
	}
	return nil
}

// cleanupNetDevices removes the TAP, egress rules, and chains of ns.
// Best-effort; safe on partial state; never touches other slots.
func (b *Backend) cleanupNetDevices(ns *netState) {
	for _, hook := range []string{"FORWARD", "INPUT"} {
		sudo("iptables", "-D", hook, "-i", ns.tap, "!", "-s", ns.guestIP, "-j", "DROP").Run()
		sudo("iptables", "-D", hook, "-i", ns.tap, "-s", ns.guestIP, "-j", ns.chain).Run()
		sudo("ip6tables", "-D", hook, "-i", ns.tap, "-j", ns.chain6).Run()
	}
	sudo("iptables", "-F", ns.chain).Run()
	sudo("iptables", "-X", ns.chain).Run()
	sudo("ip6tables", "-F", ns.chain6).Run()
	sudo("ip6tables", "-X", ns.chain6).Run()
	sudo("ip", "link", "del", ns.tap).Run()
}

// teardownNetworking removes the incarnation's TAP, egress rules, and slot
// reservation. Safe on partial state; never touches other slots.
func (b *Backend) teardownNetworking(inc *incarnation) {
	if inc.net == nil {
		return
	}
	ns := inc.net
	b.cleanupNetDevices(ns)
	releaseSlot(inc.id, ns)
	inc.net = nil
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
