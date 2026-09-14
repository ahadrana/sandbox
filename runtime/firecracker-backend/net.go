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
// per-incarnation TAP device, host NAT, and a per-incarnation iptables
// egress chain translating network.EgressPolicy semantics into packet rules.
// Requires passwordless sudo (`sudo -n ip`, `sudo -n iptables`); when
// Config.Networking is off no NIC is attached at all (fail-closed, and
// NetworkIsolated is declared false).

const (
	metadataIP       = "169.254.169.254"
	egressChainPfx   = "FC-EGR-"
	tapPfx           = "fc-tap-"
	masqueradeSubnet = "192.168.0.0/16"
)

// netState is one incarnation's host-side network plumbing.
type netState struct {
	tap     string
	hostIP  string
	guestIP string
	chain   string
	mac     string
}

// incKey is a stable per-incarnation identifier for kernel-visible names
// (tap/chain names must survive snapshot restore).
func incKey(incarnationID string) string {
	h := fnv.New32a()
	h.Write([]byte(incarnationID))
	return fmt.Sprintf("%08x", h.Sum32())
}

// netFor derives deterministic addressing from the incarnation ID: a /30
// pair inside 192.168.0.0/16 (two /30s per key half, collision-tolerant for
// test-scale fleets).
func netFor(incarnationID string) *netState {
	key := incKey(incarnationID)
	h := fnv.New32a()
	h.Write([]byte("ip/" + incarnationID))
	n := h.Sum32() % 8192 // 8192 /30s in 192.168.0.0/19
	a := n / 32
	third := (n % 32) * 8
	return &netState{
		tap:     tapPfx + key[:7],
		hostIP:  fmt.Sprintf("192.168.%d.%d", a, third+1),
		guestIP: fmt.Sprintf("192.168.%d.%d", a, third+2),
		chain:   egressChainPfx + key[:8],
		mac:     fmt.Sprintf("06:00:%02x:%02x:%02x:%02x", 0xAC, byte(n>>8), byte(n), 0x01),
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
	for _, bin := range []string{"ip", "iptables"} {
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
// process; failures surface on first use.
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

// setupNetworking creates the TAP and the egress chain for inc.
func (b *Backend) setupNetworking(inc *incarnation) error {
	if err := b.ensureGlobalNet(); err != nil {
		return err
	}
	ns := netFor(inc.id)
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
	// TAP (idempotent-ish: delete any leftover first).
	sudo("ip", "link", "del", ns.tap).Run()
	if err := run("ip", "tuntap", "add", "dev", ns.tap, "mode", "tap"); err != nil {
		return err
	}
	if err := run("ip", "addr", "add", ns.hostIP+"/30", "dev", ns.tap); err != nil {
		return err
	}
	if err := run("ip", "link", "set", ns.tap, "up"); err != nil {
		return err
	}
	// Egress chain: metadata DROP always first, then policy. The chain is
	// hooked into both FORWARD (routed/NAT'd traffic) and INPUT (services
	// on the host itself, e.g. the tap address) so host-bound traffic is
	// governed by the same policy.
	sudo("iptables", "-D", "FORWARD", "-i", ns.tap, "-j", ns.chain).Run()
	sudo("iptables", "-D", "INPUT", "-i", ns.tap, "-j", ns.chain).Run()
	sudo("iptables", "-F", ns.chain).Run()
	sudo("iptables", "-X", ns.chain).Run()
	if err := run("iptables", "-N", ns.chain); err != nil {
		return err
	}
	if err := run("iptables", "-A", ns.chain, "-d", metadataIP, "-j", "DROP"); err != nil {
		return err
	}
	denies, err := destCIDRs(pol.Deny, true)
	if err != nil {
		return err
	}
	for _, d := range denies {
		if err := run("iptables", "-A", ns.chain, "-d", d, "-j", "DROP"); err != nil {
			return err
		}
	}
	allows, err := destCIDRs(pol.Allow, false)
	if err != nil {
		return err
	}
	for _, a := range allows {
		if err := run("iptables", "-A", ns.chain, "-d", a, "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	if !pol.DefaultAllow {
		if err := run("iptables", "-A", ns.chain, "-j", "DROP"); err != nil {
			return err
		}
	}
	if err := run("iptables", "-I", "FORWARD", "-i", ns.tap, "-j", ns.chain); err != nil {
		return err
	}
	if err := run("iptables", "-I", "INPUT", "-i", ns.tap, "-j", ns.chain); err != nil {
		return err
	}
	inc.net = ns
	return nil
}

// teardownNetworking removes the incarnation's TAP and egress rules.
func (b *Backend) teardownNetworking(inc *incarnation) {
	if inc.net == nil {
		return
	}
	ns := inc.net
	sudo("iptables", "-D", "FORWARD", "-i", ns.tap, "-j", ns.chain).Run()
	sudo("iptables", "-D", "INPUT", "-i", ns.tap, "-j", ns.chain).Run()
	sudo("iptables", "-F", ns.chain).Run()
	sudo("iptables", "-X", ns.chain).Run()
	sudo("ip", "link", "del", ns.tap).Run()
	inc.net = nil
}

// networkUnit is injected (only when networking is enabled) to bring up the
// guest NIC with the static /30 pair.
const networkUnitTemplate = `[Unit]
Description=agent-sandbox guest network
Before=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'ip link set eth0 up && ip addr add %s/30 dev eth0 && ip route add default via %s && echo AGENT_NET_READY > /dev/ttyS0'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`
