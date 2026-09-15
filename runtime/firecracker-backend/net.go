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
//
// Policy generations (CubeSandbox P0.1 borrow): the egress chain name
// carries a generation (FC-EGR-<slot>-g<N>); every policy change and every
// snapshot restore bumps it and rebuilds the chain atomically, and the
// guest's conntrack entries are flushed so pre-change flows cannot ride
// stale NAT state. The rules are stateless, so every packet re-evaluates
// the new chain immediately — the generation makes the change observable
// and the flush covers restore-time flow re-admission.
//
// DNS learning (CubeSandbox P0.2 borrow, userspace): the guest resolver is
// the host TAP address, where a per-incarnation DNS proxy gates names
// through network.EvaluateEgress; allowed responses install (IP,TTL) /32
// allow entries for THIS incarnation only, reaped on TTL expiry. Hostname
// policy entries are pure DNS-gate entries — they are never resolved at
// chain-build time. A guest hardcoding its own resolver bypasses learning
// (fail-closed by omission under default-deny: the upstream resolver IP is
// not in the policy, so its DNS traffic is dropped like everything else).
//
// Atomic fail-closed updates (P0.5 borrow): every chain installation —
// initial setup, learned-entry batches, generation swaps — builds a
// scratch FC-TMP-* chain, verifies each rule with iptables -C, retargets
// the FORWARD/INPUT jumps, and only then deletes the old chain. A failure
// leaves the old complete chain (or, during initial setup, nothing — Start
// fails and teardown closes the gap); never a half-built policy.

const (
	metadataIP      = "169.254.169.254"
	linkLocalCIDR   = "169.254.0.0/16"
	vmSubnetCIDR    = "192.168.0.0/16"
	egressChainPfx  = "FC-EGR-"
	tmpChainPfx     = "FC-TMP-"
	egressChain6Pfx = "FC-EGR6-"
	tapPfx          = "fc-tap-"
	// dnsReapInterval is how often the chain-sync loop checks learned DNS
	// entries for TTL expiry.
	dnsReapInterval = time.Second
	// dnsBatchDelay coalesces bursts of learned entries into one chain
	// rebuild.
	dnsBatchDelay = 50 * time.Millisecond
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

// learnedEntry is one DNS-learned allow: an IP with its expiry.
type learnedEntry struct {
	expires time.Time
}

// netState is one incarnation's host-side network plumbing. slot/tap/
// hostIP/guestIP/chain6/mac are immutable after allocation; the mutable
// policy state (generation, policy, chain, learned) is guarded by mu, and
// chain installations are serialized by installMu.
type netState struct {
	slot    int
	tap     string
	hostIP  string
	guestIP string
	chain6  string
	mac     string

	mu           sync.Mutex
	installMu    sync.Mutex
	generation   int
	policy       network.EgressPolicy
	chain        string // active chain name: FC-EGR-<slot>-g<generation>
	learned      map[string]learnedEntry
	learnedOrder []string // insertion order for cap eviction
	dirty        bool     // chain content changed since last install
	dnsDenied    int64
	minTTL       time.Duration
	maxLearned   int
	now          func() time.Time
	published    map[int]int // hostPort -> guestPort (ADR-007 data plane)

	proxy    *dnsProxy
	syncCh   chan struct{}
	quit     chan struct{}
	syncDone chan struct{}
}

func egressChainName(slot, gen int) string {
	return fmt.Sprintf("%s%d-g%d", egressChainPfx, slot, gen)
}

func tmpChainName(slot, gen int) string {
	return fmt.Sprintf("%s%d-g%d", tmpChainPfx, slot, gen)
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

// checkNetPrereqs verifies the host can do TAP+iptables plumbing. The
// conntrack tool is optional: without it, generation bumps still swap the
// chain (stateless rules re-evaluate every packet) but stale NAT/conntrack
// state is not flushed — a warning is logged at flush time instead.
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

// flushGuestConntrack deletes all conntrack entries sourced by the guest,
// so a generation bump (policy change / snapshot restore) cannot leave
// pre-change flows admitted by stale NAT state. Best-effort: the egress
// rules are stateless, so the new chain already re-evaluates every packet;
// the flush is belt-and-braces for restore and future conntrack-aware
// rules. Overridable in tests.
var flushGuestConntrack = func(guestIP string) {
	if _, err := exec.LookPath("conntrack"); err != nil {
		fmt.Fprintf(os.Stderr, "firecrackerbackend: conntrack tool not found; skipping conntrack flush for %s (chain swap still applies)\n", guestIP)
		return
	}
	if out, err := sudo("conntrack", "-D", "-s", guestIP).CombinedOutput(); err != nil {
		// Exit 1 with "0 flow entries have been deleted" is the normal
		// nothing-to-flush case, not a failure.
		if !strings.Contains(string(out), "0 flow entries") {
			fmt.Fprintf(os.Stderr, "firecrackerbackend: conntrack flush -s %s: %v: %s\n", guestIP, err, out)
		}
	}
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
	// The per-incarnation DNS proxies bind :53 on their TAP host addresses;
	// when the backend runs unprivileged (conformance tests) port 53 needs
	// the unprivileged-port floor lowered. Production host agents run as
	// root and this is a no-op-equivalent for them.
	if out, err := sudo("sysctl", "-w", "net.ipv4.ip_unprivileged_port_start=0").CombinedOutput(); err != nil {
		return fmt.Errorf("lower unprivileged port floor (DNS proxy binds :53): %v: %s", err, out)
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

// staticDestinations translates a policy host list into iptables
// destinations: literal IPs, CIDRs, and "*" only. Hostname entries are NOT
// resolved here — they are DNS-gate entries enforced by the incarnation's
// DNS proxy (P0.2); resolving them at chain-build time is exactly the
// resolve-once staleness the DNS proxy replaces.
func staticDestinations(entries []string) []string {
	var out []string
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if e == "*" {
			out = append(out, "0.0.0.0/0")
			continue
		}
		if ip := net.ParseIP(strings.TrimPrefix(e, ".")); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				out = append(out, v4.String())
			}
			continue
		}
		if _, _, err := net.ParseCIDR(e); err == nil {
			out = append(out, e)
			continue
		}
		// hostname: DNS-gated, no static rule
	}
	return out
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

// setupNetworking creates the TAP, the generation-1 egress chain, and the
// DNS proxy for inc; the slot must already be reserved
// (allocateNetworkingLocked). Called without b.mu. On restore the caller
// pre-sets ns.generation to the snapshot's generation so the bumped
// generation invalidates pre-restore flows (P0.1).
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
	ns.mu.Lock()
	ns.generation++
	ns.policy = pol
	ns.learned = map[string]learnedEntry{}
	ns.learnedOrder = nil
	ns.dirty = false
	ns.minTTL = b.cfg.DNSMinTTL
	ns.maxLearned = b.cfg.DNSMaxLearned
	ns.now = time.Now
	ns.mu.Unlock()
	// Restored VMs inherit the snapshot's guest IP: drop any conntrack
	// state left by the pre-restore incarnation before new flows form.
	flushGuestConntrack(ns.guestIP)
	// Anti-spoofing DROP at hook position 1; the chain jump (position 2)
	// also carries the source match as defense in depth. The chain is
	// hooked into both FORWARD (routed/NAT'd traffic) and INPUT (services
	// on the host itself, including the DNS proxy) so host-bound traffic is
	// governed by the same policy.
	for _, hook := range []string{"FORWARD", "INPUT"} {
		if err := netRun("iptables", "-I", hook, "1", "-i", ns.tap, "!", "-s", ns.guestIP, "-j", "DROP"); err != nil {
			return setupErr(err)
		}
	}
	if err := b.installChain(ns, true); err != nil {
		return setupErr(err)
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
	// DNS learning proxy on the TAP host address (the guest's resolver),
	// plus the chain-sync loop applying learned-entry batches. syncDone is
	// only assigned when the loop actually starts, so a proxy-bind failure
	// cannot deadlock the teardown path on a goroutine that never ran.
	ns.syncCh = make(chan struct{}, 1)
	ns.quit = make(chan struct{})
	proxy, err := newDNSProxy(ns, b.cfg.DNSUpstream)
	if err != nil {
		return setupErr(err)
	}
	ns.syncDone = make(chan struct{})
	ns.proxy = proxy
	go b.chainSyncLoop(ns)
	return nil
}

func netRun(args ...string) error {
	if out, err := sudo(args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

// chainRules renders the full egress chain content for an incarnation.
// Rule order (first match wins): 1. cloud metadata, always; 2. the
// incarnation's DNS proxy (UDP+TCP 53 to the TAP host address only);
// 3. link-local + the whole VM /16 (cross-VM and host tap side);
// 4. policy denies (static IP/CIDR); 5. DNS-learned /32 allows;
// 6. policy allows (static IP/CIDR); 7. default-deny.
func chainRules(ns *netState, pol network.EgressPolicy, learned []string) [][]string {
	rules := [][]string{
		{"-d", metadataIP, "-j", "DROP"},
		{"-d", ns.hostIP + "/32", "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
		{"-d", ns.hostIP + "/32", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
		{"-d", linkLocalCIDR, "-j", "DROP"},
		{"-d", vmSubnetCIDR, "-j", "DROP"},
	}
	for _, d := range staticDestinations(pol.Deny) {
		rules = append(rules, []string{"-d", d, "-j", "DROP"})
	}
	for _, ip := range learned {
		rules = append(rules, []string{"-d", ip + "/32", "-j", "ACCEPT"})
	}
	for _, a := range staticDestinations(pol.Allow) {
		rules = append(rules, []string{"-d", a, "-j", "ACCEPT"})
	}
	if !pol.DefaultAllow {
		rules = append(rules, []string{"-j", "DROP"})
	}
	return rules
}

// learnedIPsLocked snapshots the unexpired learned IPs (sorted for chain
// determinism). Caller holds ns.mu.
func learnedIPsLocked(ns *netState) []string {
	now := ns.now()
	var out []string
	for ip, e := range ns.learned {
		if now.Before(e.expires) {
			out = append(out, ip)
		}
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// chainInstallFault, when set, is invoked at the named installation stage
// ("build", "verify", "swap") and aborts it — the P0.5 atomicity
// regression-test hook.
var chainInstallFault func(stage string) error

// installChain atomically (re)installs the incarnation's egress chain with
// the current policy+generation+learned set: build a scratch FC-TMP-*
// chain, verify every rule with iptables -C, retarget the FORWARD/INPUT
// jumps at it, then delete the old chain and rename the scratch into its
// generation name. A mid-install failure either leaves the old complete
// chain in place (swap) or aborts the initial setup (Start then fails and
// teardown closes the gap) — never a half-built policy (P0.5).
func (b *Backend) installChain(ns *netState, initial bool) error {
	ns.installMu.Lock()
	defer ns.installMu.Unlock()
	ns.mu.Lock()
	gen, pol := ns.generation, ns.policy
	learned := learnedIPsLocked(ns)
	oldChain := ns.chain
	ns.mu.Unlock()

	failStage := func(stage string) error {
		if chainInstallFault == nil {
			return nil
		}
		return chainInstallFault(stage)
	}
	scratch := tmpChainName(ns.slot, gen)
	newName := egressChainName(ns.slot, gen)
	rules := chainRules(ns, pol, learned)
	deleteChainQuiet(scratch)
	if err := failStage("build"); err != nil {
		return err
	}
	if err := netRun("iptables", "-N", scratch); err != nil {
		return err
	}
	abort := func(err error) error {
		deleteChainQuiet(scratch)
		return err
	}
	for _, r := range rules {
		if err := netRun(append([]string{"iptables", "-A", scratch}, r...)...); err != nil {
			return abort(err)
		}
	}
	if err := failStage("verify"); err != nil {
		return abort(err)
	}
	// Verify the scratch chain is complete before anything points at it.
	for _, r := range rules {
		if err := netRun(append([]string{"iptables", "-C", scratch}, r...)...); err != nil {
			return abort(fmt.Errorf("verify scratch chain: %w", err))
		}
	}
	if err := failStage("swap"); err != nil {
		return abort(err)
	}
	// Retarget the jumps. On swap, a failure mid-way rolls completed hooks
	// back to the old chain so both hooks always point at one complete
	// policy.
	var done []string
	swapErr := func() error {
		for _, hook := range []string{"FORWARD", "INPUT"} {
			if initial {
				if err := netRun("iptables", "-I", hook, "2", "-i", ns.tap, "-s", ns.guestIP, "-j", scratch); err != nil {
					return err
				}
			} else {
				pos, err := findJumpRule(hook, ns.tap, oldChain)
				if err != nil {
					return err
				}
				if err := netRun("iptables", "-R", hook, strconv.Itoa(pos), "-i", ns.tap, "-s", ns.guestIP, "-j", scratch); err != nil {
					return err
				}
			}
			done = append(done, hook)
		}
		return nil
	}()
	if swapErr != nil {
		if initial {
			for _, hook := range done {
				sudo("iptables", "-D", hook, "-i", ns.tap, "-s", ns.guestIP, "-j", scratch).Run()
			}
		} else {
			for _, hook := range done {
				if pos, err := findJumpRule(hook, ns.tap, scratch); err == nil {
					sudo("iptables", "-R", hook, strconv.Itoa(pos), "-i", ns.tap, "-s", ns.guestIP, "-j", oldChain).Run()
				}
			}
		}
		return abort(fmt.Errorf("chain swap: %w (old policy intact)", swapErr))
	}
	if oldChain != "" {
		deleteChainQuiet(oldChain)
	}
	if err := netRun("iptables", "-E", scratch, newName); err != nil {
		// The jumps already point at the scratch chain, which is complete
		// and correct — keep it as the active chain under its scratch name
		// rather than failing into a torn state.
		ns.mu.Lock()
		ns.chain = scratch
		ns.dirty = false
		ns.mu.Unlock()
		fmt.Fprintf(os.Stderr, "firecrackerbackend: rename %s -> %s failed (chain active under scratch name): %v\n", scratch, newName, err)
		return nil
	}
	ns.mu.Lock()
	ns.chain = newName
	ns.dirty = false
	ns.mu.Unlock()
	return nil
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

// deleteChainQuiet flushes and deletes a chain, ignoring errors (absent is
// indistinguishable from failure here, and both are fine).
func deleteChainQuiet(chain string) {
	sudo("iptables", "-F", chain).Run()
	sudo("iptables", "-X", chain).Run()
}

// chainSyncLoop applies learned-entry batches and TTL reaps to the chain:
// it wakes on requestChainSync signals or the reap tick, prunes expired
// entries, and rebuilds the chain when the content changed. Rebuilds are
// coalesced (dnsBatchDelay) so a DNS answer burst costs one install.
func (b *Backend) chainSyncLoop(ns *netState) {
	defer close(ns.syncDone)
	for {
		select {
		case <-ns.quit:
			return
		case <-ns.syncCh:
			time.Sleep(dnsBatchDelay)
		case <-time.After(dnsReapInterval):
		}
		ns.mu.Lock()
		now := ns.now()
		pruned := false
		for ip, e := range ns.learned {
			if !now.Before(e.expires) {
				delete(ns.learned, ip)
				pruned = true
			}
		}
		if pruned {
			kept := ns.learnedOrder[:0]
			for _, ip := range ns.learnedOrder {
				if _, ok := ns.learned[ip]; ok {
					kept = append(kept, ip)
				}
			}
			ns.learnedOrder = kept
		}
		dirty := ns.dirty || pruned
		ns.mu.Unlock()
		if !dirty {
			continue
		}
		if err := b.installChain(ns, false); err != nil {
			fmt.Fprintf(os.Stderr, "firecrackerbackend: egress chain sync %s: %v (keeping old rules)\n", ns.tap, err)
		}
	}
}

// requestChainSync asks the sync loop for a batched rebuild (non-blocking).
func requestChainSync(ns *netState) {
	if ns.syncCh == nil {
		return
	}
	select {
	case ns.syncCh <- struct{}{}:
	default:
	}
}

// learn records a DNS-answer IP for this incarnation with a clamped TTL,
// capping the set (oldest evicted), and schedules a batched chain rebuild.
func learnIP(ns *netState, ip string, ttl uint32) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.learned == nil {
		return // networking torn down
	}
	d := time.Duration(ttl) * time.Second
	if d < ns.minTTL {
		d = ns.minTTL
	}
	if e, ok := ns.learned[ip]; ok {
		// Refresh only: the chain rule already exists, no rebuild needed.
		e.expires = ns.now().Add(d)
		ns.learned[ip] = e
		return
	}
	for len(ns.learnedOrder) > 0 && len(ns.learned) >= ns.maxLearned {
		oldest := ns.learnedOrder[0]
		ns.learnedOrder = ns.learnedOrder[1:]
		delete(ns.learned, oldest)
	}
	ns.learned[ip] = learnedEntry{expires: ns.now().Add(d)}
	ns.learnedOrder = append(ns.learnedOrder, ip)
	ns.dirty = true
	requestChainSync(ns)
}

// SetEgressPolicy swaps the incarnation's egress policy on a live
// incarnation: the policy is persisted into the spec (snapshot restore
// carries it), the learned DNS set is dropped (entries were learned under
// the old policy), the generation is bumped, the chain rebuilt atomically,
// and the guest's conntrack state flushed (P0.1).
func (b *Backend) SetEgressPolicy(h backendinterface.Handle, pol network.EgressPolicy) error {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return err
	}
	prevEnv := inc.spec.Env
	env := map[string]string{}
	for k, v := range inc.spec.Env {
		env[k] = v
	}
	env["AGENT_SANDBOX_EGRESS"] = network.Serialize(pol)
	inc.spec.Env = env
	ns := inc.net
	b.mu.Unlock()
	if ns == nil {
		return nil
	}
	ns.mu.Lock()
	prevPol, prevGen := ns.policy, ns.generation
	prevLearned, prevOrder := ns.learned, ns.learnedOrder
	ns.policy = pol
	ns.generation++
	ns.learned = map[string]learnedEntry{}
	ns.learnedOrder = nil
	ns.mu.Unlock()
	flushGuestConntrack(ns.guestIP)
	// Transactional: a failed install leaves the old chain in place, so
	// the old policy/generation (and its learned set) are restored too.
	if err := b.installChain(ns, false); err != nil {
		ns.mu.Lock()
		ns.policy, ns.generation = prevPol, prevGen
		ns.learned, ns.learnedOrder = prevLearned, prevOrder
		ns.mu.Unlock()
		b.mu.Lock()
		inc.spec.Env = prevEnv
		b.mu.Unlock()
		return err
	}
	return nil
}

// EgressNetStatus is the observable networking state of one incarnation.
type EgressNetStatus struct {
	Generation     int
	Chain          string
	LearnedEntries int
	DNSDenied      int64
}

// EgressStatus reports the incarnation's egress policy generation, active
// chain, learned-entry count, and denied-DNS counter (P0.1/P0.2
// observability). Zero values when networking is off.
func (b *Backend) EgressStatus(h backendinterface.Handle) (EgressNetStatus, error) {
	b.mu.Lock()
	inc, err := b.get(h)
	if err != nil {
		b.mu.Unlock()
		return EgressNetStatus{}, err
	}
	ns := inc.net
	b.mu.Unlock()
	if ns == nil {
		return EgressNetStatus{}, nil
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return EgressNetStatus{
		Generation:     ns.generation,
		Chain:          ns.chain,
		LearnedEntries: len(ns.learned),
		DNSDenied:      ns.dnsDenied,
	}, nil
}

// cleanupNetDevices removes the TAP, egress rules, and chains of ns across
// ALL generations (including scratch chains). Best-effort; safe on partial
// state; never touches other slots. Stops the DNS proxy and the chain-sync
// loop first when they are running.
func cleanupNetDevices(ns *netState) {
	if ns.quit != nil {
		select {
		case <-ns.quit:
		default:
			close(ns.quit)
		}
	}
	if ns.syncDone != nil {
		<-ns.syncDone
	}
	if ns.proxy != nil {
		ns.proxy.close()
	}
	chainPfx := fmt.Sprintf("%s%d-", egressChainPfx, ns.slot)
	tmpPfx := fmt.Sprintf("%s%d-", tmpChainPfx, ns.slot)
	isOurs := func(name string) bool {
		return strings.HasPrefix(name, chainPfx) || strings.HasPrefix(name, tmpPfx)
	}
	for _, hook := range []string{"FORWARD", "INPUT"} {
		sudo("iptables", "-D", hook, "-i", ns.tap, "!", "-s", ns.guestIP, "-j", "DROP").Run()
		out, err := sudo("iptables", "-S", hook).CombinedOutput()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.HasPrefix(line, "-A ") || !strings.Contains(line, "-i "+ns.tap+" ") {
				continue
			}
			fields := strings.Fields(line)
			target := fields[len(fields)-1]
			if !isOurs(target) {
				continue
			}
			sudo(append([]string{"iptables", "-D"}, fields[1:]...)...).Run()
		}
		sudo("ip6tables", "-D", hook, "-i", ns.tap, "-j", ns.chain6).Run()
	}
	if out, err := sudo("iptables", "-S").CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "-N ") && isOurs(line[3:]) {
				deleteChainQuiet(line[3:])
			}
		}
	}
	sudo("ip6tables", "-F", ns.chain6).Run()
	sudo("ip6tables", "-X", ns.chain6).Run()
	cleanupPubRules(ns)
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
// (empty) stock resolv.conf at the incarnation's DNS-learning proxy on the
// TAP host address (P0.2).
const networkUnitTemplate = `[Unit]
Description=agent-sandbox guest network
Before=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'rm -f /etc/resolv.conf && echo nameserver %s > /etc/resolv.conf; sysctl -w net.ipv6.conf.all.disable_ipv6=1; sysctl -w net.ipv6.conf.eth0.disable_ipv6=1; ip link set eth0 up && ip addr add %s/30 dev eth0 && ip route add default via %s && echo AGENT_NET_READY > /dev/ttyS0'
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
	for _, spec := range []struct{ bin, pfx string }{{"iptables", egressChainPfx}, {"iptables", tmpChainPfx}, {"ip6tables", egressChain6Pfx}} {
		out, err := sudo(spec.bin, "-S").CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "firecrackerbackend: crash sweep: %s -S: %v: %s\n", spec.bin, err, out)
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "-N ") {
				if n, found := parseChainSlot(line[3:], spec.pfx); found {
					slots[n] = true
				}
			}
		}
	}
	// Published-port chains live in the nat table (ADR-007 data plane).
	if out, err := sudo("iptables", "-t", "nat", "-S").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "firecrackerbackend: crash sweep: iptables -t nat -S: %v: %s\n", err, out)
	} else {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "-N ") {
				if n, found := parseChainSlot(line[3:], pubChainPfx); found {
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
		fmt.Fprintf(os.Stderr, "firecrackerbackend: crash sweep: removing stale %s / %s* / %s\n", ns.tap, egressChainPfx, ns.chain6)
		cleanupNetDevices(ns)
	}
}

// parseSlotSuffix parses "<prefix><number>" names; the number must be a
// valid slot index so lookalike names are never matched.
func parseSlotSuffix(name, pfx string) (int, bool) {
	if !strings.HasPrefix(name, pfx) {
		return 0, false
	}
	n, err := strconv.Atoi(name[len(pfx):])
	if err != nil || n < 0 || n >= netSlotSpace {
		return 0, false
	}
	return n, true
}

// parseChainSlot parses chain names "<prefix><slot>" (legacy) or
// "<prefix><slot>-g<generation>"; the slot must be a valid index.
func parseChainSlot(name, pfx string) (int, bool) {
	if !strings.HasPrefix(name, pfx) {
		return 0, false
	}
	rest := name[len(pfx):]
	digits := rest
	for i, r := range rest {
		if r < '0' || r > '9' {
			digits = rest[:i]
			break
		}
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n < 0 || n >= netSlotSpace {
		return 0, false
	}
	return n, true
}
