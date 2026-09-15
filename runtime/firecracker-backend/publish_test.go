package firecrackerbackend

// KVM-free publish-path tests: rule construction, hook set, lifecycle,
// idempotence, and conflict semantics, against a stateful fake iptables
// (the pubSudo/pubNetRun indirection, mirroring flushGuestConntrack).

import (
	"errors"
	"os/exec"
	"strings"
	"sync"
	"testing"

	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
)

// fakeIPTables is a stateful nat-table fake: -N/-A/-D mutate the rule set,
// -C/-S answer from it, and every invocation is recorded.
type fakeIPTables struct {
	mu     sync.Mutex
	cmds   [][]string
	rules  map[string]bool // "A <rule args joined>" present
	chains map[string]bool
}

func newFakeIPTables() *fakeIPTables {
	return &fakeIPTables{rules: map[string]bool{}, chains: map[string]bool{}}
}

// install wires the fake into the publish path and restores on cleanup.
func (f *fakeIPTables) install(t *testing.T) {
	t.Helper()
	prevSudo, prevRun := pubSudo, pubNetRun
	pubSudo = f.cmd
	pubNetRun = f.run
	t.Cleanup(func() { pubSudo, pubNetRun = prevSudo, prevRun })
}

func (f *fakeIPTables) apply(args []string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, append([]string{}, args...))
	if len(args) < 2 || args[0] != "iptables" {
		return true
	}
	// normalize: strip "-t nat"
	rest := args[1:]
	if rest[0] == "-t" {
		rest = rest[2:]
	}
	key := strings.Join(rest[1:], " ")
	switch rest[0] {
	case "-N":
		f.chains[rest[1]] = true
		return true
	case "-X":
		delete(f.chains, rest[1])
		return true
	case "-F":
		for k := range f.rules {
			if strings.HasPrefix(k, rest[1]+" ") {
				delete(f.rules, k)
			}
		}
		return true
	case "-A":
		f.rules[key] = true
		return true
	case "-D":
		delete(f.rules, key)
		return true
	case "-C":
		return f.rules[key]
	case "-S":
		if len(rest) == 1 {
			return true
		}
		return f.chains[rest[1]]
	}
	return true
}

func (f *fakeIPTables) cmd(args ...string) *exec.Cmd {
	if f.apply(args) {
		return exec.Command("true")
	}
	return exec.Command("false")
}

func (f *fakeIPTables) run(args ...string) error {
	if f.apply(args) {
		return nil
	}
	return errors.New("fake iptables: " + strings.Join(args, " "))
}

func (f *fakeIPTables) has(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cmds {
		if strings.Contains(strings.Join(c, " "), substr) {
			return true
		}
	}
	return false
}

// pubBackend builds a Backend with one networked incarnation and no other
// machinery (PublishPort/UnpublishPort touch only b.mu/b.incs).
func pubBackend(incID string, slot int) *Backend {
	return &Backend{incs: map[string]*incarnation{
		incID: {id: incID, net: slotNames(slot)},
	}}
}

func pubReset(t *testing.T) {
	t.Helper()
	pubPorts.Lock()
	pubPorts.byPort = map[int]int{}
	pubPorts.Unlock()
	t.Cleanup(func() {
		pubPorts.Lock()
		pubPorts.byPort = map[int]int{}
		pubPorts.Unlock()
	})
}

func TestPublishRuleConstruction(t *testing.T) {
	rule := dnatRule("192.168.3.2", 8080, 18080)
	got := strings.Join(rule, " ")
	want := "-p tcp --dport 18080 -j DNAT --to-destination 192.168.3.2:8080"
	if got != want {
		t.Fatalf("dnatRule = %q, want %q", got, want)
	}
	if name := pubChainName(7); name != "FC-PUB-7" {
		t.Fatalf("pubChainName = %q", name)
	}
}

func TestPublishPortInstallsVerifiedRules(t *testing.T) {
	pubReset(t)
	fake := newFakeIPTables()
	fake.install(t)
	b := pubBackend("inc-pub", 7)
	h := backendinterface.Handle{IncarnationID: "inc-pub"}

	if err := b.PublishPort(h, 8080, 18080); err != nil {
		t.Fatal(err)
	}
	// Chain created, hooked from PREROUTING and OUTPUT (loopback excluded),
	// rule appended then verified.
	for _, want := range []string{
		"-t nat -N FC-PUB-7",
		"-t nat -A PREROUTING -j FC-PUB-7",
		"-t nat -A OUTPUT ! -d 127.0.0.0/8 -j FC-PUB-7",
		"-t nat -A FC-PUB-7 -p tcp --dport 18080 -j DNAT --to-destination 192.168.0.58:8080",
		"-t nat -C FC-PUB-7 -p tcp --dport 18080 -j DNAT --to-destination 192.168.0.58:8080",
	} {
		if !fake.has(want) {
			t.Fatalf("missing command %q in %v", want, fake.cmds)
		}
	}
	// Registry + bookkeeping.
	pubPorts.Lock()
	if pubPorts.byPort[18080] != 7 {
		t.Fatalf("registry = %v", pubPorts.byPort)
	}
	pubPorts.Unlock()
	ns := b.incs["inc-pub"].net
	ns.mu.Lock()
	if ns.published[18080] != 8080 {
		t.Fatalf("ns.published = %v", ns.published)
	}
	ns.mu.Unlock()

	// Idempotent re-publish (resume republish): no second -A.
	before := len(fake.cmds)
	if err := b.PublishPort(h, 8080, 18080); err != nil {
		t.Fatal(err)
	}
	for _, c := range fake.cmds[before:] {
		if strings.HasPrefix(strings.Join(c, " "), "iptables -t nat -A FC-PUB-7 -p tcp") {
			t.Fatalf("re-publish appended a duplicate rule: %v", c)
		}
	}

	// Unpublish removes exactly the DNAT rule and frees the port.
	if err := b.UnpublishPort(h, 18080); err != nil {
		t.Fatal(err)
	}
	if !fake.has("-t nat -D FC-PUB-7 -p tcp --dport 18080 -j DNAT --to-destination 192.168.0.58:8080") {
		t.Fatalf("missing rule delete in %v", fake.cmds)
	}
	pubPorts.Lock()
	if _, ok := pubPorts.byPort[18080]; ok {
		t.Fatal("port still registered after unpublish")
	}
	pubPorts.Unlock()
	// Unknown port is a no-op.
	if err := b.UnpublishPort(h, 29999); err != nil {
		t.Fatal(err)
	}
}

func TestPublishPortConflictDeterministic(t *testing.T) {
	pubReset(t)
	fake := newFakeIPTables()
	fake.install(t)
	b1 := pubBackend("inc-a", 7)
	b2 := pubBackend("inc-b", 8)
	h1 := backendinterface.Handle{IncarnationID: "inc-a"}
	h2 := backendinterface.Handle{IncarnationID: "inc-b"}

	if err := b1.PublishPort(h1, 8080, 18080); err != nil {
		t.Fatal(err)
	}
	// Another incarnation on the same host port: explicit typed error.
	err := b2.PublishPort(h2, 9000, 18080)
	if !errors.Is(err, backendinterface.ErrPortConflict) {
		t.Fatalf("err = %v, want ErrPortConflict", err)
	}
	// The loser's port is not registered and no DNAT rule was added for it.
	if fake.has("--to-destination 192.168.0.66:9000") {
		t.Fatal("conflicting publish installed a rule")
	}
	pubPorts.Lock()
	if pubPorts.byPort[18080] != 7 {
		t.Fatalf("registry clobbered by conflict: %v", pubPorts.byPort)
	}
	pubPorts.Unlock()
	// The SAME slot re-publishing the same port is not a conflict.
	if err := b1.PublishPort(h1, 8080, 18080); err != nil {
		t.Fatal(err)
	}
	// After the owner tears down, the port is free.
	cleanupPubRules(b1.incs["inc-a"].net)
	if err := b2.PublishPort(h2, 9000, 18080); err != nil {
		t.Fatalf("port not freed by teardown: %v", err)
	}
}

func TestPublishPortRequiresNetworking(t *testing.T) {
	pubReset(t)
	b := &Backend{incs: map[string]*incarnation{"inc-nonet": {id: "inc-nonet"}}}
	err := b.PublishPort(backendinterface.Handle{IncarnationID: "inc-nonet"}, 8080, 8080)
	if err == nil || !strings.Contains(err.Error(), "networking") {
		t.Fatalf("err = %v, want networking-required", err)
	}
	// Invalid ports rejected before touching iptables.
	b2 := pubBackend("inc-p", 3)
	if err := b2.PublishPort(backendinterface.Handle{IncarnationID: "inc-p"}, 0, 8080); err == nil {
		t.Fatal("guest port 0 accepted")
	}
	if err := b2.PublishPort(backendinterface.Handle{IncarnationID: "inc-p"}, 8080, 70000); err == nil {
		t.Fatal("host port 70000 accepted")
	}
}

func TestCleanupPubRulesRemovesEverything(t *testing.T) {
	pubReset(t)
	fake := newFakeIPTables()
	fake.install(t)
	b := pubBackend("inc-c", 5)
	h := backendinterface.Handle{IncarnationID: "inc-c"}
	if err := b.PublishPort(h, 8080, 18080); err != nil {
		t.Fatal(err)
	}
	if err := b.PublishPort(h, 9090, 19090); err != nil {
		t.Fatal(err)
	}
	// Another slot's port must survive our cleanup.
	pubPorts.Lock()
	pubPorts.byPort[23456] = 99
	pubPorts.Unlock()

	ns := b.incs["inc-c"].net
	cleanupPubRules(ns)
	for _, want := range []string{
		"-t nat -D PREROUTING -j FC-PUB-5",
		"-t nat -D OUTPUT ! -d 127.0.0.0/8 -j FC-PUB-5",
		"-t nat -F FC-PUB-5",
		"-t nat -X FC-PUB-5",
	} {
		if !fake.has(want) {
			t.Fatalf("cleanup missing %q in %v", want, fake.cmds)
		}
	}
	pubPorts.Lock()
	if len(pubPorts.byPort) != 1 || pubPorts.byPort[23456] != 99 {
		t.Fatalf("registry after cleanup = %v, want only slot 99's port", pubPorts.byPort)
	}
	pubPorts.Unlock()
	ns.mu.Lock()
	if ns.published != nil {
		t.Fatalf("published map not cleared: %v", ns.published)
	}
	ns.mu.Unlock()
}

// The capability flag follows Config.Networking exactly (truthful
// declaration): publish works only where networking exists.
func TestPublishCapabilityHonest(t *testing.T) {
	on := &Backend{cfg: Config{Networking: true}}
	off := &Backend{cfg: Config{}}
	if !on.Capabilities().SupportsPortPublish {
		t.Fatal("SupportsPortPublish false with Networking on")
	}
	if off.Capabilities().SupportsPortPublish {
		t.Fatal("SupportsPortPublish true with Networking off")
	}
}
