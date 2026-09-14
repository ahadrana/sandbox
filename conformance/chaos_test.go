// Chaos qualification (PLAN §14): seeded fault-injection runs across the
// fake backend (3 seeds x 300 ops) and a local-fleet smoke run with real
// processes.
package conformance

import (
	"testing"

	"github.com/agent-sandbox/platform/chaos"
)

func TestChaosFakeSeeds(t *testing.T) {
	for _, seed := range []int64{11, 22, 33} {
		t.Run("", func(t *testing.T) {
			report := chaos.Run(t, chaos.Config{Seed: seed, Ops: 300, Sandboxes: 10})
			t.Logf("seed %d faults: %v tolerated-failures: %v", seed, report.FaultsInjected, report.OpsFailed)
		})
	}
}

func TestChaosFleetSmoke(t *testing.T) {
	report := chaos.Run(t, chaos.Config{Seed: 77, Ops: 60, Fleet: true, Sandboxes: 6})
	t.Logf("fleet faults: %v tolerated-failures: %v", report.FaultsInjected, report.OpsFailed)
}
