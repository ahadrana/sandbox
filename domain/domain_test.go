package domain

import (
	"math"
	"sync"
	"testing"
	"time"
)

// L8: itoa handles math.MinInt64 (the old hand-rolled version returned "-0").
func TestItoaMinInt64(t *testing.T) {
	if got := itoa(math.MinInt64); got != "-9223372036854775808" {
		t.Fatalf("itoa(MinInt64) = %q", got)
	}
	if got := itoa(0); got != "0" {
		t.Fatalf("itoa(0) = %q", got)
	}
}

// L8: ManualClock and IDGen are goroutine-safe; concurrent use never
// produces duplicate IDs.
func TestClockAndIDGenConcurrent(t *testing.T) {
	c := NewManualClock(time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC))
	g := NewIDGen()
	const n = 200
	var wg sync.WaitGroup
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Advance(time.Millisecond)
			_ = c.Now()
			ids[i] = g.Next("x")
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate ID %s", id)
		}
		seen[id] = true
	}
}

// Boot-scoped IDGen: two control-plane boots with the same prefixes produce
// disjoint ID spaces, so a restarted plane can never reissue an ID a
// long-lived host agent still remembers. Unscoped NewIDGen is unchanged.
func TestScopedIDGen(t *testing.T) {
	a := NewScopedIDGen("boota")
	b := NewScopedIDGen("bootb")
	if got := a.Next("inc"); got != "inc-boota-1" {
		t.Fatalf("scoped ID = %q, want inc-boota-1", got)
	}
	if got := b.Next("inc"); got != "inc-bootb-1" {
		t.Fatalf("scoped ID = %q, want inc-bootb-1", got)
	}
	if a.Next("inc") == b.Next("inc") {
		t.Fatal("scoped IDGens from different boots collided")
	}
	if got := NewIDGen().Next("inc"); got != "inc-1" {
		t.Fatalf("unscoped ID = %q, want inc-1", got)
	}
}
