package scheduler

import (
	"math"
	"testing"
)

// L4: zero-capacity hosts score 0 on that dimension, never NaN.
func TestScoreZeroCapacityNoNaN(t *testing.T) {
	h := HostView{HostID: "zero", Healthy: true, CapacitySlots: 0, CapacityMemory: 0}
	got := score(Request{}, h)
	if math.IsNaN(got) || math.IsInf(got, 0) {
		t.Fatalf("zero-capacity score = %v, want finite", got)
	}
	if got != 0 {
		t.Fatalf("zero-capacity score = %v, want 0", got)
	}
}

// L4: ReleaseFence drops the per-sandbox counter; the next placement starts
// a fresh fence sequence.
func TestReleaseFence(t *testing.T) {
	s := New()
	hosts := []HostView{{HostID: "h1", Healthy: true, CapacitySlots: 4, CapacityMemory: 1 << 20}}
	p1, err := s.Place(Request{SandboxID: "sb-1", MemoryRequired: 64}, hosts)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := s.Place(Request{SandboxID: "sb-1", MemoryRequired: 64}, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Fence != p1.Fence+1 {
		t.Fatalf("fences not monotonic: %d, %d", p1.Fence, p2.Fence)
	}
	s.ReleaseFence("sb-1")
	p3, err := s.Place(Request{SandboxID: "sb-1", MemoryRequired: 64}, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if p3.Fence != 1 {
		t.Fatalf("fence after release = %d, want fresh sequence at 1", p3.Fence)
	}
	// Other sandboxes are unaffected.
	pOther, err := s.Place(Request{SandboxID: "sb-2", MemoryRequired: 64}, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if pOther.Fence != 1 {
		t.Fatalf("sb-2 fence = %d, want 1", pOther.Fence)
	}
}
