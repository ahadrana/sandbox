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

// P1.7: the checkpoint-locality bonus only applies when the host's facts
// match the checkpoint's guard; a mismatching host is scored as if it held
// no checkpoint at all.
func TestCheckpointGuardScoresLocality(t *testing.T) {
	base := func(id string) HostView {
		return HostView{
			HostID:            id,
			Healthy:           true,
			CapacitySlots:     4,
			CapacityMemory:    1 << 30,
			UsedSlots:         1,
			UsedMemory:        1 << 28,
			CachedCheckpoints: map[string]bool{"sb-1": true},
			KernelRelease:     "6.8.0-1063-aws",
			CPUPart:           "0xd40",
		}
	}
	match := base("match")
	mismatch := base("mismatch")
	mismatch.KernelRelease = "5.15.0-1-generic"
	req := Request{
		SandboxID:      "sb-1",
		MemoryRequired: 1 << 28,
		CheckpointGuard: &Guard{
			KernelRelease: "6.8.0-1063-aws",
			CPUPart:       "0xd40",
		},
	}
	sMatch := score(req, match)
	sMismatch := score(req, mismatch)
	if sMatch-sMismatch != 3 {
		t.Fatalf("guard match should be worth the +3 checkpoint bonus: match=%v mismatch=%v", sMatch, sMismatch)
	}
	// The mismatching host scores exactly as if it held no checkpoint.
	noCheckpoint := match
	noCheckpoint.CachedCheckpoints = map[string]bool{}
	if sMismatch != score(req, noCheckpoint) {
		t.Fatalf("mismatched host score %v != no-checkpoint score %v", sMismatch, score(req, noCheckpoint))
	}
	// A nil guard (no restore in play) applies the bonus unconditionally.
	noGuard := Request{SandboxID: "sb-1", MemoryRequired: 1 << 28}
	if score(noGuard, mismatch) != sMatch {
		t.Fatalf("nil guard should keep the bonus: got %v want %v", score(noGuard, mismatch), sMatch)
	}
	// Placement actually prefers the guard-matching host.
	s := New()
	p, err := s.Place(req, []HostView{mismatch, match})
	if err != nil {
		t.Fatal(err)
	}
	if p.HostID != "match" {
		t.Fatalf("placed on %q, want guard-matching host", p.HostID)
	}
}
