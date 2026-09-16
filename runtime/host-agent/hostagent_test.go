package hostagent

// In-package tests that need to pin host-side accounting state directly.

import (
	"testing"

	backendinterface "github.com/agent-sandbox/platform/runtime/backend-interface"
	fakebackend "github.com/agent-sandbox/platform/runtime/fake-backend"
)

// Review L5: a live in-place restore adopting a fence must never regress
// rec.fence below an already-advanced value — adoption is a max, and
// h.fences still advances to the adopted fence.
func TestRestoreFenceNoRegression(t *testing.T) {
	h := New("h-test", fakebackend.New(), nil, nil, 1<<20, 4, 16)
	h.mu.Lock()
	h.incarnations["inc-1"] = &incRecord{sandboxID: "sb-1", fence: 5, paused: true, memory: 64}
	h.fences["sb-1"] = 3
	h.slotsUsed, h.memUsed = 1, 64
	h.mu.Unlock()
	cp := backendinterface.CheckpointData{
		IncarnationID: "inc-1",
		Metadata:      map[string]string{"fence": "4"},
	}
	if _, err := h.Restore(cp); err != nil {
		t.Fatal(err)
	}
	if got := h.incarnations["inc-1"].fence; got != 5 {
		t.Fatalf("rec.fence regressed to %d, want 5 (max)", got)
	}
	if got := h.fences["sb-1"]; got != 4 {
		t.Fatalf("h.fences = %d, want 4 (adopted fence)", got)
	}
}
