package firecrackerbackend

// Tools-image GC unit tests (P0.3 follow-up) — KVM-free.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeToolsMeta writes a snapshot dir whose meta records the given
// supervisor sha (as Snapshot does), linking the chain via parent.
func writeToolsMeta(t *testing.T, root, name, parent string, depth int, supSHA string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := snapshotMeta{Kind: snapshotKindDiff, Parent: parent, Depth: depth, SupervisorSHA256: supSHA}
	if parent == "" {
		meta.Kind = snapshotKindFull
	}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func toolsBackend(t *testing.T) (*Backend, string) {
	t.Helper()
	root := t.TempDir()
	b := unitBackend(root)
	b.cfg.GuestSupervisorBin = filepath.Join(root, "guest-supervisor")
	if err := os.WriteFile(b.cfg.GuestSupervisorBin, []byte("bin"), 0o600); err != nil {
		t.Fatal(err)
	}
	toolsDir := filepath.Join(root, "tools")
	if err := os.MkdirAll(toolsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return b, toolsDir
}

func touchToolsImage(t *testing.T, toolsDir, sha string) string {
	t.Helper()
	p := filepath.Join(toolsDir, "tools-"+sha+".ext4")
	if err := os.WriteFile(p, []byte("img"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// An image referenced by a retained checkpoint — including through a
// MID-CHAIN link (every link carries SupervisorSHA256, ADR-006 CI-4) —
// survives GC; an unreferenced image and a stale .tmp are collected.
func TestToolsImageGCReferences(t *testing.T) {
	b, toolsDir := toolsBackend(t)
	snapRoot := filepath.Join(b.cfg.Root, "snapshots", "inc-1")
	// Chain: full base -> diff. The base references sha-old, the diff
	// references sha-new (supervisor upgraded between checkpoints).
	writeToolsMeta(t, snapRoot, "100", "", 0, "sha-old")
	writeToolsMeta(t, snapRoot, "200", "100", 1, "sha-new")
	pOld := touchToolsImage(t, toolsDir, "sha-old")
	pNew := touchToolsImage(t, toolsDir, "sha-new")
	pOrphan := touchToolsImage(t, toolsDir, "sha-orphan")
	tmp := filepath.Join(toolsDir, "tools-crashed.ext4.tmp")
	if err := os.WriteFile(tmp, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	b.gcToolsImages()
	for _, p := range []string{pOld, pNew} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("referenced image collected: %s", p)
		}
	}
	if _, err := os.Stat(pOrphan); !os.IsNotExist(err) {
		t.Fatal("unreferenced image survived GC")
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("stale .tmp build artifact survived GC")
	}
}

// A live incarnation's tools image survives even with no snapshots; once
// the incarnation is dead and no checkpoint references the sha, it goes.
func TestToolsImageGCLiveIncarnation(t *testing.T) {
	b, toolsDir := toolsBackend(t)
	pLive := touchToolsImage(t, toolsDir, "sha-live")
	b.incs["inc-live"] = &incarnation{id: "inc-live", toolsSHA: "sha-live"}
	b.gcToolsImages()
	if _, err := os.Stat(pLive); err != nil {
		t.Fatal("live incarnation's image collected")
	}
	b.mu.Lock()
	b.incs["inc-live"].dead = true
	b.mu.Unlock()
	b.gcToolsImages()
	if _, err := os.Stat(pLive); !os.IsNotExist(err) {
		t.Fatal("dead incarnation's unreferenced image survived GC")
	}
}

// M8: a .tmp from an IN-FLIGHT build (toolsMu held by the builder) is never
// deleted — the GC blocks on toolsMu until the build finishes; only after
// the builder releases (crash or completion) is the leftover collected.
func TestToolsImageGCSkipsInFlightTmp(t *testing.T) {
	b, toolsDir := toolsBackend(t)
	tmp := filepath.Join(toolsDir, "tools-building.ext4.tmp")
	if err := os.WriteFile(tmp, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Simulate an in-progress build: the builder holds toolsMu.
	b.toolsMu.Lock()
	done := make(chan struct{})
	go func() {
		b.gcToolsImages()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("gc completed while a build held toolsMu")
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Fatal("in-flight .tmp deleted by GC")
	}
	// Build finishes (crashed): the leftover is now collectible.
	b.toolsMu.Unlock()
	<-done
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("stale .tmp survived GC after build released toolsMu")
	}
}
