package firecrackerbackend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// KVM-free cross-host transfer tests (ADR-009): package manifest/serve and
// stage/verify/install between two backends with separate roots.

func transferTestBackend(t *testing.T) *Backend {
	t.Helper()
	b, err := New(Config{
		Root:           t.TempDir(),
		KernelPath:     "kernel",
		RootfsPath:     "rootfs",
		FirecrackerBin: "firecracker",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

// craftChainLink writes one snapshot link dir under the backend's snapshot
// root: mem.file filled with fill (with mutated bytes at mutateOff when
// non-negative), vm.state, both drive copies, and a meta.json recording the
// capture-time hashes (CI-3). Empty-fact metas skip P0.4 validation, so the
// chain loads on any host.
func craftChainLink(t *testing.T, b *Backend, inc, name string, kind snapshotKindT, parent string, depth int, fill byte, mutateOff int) string {
	t.Helper()
	dir := filepath.Join(b.snapshotDir(inc), name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mem := bytes.Repeat([]byte{fill}, 128*1024)
	if mutateOff >= 0 {
		for i := 0; i < 4096; i++ {
			mem[mutateOff+i] = 0xBB
		}
	}
	if kind == snapshotKindDiff {
		// A real diff memory file is sparse: only dirtied pages hold data.
		f, err := os.OpenFile(filepath.Join(dir, "mem.file"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteAt(mem[mutateOff:mutateOff+4096], int64(mutateOff)); err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(int64(len(mem))); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	} else if err := os.WriteFile(filepath.Join(dir, "mem.file"), mem, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vm.state"), []byte("vmstate-"+name), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rootfs.ext4"), []byte("rootfs-"+name), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "workspace.img"), []byte("ws-"+name), 0o600); err != nil {
		t.Fatal(err)
	}
	memSHA, err := sha256File(filepath.Join(dir, "mem.file"))
	if err != nil {
		t.Fatal(err)
	}
	stateSHA, err := sha256File(filepath.Join(dir, "vm.state"))
	if err != nil {
		t.Fatal(err)
	}
	meta := snapshotMeta{CreatedAt: time.Now(), MemSHA256: memSHA, VMStateSHA256: stateSHA}
	if kind == snapshotKindDiff {
		meta.Kind = snapshotKindDiff
		meta.Parent = parent
		meta.Depth = depth
	}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

type snapshotKindT = string

// craftChain builds a full base + one diff (mutating 4KiB of the base at
// 64KiB) and returns the tip name.
func craftChain(t *testing.T, b *Backend, inc string) (base, tip string) {
	t.Helper()
	base = "1000000000000000001"
	tip = "1000000000000000002"
	craftChainLink(t, b, inc, base, snapshotKindFull, "", 0, 0xAA, -1)
	craftChainLink(t, b, inc, tip, snapshotKindDiff, base, 1, 0x00, 64*1024)
	return base, tip
}

// fetchFrom returns a fetch closure reading blobs from the source backend,
// as the destination's ReceiveSnapshotPackage expects.
func fetchFrom(src *Backend, inc string) func(rel string) (io.ReadCloser, error) {
	return func(rel string) (io.ReadCloser, error) {
		return src.OpenPackageFile(inc, rel)
	}
}

// Full round-trip: manifest on the source, stage+verify+install on the
// destination, then the destination's own chain validation and merge —
// including the mutated memory from the diff — must succeed unchanged.
func TestSnapshotPackageTransferRoundTrip(t *testing.T) {
	src := transferTestBackend(t)
	dst := transferTestBackend(t)
	base, tip := craftChain(t, src, "inc-1")

	m, err := src.SnapshotPackageManifest("inc-1", tip)
	if err != nil {
		t.Fatal(err)
	}
	// Two links x five files; no tools image (stage-2 snapshot).
	if len(m.Files) != 10 {
		t.Fatalf("manifest files = %d, want 10: %v", len(m.Files), m.Files)
	}
	snapDir, err := dst.ReceiveSnapshotPackage(m, fetchFrom(src, "inc-1"))
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(dst.snapshotDir("inc-1"), tip)
	if snapDir != wantDir {
		t.Fatalf("installed tip = %q, want %q", snapDir, wantDir)
	}
	// The staging dir is gone; the chain dirs are visible and complete.
	if _, err := os.Stat(filepath.Join(dst.snapshotDir("inc-1"), ".xfer-"+tip)); !os.IsNotExist(err) {
		t.Fatalf("staging dir not cleaned: %v", err)
	}
	for _, link := range []string{base, tip} {
		for _, f := range packageLinkFiles {
			if _, err := os.Stat(filepath.Join(dst.snapshotDir("inc-1"), link, f)); err != nil {
				t.Fatalf("installed package incomplete: %s/%s: %v", link, f, err)
			}
		}
	}
	// The destination validates the chain (CI-2..CI-5) and merges the diff:
	// the mutation must land at 64KiB over the 0xAA base.
	chain, err := dst.loadSnapshotChain(snapDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain links = %d, want 2", len(chain))
	}
	memFile, err := dst.mergeChainMem(chain)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := os.ReadFile(memFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 128*1024 {
		t.Fatalf("merged size = %d", len(merged))
	}
	if !bytes.Equal(merged[64*1024:68*1024], bytes.Repeat([]byte{0xBB}, 4096)) {
		t.Fatal("merged memory lost the diff mutation")
	}
	if merged[0] != 0xAA || merged[64*1024-1] != 0xAA || merged[68*1024] != 0xAA {
		t.Fatal("merged memory lost base content outside the diff")
	}
	// A re-receive is a clean no-op (existing link dirs are immutable).
	if _, err := dst.ReceiveSnapshotPackage(m, fetchFrom(src, "inc-1")); err != nil {
		t.Fatalf("re-receive: %v", err)
	}
}

// A corrupted byte stream must be rejected loudly: the per-file sha256
// against the manifest fails with the typed incompatibility error and no
// package becomes visible.
func TestSnapshotPackageTransferHashMismatch(t *testing.T) {
	src := transferTestBackend(t)
	dst := transferTestBackend(t)
	base, tip := craftChain(t, src, "inc-1")
	m, err := src.SnapshotPackageManifest("inc-1", tip)
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(rel string) (io.ReadCloser, error) {
		rc, err := src.OpenPackageFile("inc-1", rel)
		if err != nil {
			return nil, err
		}
		if rel == base+"/mem.file" {
			data, _ := io.ReadAll(rc)
			rc.Close()
			data[1234] ^= 0xFF // corruption in transit
			return io.NopCloser(bytes.NewReader(data)), nil
		}
		return rc, nil
	}
	_, err = dst.ReceiveSnapshotPackage(m, fetch)
	if !IsSnapshotIncompatible(err) {
		t.Fatalf("err = %v, want SnapshotIncompatibleError", err)
	}
	// Nothing visible: no link dirs, no staging.
	entries, _ := os.ReadDir(dst.snapshotDir("inc-1"))
	for _, e := range entries {
		t.Fatalf("partial package visible after failed transfer: %s", e.Name())
	}
	// Retry with clean bytes succeeds.
	if _, err := dst.ReceiveSnapshotPackage(m, fetchFrom(src, "inc-1")); err != nil {
		t.Fatalf("retry after mismatch: %v", err)
	}
}

// An interrupted transfer (source fails mid-stream) leaves no visible
// package and no staging; a later retry succeeds.
func TestSnapshotPackageTransferInterrupted(t *testing.T) {
	src := transferTestBackend(t)
	dst := transferTestBackend(t)
	_, tip := craftChain(t, src, "inc-1")
	m, err := src.SnapshotPackageManifest("inc-1", tip)
	if err != nil {
		t.Fatal(err)
	}
	served := 0
	fetch := func(rel string) (io.ReadCloser, error) {
		served++
		if served == 4 {
			return nil, errors.New("connection reset")
		}
		return src.OpenPackageFile("inc-1", rel)
	}
	if _, err := dst.ReceiveSnapshotPackage(m, fetch); err == nil || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("err = %v, want connection reset", err)
	}
	entries, _ := os.ReadDir(dst.snapshotDir("inc-1"))
	for _, e := range entries {
		t.Fatalf("partial package visible after interrupted transfer: %s", e.Name())
	}
	if _, err := dst.ReceiveSnapshotPackage(m, fetchFrom(src, "inc-1")); err != nil {
		t.Fatalf("retry after interruption: %v", err)
	}
}

// Path safety: traversal and non-whitelisted paths are refused by both the
// serving and receiving sides.
func TestSnapshotPackagePathSafety(t *testing.T) {
	b := transferTestBackend(t)
	for _, rel := range []string{
		"../etc/passwd", "1000000000000000001/../../secret", "tools/../../etc/passwd",
		"abs//etc/passwd", "notanumber/mem.file", "1000000000000000001/evil.sh",
		"tools/tools-notasha.ext4", "",
	} {
		if _, err := b.OpenPackageFile("inc-1", rel); err == nil {
			t.Fatalf("OpenPackageFile(%q) succeeded", rel)
		}
		if err := validatePackageRel(rel); err == nil {
			t.Fatalf("validatePackageRel(%q) succeeded", rel)
		}
	}
	if _, err := b.SnapshotPackageManifest("inc-1", "../x"); err == nil {
		t.Fatal("manifest with traversal tip succeeded")
	}
	if _, err := b.SnapshotPackageManifest("../inc", "1000000000000000001"); err == nil {
		t.Fatal("manifest with traversal incarnation succeeded")
	}
}

// GC pinning (ADR-009 decision 6): serving a manifest pins the chain so
// gcSnapshots retains it beyond the retention bound; once the lease is gone
// (swept lazily at expiry) normal retention resumes.
func TestSnapshotPackageGCPinning(t *testing.T) {
	b := transferTestBackend(t)
	inc := "inc-1"
	// Five unreferenced full snapshots; retention keeps 3.
	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("100000000000000000%d", i)
		craftChainLink(t, b, inc, name, snapshotKindFull, "", 0, 0xAA, -1)
	}
	tip := "1000000000000000005"
	if _, err := b.SnapshotPackageManifest(inc, tip); err != nil {
		t.Fatal(err)
	}
	b.gcSnapshots(inc)
	entries, _ := os.ReadDir(b.snapshotDir(inc))
	if len(entries) != 5 {
		t.Fatalf("pinned chain GC'd: %d dirs remain, want 5", len(entries))
	}
	// Simulate lease expiry: the pin sweeps lazily on the next check.
	b.mu.Lock()
	b.pins[inc] = time.Now().Add(-time.Minute)
	b.mu.Unlock()
	b.gcSnapshots(inc)
	entries, _ = os.ReadDir(b.snapshotDir(inc))
	if len(entries) != 3 {
		t.Fatalf("retention after pin expiry = %d dirs, want 3", len(entries))
	}
	// Blob fetches also refresh the pin: add another snapshot past the
	// retention bound and confirm nothing is reclaimed.
	if _, err := b.SnapshotPackageManifest(inc, tip); err != nil {
		t.Fatal(err)
	}
	rc, err := b.OpenPackageFile(inc, tip+"/meta.json")
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
	craftChainLink(t, b, inc, "1000000000000000006", snapshotKindFull, "", 0, 0xAA, -1)
	b.gcSnapshots(inc)
	entries, _ = os.ReadDir(b.snapshotDir(inc))
	if len(entries) != 4 {
		t.Fatalf("re-pinned chain GC'd: %d dirs remain, want 4", len(entries))
	}
}

// A manifest for a checkpoint whose chain is incomplete (a mid-chain dir
// was deleted out of band) fails loudly at manifest time.
func TestSnapshotPackageManifestMissingLink(t *testing.T) {
	b := transferTestBackend(t)
	base, tip := craftChain(t, b, "inc-1")
	os.RemoveAll(filepath.Join(b.snapshotDir("inc-1"), base))
	if _, err := b.SnapshotPackageManifest("inc-1", tip); err == nil {
		t.Fatal("manifest succeeded over a broken chain")
	}
}
