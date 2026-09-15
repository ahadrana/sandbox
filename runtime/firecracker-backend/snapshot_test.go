package firecrackerbackend

// Chain-walk, merge and GC unit tests (ADR-006) — no KVM required; the
// real-microVM chain regression tests are FC_TEST-gated in backend_test.go.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeFakeLink materializes a minimal but valid chain link: mem.file and
// vm.state with the given contents plus a meta.json recording kind, parent,
// depth and real sha256 hashes (like Snapshot does).
func writeFakeLink(t *testing.T, root, name, kind, parent string, depth int, mem, state []byte) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mem.file"), mem, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vm.state"), state, 0o600); err != nil {
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
	meta := snapshotMeta{
		Kind:          kind,
		Parent:        parent,
		Depth:         depth,
		MemSHA256:     memSHA,
		VMStateSHA256: stateSHA,
	}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func unitBackend(root string) *Backend {
	c := Config{Root: root}
	cfg := c.withDefaults()
	return &Backend{cfg: cfg, incs: map[string]*incarnation{}}
}

func TestApplySparseFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	base := make([]byte, 1<<20)
	for i := range base {
		base[i] = 0xAA
	}
	if err := os.WriteFile(out, base, 0o600); err != nil {
		t.Fatal(err)
	}
	// Sparse diff: holes everywhere except two written extents.
	diff := filepath.Join(dir, "diff")
	df, err := os.Create(diff)
	if err != nil {
		t.Fatal(err)
	}
	if err := df.Truncate(1 << 20); err != nil {
		t.Fatal(err)
	}
	ext1 := []byte("hello-extent-one")
	ext2 := make([]byte, 4096)
	for i := range ext2 {
		ext2[i] = 0x5A
	}
	if _, err := df.WriteAt(ext1, 4096); err != nil {
		t.Fatal(err)
	}
	if _, err := df.WriteAt(ext2, 512<<10); err != nil {
		t.Fatal(err)
	}
	df.Close()
	if err := applySparseFile(diff, out); err != nil {
		t.Fatalf("applySparseFile: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[4096:4096+len(ext1)]) != string(ext1) {
		t.Fatal("extent 1 not applied")
	}
	if got[512<<10] != 0x5A || got[(512<<10)+4095] != 0x5A {
		t.Fatal("extent 2 not applied")
	}
	if got[0] != 0xAA || got[100] != 0xAA {
		t.Fatal("untouched region clobbered")
	}
	// Regions the diff wrote as zeros stay applied (a zero page dirtied by
	// the guest must override the base); truncate-created holes in the
	// diff must NOT clobber the base. The truncate above makes everything
	// outside the two WriteAt extents a hole, so 0xAA must survive there.
	if got[256<<10] != 0xAA {
		t.Fatal("diff hole clobbered base content")
	}
}

func TestLoadSnapshotChainAndMerge(t *testing.T) {
	root := t.TempDir()
	mem0 := []byte("BASE----")
	writeFakeLink(t, root, "100", snapshotKindFull, "", 0, mem0, []byte("state0"))
	writeFakeLink(t, root, "200", snapshotKindDiff, "100", 1, []byte("BASE-x--"), []byte("state1"))
	writeFakeLink(t, root, "300", snapshotKindDiff, "200", 2, []byte("BASE-xy-"), []byte("state2"))
	b := unitBackend(root)
	chain, err := b.loadSnapshotChain(filepath.Join(root, "300"))
	if err != nil {
		t.Fatalf("loadSnapshotChain: %v", err)
	}
	if len(chain) != 3 || chain[0].name != "300" || chain[2].name != "100" {
		t.Fatalf("chain order wrong: %+v", chain)
	}
	// Small files have no holes, so merging is a whole-file overlay here;
	// the sparse-extent semantics are covered by TestApplySparseFile. Use
	// page-padded files for a meaningful merge.
	root2 := t.TempDir()
	page := 4096
	base := make([]byte, 4*page)
	copy(base, []byte("base"))
	writeFakeLink(t, root2, "100", snapshotKindFull, "", 0, base, []byte("s0"))
	// diff1: only page 1 differs; diff2: only page 3 differs.
	d1 := make([]byte, 4*page)
	copy(d1, base)
	copy(d1[page:], []byte("d1xx"))
	writeFakeLink(t, root2, "200", snapshotKindDiff, "100", 1, d1, []byte("s1"))
	d2 := make([]byte, 4*page)
	copy(d2, []byte("zzzz"))
	writeFakeLink(t, root2, "300", snapshotKindDiff, "200", 2, d2, []byte("s2"))
	b2 := unitBackend(root2)
	chain2, err := b2.loadSnapshotChain(filepath.Join(root2, "300"))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := b2.mergeChainMem(chain2)
	if err != nil {
		t.Fatalf("mergeChainMem: %v", err)
	}
	data, err := os.ReadFile(merged)
	if err != nil {
		t.Fatal(err)
	}
	// Whole-file diffs overlay in order: tip wins.
	if string(data[:4]) != "zzzz" {
		t.Fatalf("merged content = %q..., want tip overlay", data[:4])
	}
	// Reuse path: second merge returns the same artifact via the sidecar.
	again, err := b2.mergeChainMem(chain2)
	if err != nil || again != merged {
		t.Fatalf("merge reuse: %v %q", err, again)
	}
}

func TestLoadSnapshotChainCorruptMidDiff(t *testing.T) {
	root := t.TempDir()
	writeFakeLink(t, root, "100", snapshotKindFull, "", 0, []byte("base-mem"), []byte("s0"))
	writeFakeLink(t, root, "200", snapshotKindDiff, "100", 1, []byte("diff1-mem"), []byte("s1"))
	writeFakeLink(t, root, "300", snapshotKindDiff, "200", 2, []byte("diff2-mem"), []byte("s2"))
	// Corrupt the MID-CHAIN diff's memory file after the fact.
	if err := os.WriteFile(filepath.Join(root, "200", "mem.file"), []byte("tampered!"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := unitBackend(root)
	_, err := b.loadSnapshotChain(filepath.Join(root, "300"))
	var si *SnapshotIncompatibleError
	if !errors.As(err, &si) {
		t.Fatalf("corrupt mid-chain diff: err = %v, want SnapshotIncompatibleError", err)
	}
	if si.Field != "mem_sha256" {
		t.Fatalf("field = %q, want mem_sha256", si.Field)
	}
}

func TestLoadSnapshotChainBrokenLinkage(t *testing.T) {
	root := t.TempDir()
	writeFakeLink(t, root, "200", snapshotKindDiff, "100", 1, []byte("m"), []byte("s"))
	b := unitBackend(root)
	// Missing parent dir.
	if _, err := b.loadSnapshotChain(filepath.Join(root, "200")); err == nil {
		t.Fatal("missing parent must fail")
	}
	// Depth discontinuity.
	writeFakeLink(t, root, "100", snapshotKindFull, "", 5, []byte("m"), []byte("s"))
	if _, err := b.loadSnapshotChain(filepath.Join(root, "200")); err == nil {
		t.Fatal("depth discontinuity must fail")
	}
	// Diff with no parent at chain end.
	root2 := t.TempDir()
	writeFakeLink(t, root2, "100", snapshotKindDiff, "", 0, []byte("m"), []byte("s"))
	if _, err := unitBackend(root2).loadSnapshotChain(filepath.Join(root2, "100")); err == nil {
		t.Fatal("diff without parent or base must fail")
	}
	// Cycle.
	root3 := t.TempDir()
	writeFakeLink(t, root3, "100", snapshotKindDiff, "200", 1, []byte("m"), []byte("s"))
	writeFakeLink(t, root3, "200", snapshotKindDiff, "100", 2, []byte("m"), []byte("s"))
	if _, err := unitBackend(root3).loadSnapshotChain(filepath.Join(root3, "100")); err == nil {
		t.Fatal("cycle must fail")
	}
}

// ADR-006 GC: chain ancestors are never deleted (mid-chain deletion is
// refused); dead tips and unreferenced standalone snapshots are.
func TestGCSkipsChainAncestors(t *testing.T) {
	root := t.TempDir()
	snapRoot := filepath.Join(root, "snapshots", "inc-gc")
	// Old standalone full, then a live chain full+diff+diff.
	writeFakeLink(t, snapRoot, "100", snapshotKindFull, "", 0, []byte("m0"), []byte("s0"))
	writeFakeLink(t, snapRoot, "200", snapshotKindFull, "", 0, []byte("m1"), []byte("s1"))
	writeFakeLink(t, snapRoot, "300", snapshotKindDiff, "200", 1, []byte("m2"), []byte("s2"))
	writeFakeLink(t, snapRoot, "400", snapshotKindDiff, "300", 2, []byte("m3"), []byte("s3"))
	b := unitBackend(root)
	b.cfg.MaxSnapshotsPerIncarnation = 2
	b.gcSnapshots("inc-gc")
	entries, err := os.ReadDir(snapRoot)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	// With max=2 the GC deletes oldest-first among unreferenced dirs: the
	// standalone 100 goes, then the chain tip 400 (the only other
	// deletable dir). The ancestors 200 and 300 must survive — mid-chain
	// deletion is refused (ADR-006).
	if dirExists(filepath.Join(snapRoot, "100")) {
		t.Fatalf("standalone old snapshot should be GC'd: %v", got)
	}
	if !dirExists(filepath.Join(snapRoot, "200")) || !dirExists(filepath.Join(snapRoot, "300")) {
		t.Fatalf("chain ancestors must survive GC: %v", got)
	}
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// The merged-artifact GC removes .merged-<tip> only when the tip dir is
// gone and no live incarnation restores from it.
func TestGCMergedArtifactLifecycle(t *testing.T) {
	root := t.TempDir()
	snapRoot := filepath.Join(root, "snapshots", "inc-m")
	writeFakeLink(t, snapRoot, "100", snapshotKindFull, "", 0, []byte("m0"), []byte("s0"))
	b := unitBackend(root)
	b.cfg.MaxSnapshotsPerIncarnation = -1 // keep all dirs
	merged := filepath.Join(snapRoot, mergedMemName("100"))
	if err := os.WriteFile(merged, []byte("merged"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Live incarnation backed by the merged artifact: kept.
	b.incs["inc-m"] = &incarnation{id: "inc-m", mergedFrom: "100"}
	os.RemoveAll(filepath.Join(snapRoot, "100")) // tip dir gone
	b.gcSnapshots("inc-m")
	if _, err := os.Stat(merged); err != nil {
		t.Fatalf("merged artifact of live incarnation must be kept: %v", err)
	}
	// Incarnation gone: reclaimed.
	delete(b.incs, "inc-m")
	b.gcSnapshots("inc-m")
	if _, err := os.Stat(merged); !os.IsNotExist(err) {
		t.Fatalf("merged artifact should be GC'd, stat err = %v", err)
	}
}
