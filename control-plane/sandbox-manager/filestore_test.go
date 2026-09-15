package sandboxmanager

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-sandbox/platform/domain"
)

func commitSandbox(t *testing.T, f *FileStore, id string) {
	t.Helper()
	tx := Tx{Sandboxes: []*domain.Sandbox{{SandboxID: id}}}
	if err := f.Commit(tx); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

// P1.10 rule 2+3: every committed line is CRC-prefixed and replays.
func TestFileStoreCRCLinesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	f, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	commitSandbox(t, f, "sb-1")
	commitSandbox(t, f, "sb-2")
	data, err := os.ReadFile(filepath.Join(dir, journalName))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("journal lines = %d, want 2", len(lines))
	}
	for _, ln := range lines {
		if len(ln) < 10 || ln[8] != ' ' {
			t.Fatalf("line not CRC-prefixed: %q", ln)
		}
	}
	f.Close()
	f2, err := OpenFileStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	snap, err := f2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snap.Sandboxes["sb-1"]; !ok {
		t.Fatalf("sb-1 missing after replay")
	}
	if _, ok := snap.Sandboxes["sb-2"]; !ok {
		t.Fatalf("sb-2 missing after replay")
	}
	f2.Close()
}

// P1.10 rule 3: flipping a byte inside a CRC line is detected as
// corruption; a valid line after it fails the load loudly (rule 4).
func TestFileStoreCRCMismatchMidJournalIsFatal(t *testing.T) {
	dir := t.TempDir()
	f, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	commitSandbox(t, f, "sb-1")
	commitSandbox(t, f, "sb-2")
	f.Close()
	path := filepath.Join(dir, journalName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a payload byte in the FIRST line (mid-journal corruption).
	idx := strings.IndexByte(string(data), '{')
	if idx < 0 {
		t.Fatal("no json payload found")
	}
	data[idx+1] ^= 0x01
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(dir); err == nil || !strings.Contains(err.Error(), "corrupt journal line") {
		t.Fatalf("mid-journal CRC corruption must fail loudly, got %v", err)
	}
}

// P1.10 rule 4: a torn final line (valid CRC lines, then garbage) is
// discarded whole on load.
func TestFileStoreTornTailTolerated(t *testing.T) {
	dir := t.TempDir()
	f, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	commitSandbox(t, f, "sb-1")
	f.Close()
	path := filepath.Join(dir, journalName)
	jf, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jf.WriteString("1234abcd {\"Sandboxes\":[{\"SandboxID\":\"sb-2"); err != nil {
		t.Fatal(err)
	}
	jf.Close()
	f2, err := OpenFileStore(dir)
	if err != nil {
		t.Fatalf("torn tail must be tolerated: %v", err)
	}
	snap, _ := f2.Load()
	if _, ok := snap.Sandboxes["sb-1"]; !ok {
		t.Fatalf("sb-1 missing after torn-tail replay")
	}
	f2.Close()
}

// P1.10 rule 3 backward compatibility: legacy plain-JSON lines (no CRC
// prefix) still replay.
func TestFileStoreLegacyPlainJSONLines(t *testing.T) {
	dir := t.TempDir()
	tx := Tx{Sandboxes: []*domain.Sandbox{{SandboxID: "sb-legacy"}}}
	data, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, journalName), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := OpenFileStore(dir)
	if err != nil {
		t.Fatalf("legacy line must replay: %v", err)
	}
	snap, _ := f.Load()
	if _, ok := snap.Sandboxes["sb-legacy"]; !ok {
		t.Fatalf("legacy sandbox missing after replay")
	}
	f.Close()
}

// P1.10 compaction knobs: the byte trigger compacts inline once the
// journal exceeds CompactAfterBytes.
func TestFileStoreCompactionByteTrigger(t *testing.T) {
	dir := t.TempDir()
	f, err := OpenFileStoreWithOptions(dir, FileStoreOptions{CompactAfterBytes: 1, CompactAfterLines: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	commitSandbox(t, f, "sb-1")
	info, err := os.Stat(filepath.Join(dir, journalName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("byte trigger should have compacted; journal size = %d", info.Size())
	}
	if _, err := os.Stat(filepath.Join(dir, snapshotName)); err != nil {
		t.Fatalf("snapshot.json missing after compaction: %v", err)
	}
	snap, _ := f.Load()
	if _, ok := snap.Sandboxes["sb-1"]; !ok {
		t.Fatalf("state lost by compaction")
	}
}

// P1.10 compaction knobs: the line trigger compacts once more than
// CompactAfterLines lines accumulate since the last snapshot.
func TestFileStoreCompactionLineTrigger(t *testing.T) {
	dir := t.TempDir()
	f, err := OpenFileStoreWithOptions(dir, FileStoreOptions{CompactAfterBytes: -1, CompactAfterLines: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := 0; i < 3; i++ {
		commitSandbox(t, f, fmt.Sprint("sb-", i))
	}
	info, err := os.Stat(filepath.Join(dir, journalName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatalf("journal compacted too early (at 3 lines, trigger is >3)")
	}
	commitSandbox(t, f, "sb-3") // 4th line crosses the trigger
	info, err = os.Stat(filepath.Join(dir, journalName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("line trigger should have compacted; journal size = %d", info.Size())
	}
	snap, _ := f.Load()
	for i := 0; i < 4; i++ {
		if _, ok := snap.Sandboxes[fmt.Sprint("sb-", i)]; !ok {
			t.Fatalf("sb-%d lost by compaction", i)
		}
	}
}

// CRC helper kept honest: the writer's prefix matches crc32 of the payload.
func TestFileStoreCRCFormat(t *testing.T) {
	dir := t.TempDir()
	f, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	commitSandbox(t, f, "sb-crc")
	f.Close()
	data, err := os.ReadFile(filepath.Join(dir, journalName))
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(data))
	var want uint32
	if _, err := fmt.Sscanf(line[:8], "%08x", &want); err != nil {
		t.Fatalf("parse crc prefix: %v", err)
	}
	if got := crc32.ChecksumIEEE([]byte(line[9:])); got != want {
		t.Fatalf("crc prefix %08x != payload crc %08x", want, got)
	}
}
