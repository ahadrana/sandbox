package sandboxmanager

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// FileStore is a durable Store: an append-only JSON journal with fsync per
// commit, plus an optional compacted snapshot. A torn final journal line
// (crash mid-write) is tolerated on load.
//
// WAL discipline audit (P1.10, against CubeS3lvol's four journal rules):
//  1. One batch in flight: FileStore.mu serializes every Commit and every
//     Snapshot; a commit's write+fsync is atomic with respect to other
//     writers, and the in-memory snapshot is only updated after the fsync
//     returns.
//  2. Ack after fsync: Commit returns only after journal.Sync; callers
//     never observe committed state that is not durable.
//  3. Corruption detected as corruption: every journal line carries a
//     CRC32 of its payload ("<8-hex-crc> <json>\n"); a CRC mismatch is
//     treated exactly like unparseable JSON (torn tail tolerance below).
//     Legacy pre-CRC plain-JSON lines remain readable.
//  4. Torn tail discarded whole: trailing corrupt lines are skipped, but
//     any VALID line after a corrupt one fails the load loudly — a corrupt
//     line in the middle of the journal is damage, not a torn write.
//
// Compaction knobs: when the journal grows past CompactAfterBytes OR
// CompactAfterLines since the last snapshot, Commit compacts inline (the
// same mutex already held, so rule 1 is preserved).
type FileStore struct {
	mu      sync.Mutex
	dir     string
	journal *os.File
	snap    Snapshot
	opts    FileStoreOptions
	// journalBytes/journalLines track journal growth since the last
	// compaction (reset by Snapshot).
	journalBytes int64
	journalLines int
}

// FileStoreOptions tunes journal compaction (P1.10). Zero values use the
// defaults.
type FileStoreOptions struct {
	// CompactAfterBytes compacts the journal once it exceeds this many
	// bytes since the last snapshot (default 8 MiB; <=0 disables the
	// byte trigger).
	CompactAfterBytes int64
	// CompactAfterLines compacts once more than this many journal lines
	// were appended since the last snapshot (default 50000; <=0 disables
	// the line trigger).
	CompactAfterLines int
}

const (
	defaultCompactAfterBytes = 8 << 20
	defaultCompactAfterLines = 50000
)

func (o FileStoreOptions) withDefaults() FileStoreOptions {
	if o.CompactAfterBytes == 0 {
		o.CompactAfterBytes = defaultCompactAfterBytes
	}
	if o.CompactAfterLines == 0 {
		o.CompactAfterLines = defaultCompactAfterLines
	}
	return o
}

const (
	journalName  = "journal.jsonl"
	snapshotName = "snapshot.json"
)

// OpenFileStore opens (or creates) a durable store rooted at dir and
// replays any existing snapshot+journal, with default compaction knobs.
func OpenFileStore(dir string) (*FileStore, error) {
	return OpenFileStoreWithOptions(dir, FileStoreOptions{})
}

// OpenFileStoreWithOptions is OpenFileStore with explicit compaction knobs.
func OpenFileStoreWithOptions(dir string, opts FileStoreOptions) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f := &FileStore{dir: dir, snap: emptySnapshot(), opts: opts.withDefaults()}
	if err := f.load(); err != nil {
		return nil, err
	}
	j, err := os.OpenFile(filepath.Join(dir, journalName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	f.journal = j
	return f, nil
}

func (f *FileStore) load() error {
	if data, err := os.ReadFile(filepath.Join(f.dir, snapshotName)); err == nil {
		var snap Snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			// A corrupt snapshot (e.g. crash mid-rename left a partial
			// file) must not brick the store: quarantine it aside and
			// recover by replaying the journal from scratch.
			quarantine := filepath.Join(f.dir, snapshotName+".corrupt")
			os.Remove(quarantine)
			if rerr := os.Rename(filepath.Join(f.dir, snapshotName), quarantine); rerr != nil {
				return rerr
			}
		} else {
			mergeSnapshot(&f.snap, snap)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := os.ReadFile(filepath.Join(f.dir, journalName))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	f.journalBytes = int64(len(data))
	sawCorrupt := false
	for sc.Scan() {
		line := sc.Bytes()
		payload := bytes.TrimSpace(line)
		if len(payload) == 0 {
			continue
		}
		// P1.10 rule 3: CRC-prefixed lines ("<8-hex-crc> <json>") are
		// verified; a mismatch is corruption, not data. Legacy plain-JSON
		// lines (starting with '{') are accepted as-is.
		if len(payload) > 9 && payload[8] == ' ' && isHex8(payload[:8]) {
			want, err := strconv.ParseUint(string(payload[:8]), 16, 32)
			if err != nil || crc32.ChecksumIEEE(payload[9:]) != uint32(want) {
				sawCorrupt = true
				continue
			}
			payload = payload[9:]
		}
		var tx Tx
		if err := json.Unmarshal(payload, &tx); err != nil {
			sawCorrupt = true
			continue
		}
		if sawCorrupt {
			// A corrupt line followed by a valid one cannot be a torn
			// final write: the journal itself is damaged. Fail loudly.
			return errors.New("filestore: corrupt journal line before end of journal")
		}
		applyTx(&f.snap, tx)
		f.journalLines++
	}
	return nil
}

// isHex8 reports whether b is exactly 8 lowercase hex digits (the journal
// CRC prefix shape). Uppercase is rejected so a JSON payload can never be
// mistaken for a CRC line.
func isHex8(b []byte) bool {
	if len(b) != 8 {
		return false
	}
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func mergeSnapshot(dst *Snapshot, src Snapshot) {
	for k, v := range src.Sandboxes {
		dst.Sandboxes[k] = v
	}
	for k, v := range src.Executions {
		dst.Executions[k] = v
	}
	for k, v := range src.Incarnations {
		dst.Incarnations[k] = v
	}
	for k, v := range src.IdempotencyKeys {
		dst.IdempotencyKeys[k] = v
	}
	for k, v := range src.Outcomes {
		dst.Outcomes[k] = v
	}
	for k, v := range src.Leases {
		dst.Leases[k] = v
	}
	for k, v := range src.Checkpoints {
		dst.Checkpoints[k] = v
	}
	for k, v := range src.Bindings {
		dst.Bindings[k] = v
	}
	dst.Events = append(dst.Events, src.Events...)
}

// Commit appends the transaction to the journal and fsyncs before returning
// (WAL rule 2: the ack lands after the fsync). When the journal has grown
// past either compaction knob since the last snapshot, Commit compacts
// inline before returning.
func (f *FileStore) Commit(tx Tx) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	// P1.10 rule 3: prefix the CRC32 of the payload so corruption is
	// detected as corruption on replay.
	line := fmt.Sprintf("%08x %s\n", crc32.ChecksumIEEE(data), data)
	if _, err := f.journal.WriteString(line); err != nil {
		return err
	}
	if err := f.journal.Sync(); err != nil {
		return err
	}
	applyTx(&f.snap, tx)
	f.journalBytes += int64(len(line))
	f.journalLines++
	if f.compactionDue() {
		return f.snapshotLocked()
	}
	return nil
}

// compactionDue reports whether the journal has grown past a configured
// knob since the last snapshot.
func (f *FileStore) compactionDue() bool {
	if f.opts.CompactAfterBytes > 0 && f.journalBytes > f.opts.CompactAfterBytes {
		return true
	}
	return f.opts.CompactAfterLines > 0 && f.journalLines > f.opts.CompactAfterLines
}

func (f *FileStore) Load() (Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return copySnapshot(f.snap), nil
}

// Snapshot compacts the journal. Crash-atomic ordering: fsync the snapshot
// tmp file, rename it into place, fsync the directory, then truncate the
// journal and fsync the journal file and directory. A crash before the
// rename leaves the old snapshot+journal intact; a crash after the rename
// but before the truncation replays journal records already present in the
// snapshot (applyTx is idempotent); a crash during truncation can only lose
// journal records whose state is already durable in the fsynced snapshot.
func (f *FileStore) Snapshot() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshotLocked()
}

// snapshotLocked is Snapshot with the mutex already held (inline
// compaction from Commit; WAL rule 1 preserved).
func (f *FileStore) snapshotLocked() error {
	data, err := json.Marshal(f.snap)
	if err != nil {
		return err
	}
	tmp := filepath.Join(f.dir, snapshotName+".tmp")
	tf, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := tf.Write(data); err != nil {
		tf.Close()
		return err
	}
	if err := tf.Sync(); err != nil {
		tf.Close()
		return err
	}
	if err := tf.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(f.dir, snapshotName)); err != nil {
		return err
	}
	if err := syncDir(f.dir); err != nil {
		return err
	}
	if err := f.journal.Close(); err != nil {
		return err
	}
	jf, err := os.OpenFile(filepath.Join(f.dir, journalName), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := jf.Sync(); err != nil {
		jf.Close()
		return err
	}
	if err := jf.Close(); err != nil {
		return err
	}
	j, err := os.OpenFile(filepath.Join(f.dir, journalName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	f.journal = j
	f.journalBytes = 0
	f.journalLines = 0
	return syncDir(f.dir)
}

func (f *FileStore) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.journal.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
