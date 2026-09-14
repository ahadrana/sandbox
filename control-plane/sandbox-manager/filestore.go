package sandboxmanager

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// FileStore is a durable Store: an append-only JSON journal with fsync per
// commit, plus an optional compacted snapshot. A torn final journal line
// (crash mid-write) is tolerated on load.
type FileStore struct {
	mu      sync.Mutex
	dir     string
	journal *os.File
	snap    Snapshot
}

const (
	journalName  = "journal.jsonl"
	snapshotName = "snapshot.json"
)

// OpenFileStore opens (or creates) a durable store rooted at dir and
// replays any existing snapshot+journal.
func OpenFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f := &FileStore{dir: dir, snap: emptySnapshot()}
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
	sawCorrupt := false
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var tx Tx
		if err := json.Unmarshal(line, &tx); err != nil {
			sawCorrupt = true
			continue
		}
		if sawCorrupt {
			// A corrupt line followed by a valid one cannot be a torn
			// final write: the journal itself is damaged. Fail loudly.
			return errors.New("filestore: corrupt journal line before end of journal")
		}
		applyTx(&f.snap, tx)
	}
	return nil
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

// Commit appends the transaction to the journal and fsyncs before returning.
func (f *FileStore) Commit(tx Tx) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	if _, err := f.journal.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := f.journal.Sync(); err != nil {
		return err
	}
	applyTx(&f.snap, tx)
	return nil
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
