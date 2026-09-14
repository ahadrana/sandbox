package sandboxmanager

import (
	"bufio"
	"bytes"
	"encoding/json"
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
			return err
		}
		mergeSnapshot(&f.snap, snap)
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
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var tx Tx
		if err := json.Unmarshal(line, &tx); err != nil {
			// Torn final write from a crash: ignore the partial record.
			break
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

// Snapshot compacts the journal: write snapshot.json atomically, truncate
// the journal.
func (f *FileStore) Snapshot() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := json.Marshal(f.snap)
	if err != nil {
		return err
	}
	tmp := filepath.Join(f.dir, snapshotName+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(f.dir, snapshotName)); err != nil {
		return err
	}
	if err := f.journal.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(f.dir, journalName), nil, 0o644); err != nil {
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
