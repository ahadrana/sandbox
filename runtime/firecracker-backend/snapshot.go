package firecrackerbackend

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// Incremental snapshot chains (ADR-006). A chain is a full base snapshot
// plus zero or more sparse diff memory files, each recording its parent in
// meta.json. Restore walks the chain (validating every link), materializes
// a merged memory file next to the chain, and loads it with the tip's
// vm.state — Firecracker v1.17 has no layered restore.

// maxChainLinks caps chain walks (cycle/runaway protection; well above
// any legitimate MaxSnapshotChainDepth).
const maxChainLinks = 64

// snapshotDirNamePattern whitelists snapshot dir names (unix-nanosecond
// timestamps) before a recorded parent pointer touches the filesystem.
var snapshotDirNamePattern = regexp.MustCompile(`^[0-9]{1,20}$`)

// chainLink is one validated link of a snapshot chain.
type chainLink struct {
	name string // dir name within the snapshot root
	dir  string
	meta snapshotMeta
}

// loadSnapshotChain reads and validates the chain ending at snapDir,
// returning the links tip-first with the full base last. Every link is
// package-validated (CI-4) and hash-verified (CI-3); linkage problems
// (missing parent, cycle, depth discontinuity, no full base) are typed
// errors (CI-2).
func (b *Backend) loadSnapshotChain(snapDir string) ([]chainLink, error) {
	chain := []chainLink{}
	dir := snapDir
	for len(chain) < maxChainLinks {
		name := filepath.Base(dir)
		metaBytes, err := os.ReadFile(filepath.Join(dir, "meta.json"))
		if err != nil {
			return nil, &SnapshotIncompatibleError{Field: "chain", Want: "meta.json in " + dir, Got: "unreadable: " + err.Error()}
		}
		var meta snapshotMeta
		if err := json.Unmarshal(metaBytes, &meta); err != nil {
			return nil, &SnapshotIncompatibleError{Field: "chain", Want: "valid meta.json in " + dir, Got: err.Error()}
		}
		if err := b.validateSnapshotPackage(&meta); err != nil {
			return nil, err
		}
		link := chainLink{name: name, dir: dir, meta: meta}
		if err := verifyLinkHashes(link); err != nil {
			return nil, err
		}
		if len(chain) > 0 {
			// CI-2: depth decreases by exactly one toward the base.
			child := chain[len(chain)-1]
			if child.meta.Depth != meta.Depth+1 {
				return nil, &SnapshotIncompatibleError{Field: "chain", Want: fmt.Sprintf("depth %d parent for %s (depth %d)", child.meta.Depth-1, child.name, child.meta.Depth), Got: fmt.Sprintf("%s has depth %d", name, meta.Depth)}
			}
		}
		chain = append(chain, link)
		if meta.Parent == "" {
			if meta.Kind == snapshotKindDiff {
				return nil, &SnapshotIncompatibleError{Field: "chain", Want: "full base at chain end", Got: name + " is a diff with no parent"}
			}
			return chain, nil
		}
		if !snapshotDirNamePattern.MatchString(meta.Parent) {
			return nil, &SnapshotIncompatibleError{Field: "chain", Want: "numeric parent dir name", Got: meta.Parent}
		}
		dir = filepath.Join(filepath.Dir(snapDir), meta.Parent)
	}
	return nil, &SnapshotIncompatibleError{Field: "chain", Want: fmt.Sprintf("<= %d links", maxChainLinks), Got: "chain walk exceeded the cap (cycle?)"}
}

// verifyLinkHashes checks the recorded sha256 of a link's memory and state
// files (CI-3). Links without recorded hashes (pre-ADR-006 snapshots) pass.
func verifyLinkHashes(l chainLink) error {
	check := func(field, recorded, path string) error {
		if recorded == "" {
			return nil
		}
		got, err := sha256File(path)
		if err != nil {
			return &SnapshotIncompatibleError{Field: field, Want: recorded, Got: "unreadable: " + err.Error()}
		}
		if got != recorded {
			return &SnapshotIncompatibleError{Field: field, Want: recorded, Got: got}
		}
		return nil
	}
	if err := check("mem_sha256", l.meta.MemSHA256, filepath.Join(l.dir, "mem.file")); err != nil {
		return err
	}
	return check("vm_state_sha256", l.meta.VMStateSHA256, filepath.Join(l.dir, "vm.state"))
}

// mergedMemName is the deterministic merged-artifact name for a chain tip
// (lives in the snapshot root next to the chain dirs; derived data, CI-1).
func mergedMemName(tipName string) string { return ".merged-" + tipName }

// mergeChainMem materializes the complete memory file for a validated
// chain and returns its path. Single-link (full) chains use the link's own
// memory file. For longer chains the merged file is the reflink-copied
// base with each diff's sparse extents applied in creation order (CI-5);
// it is reused across restores of the same tip (chain dirs are immutable),
// guarded by a sha256 sidecar so on-disk corruption of the merged artifact
// is detected and repaired rather than trusted.
func (b *Backend) mergeChainMem(chain []chainLink) (string, error) {
	base := chain[len(chain)-1]
	if len(chain) == 1 {
		return filepath.Join(base.dir, "mem.file"), nil
	}
	tip := chain[0]
	root := filepath.Dir(tip.dir)
	out := filepath.Join(root, mergedMemName(tip.name))
	sidecar := out + ".sha256"
	if recorded, err := os.ReadFile(sidecar); err == nil {
		if got, err := sha256File(out); err == nil && string(recorded) == got {
			return out, nil // intact merged artifact from an earlier restore
		}
		// Corrupt artifact: fall through and rebuild it.
	}
	tmp := out + ".tmp"
	os.Remove(tmp)
	if err := copyFile(tmp, filepath.Join(base.dir, "mem.file")); err != nil {
		return "", err
	}
	os.Chmod(tmp, 0o600)
	// Apply diffs oldest-first (chain is tip-first; the base is last).
	for i := len(chain) - 2; i >= 0; i-- {
		if err := applySparseFile(filepath.Join(chain[i].dir, "mem.file"), tmp); err != nil {
			os.Remove(tmp)
			return "", fmt.Errorf("merge diff %s: %w", chain[i].name, err)
		}
	}
	sum, err := sha256File(tmp)
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, out); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.WriteFile(sidecar, []byte(sum), 0o600); err != nil {
		return "", err
	}
	return out, nil
}
