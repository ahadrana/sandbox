package firecrackerbackend

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/agent-sandbox/platform/runtime/backend-interface"
)

// Cross-host snapshot package transfer (ADR-009): the source backend
// enumerates and serves one incarnation's checkpoint chain (plus the
// referenced tools image) to a peer host; the destination stages, verifies,
// and atomically installs it, then restores through the unchanged path.

// pinLeaseDur bounds how long a manifest/blob request pins an incarnation's
// snapshot chain against GC. Every serve refreshes the lease; an abandoned
// transfer reverts to normal retention after expiry.
const pinLeaseDur = 10 * time.Minute

// packageLinkFiles is the fixed file set of a chain link dir.
var packageLinkFiles = []string{"meta.json", "mem.file", "vm.state", "rootfs.ext4", "workspace.img"}

var toolsRelPattern = regexp.MustCompile(`^tools/tools-[0-9a-f]{64}\.ext4$`)

// validatePackageRel whitelists a manifest/blob path: a chain link file
// ("<numeric link dir>/<known name>") or a content-addressed tools image.
// Anything else (traversal, absolute paths, unknown files) is rejected.
func validatePackageRel(rel string) error {
	if toolsRelPattern.MatchString(rel) {
		return nil
	}
	dir, file := filepath.Split(rel)
	dir = strings.TrimSuffix(dir, "/")
	if snapshotDirNamePattern.MatchString(dir) {
		for _, f := range packageLinkFiles {
			if file == f {
				return nil
			}
		}
	}
	return fmt.Errorf("firecrackerbackend: package path %q not servable", rel)
}

// pinActiveLocked reports whether the incarnation's chain is GC-pinned,
// sweeping expired leases lazily.
func (b *Backend) pinActiveLocked(incarnationID string) bool {
	expiry, ok := b.pins[incarnationID]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(b.pins, incarnationID)
		return false
	}
	return true
}

func (b *Backend) pinLocked(incarnationID string) {
	b.pins[incarnationID] = time.Now().Add(pinLeaseDur)
}

// SnapshotPackageManifest implements backendinterface.PackageProvider: the
// ordered file list (with sha256) for the chain ending at tip, plus the
// tools image the tip's saved VMM state references. Serving a manifest
// pins the chain against GC (ADR-009 decision 6).
func (b *Backend) SnapshotPackageManifest(incarnationID, tip string) (backendinterface.SnapshotPackageManifest, error) {
	if err := validateIncarnationID(incarnationID); err != nil {
		return backendinterface.SnapshotPackageManifest{}, err
	}
	if !snapshotDirNamePattern.MatchString(tip) {
		return backendinterface.SnapshotPackageManifest{}, fmt.Errorf("firecrackerbackend: invalid snapshot tip %q", tip)
	}
	root := b.snapshotDir(incarnationID)
	m := backendinterface.SnapshotPackageManifest{IncarnationID: incarnationID, Tip: tip}
	// Walk the chain tip -> base, collecting every link's files. Hashes for
	// mem/state come from the capture-time records (CI-3); the destination
	// re-validates the whole chain after the transfer anyway.
	dir := filepath.Join(root, tip)
	for links := 0; links < maxChainLinks; links++ {
		name := filepath.Base(dir)
		metaBytes, err := os.ReadFile(filepath.Join(dir, "meta.json"))
		if err != nil {
			return backendinterface.SnapshotPackageManifest{}, fmt.Errorf("snapshot package unreadable at %s: %w", dir, err)
		}
		var meta snapshotMeta
		if err := json.Unmarshal(metaBytes, &meta); err != nil {
			return backendinterface.SnapshotPackageManifest{}, fmt.Errorf("snapshot meta corrupt at %s: %w", dir, err)
		}
		for _, f := range packageLinkFiles {
			pf := backendinterface.PackageFile{Rel: name + "/" + f}
			p := filepath.Join(dir, f)
			st, err := os.Stat(p)
			if err != nil {
				return backendinterface.SnapshotPackageManifest{}, fmt.Errorf("snapshot package incomplete at %s: %w", p, err)
			}
			pf.Size = st.Size()
			switch f {
			case "mem.file":
				pf.SHA256 = meta.MemSHA256
				// Diff memory files are sparse (ADR-006): the receiver
				// re-materializes the holes from this extent map instead of
				// writing the streamed zeros (which would corrupt merges).
				if pf.Extents, err = fileExtents(p); err != nil {
					return backendinterface.SnapshotPackageManifest{}, err
				}
			case "vm.state":
				pf.SHA256 = meta.VMStateSHA256
			}
			if pf.SHA256 == "" { // legacy link without recorded hashes
				if pf.SHA256, err = sha256File(p); err != nil {
					return backendinterface.SnapshotPackageManifest{}, err
				}
			}
			m.Files = append(m.Files, pf)
		}
		if meta.Parent == "" {
			// The tools image is referenced by the tip's saved VMM state.
			if meta.ToolsImage != "" {
				rel := "tools/" + filepath.Base(meta.ToolsImage)
				if err := validatePackageRel(rel); err != nil {
					return backendinterface.SnapshotPackageManifest{}, err
				}
				p := filepath.Join(b.cfg.Root, rel)
				st, err := os.Stat(p)
				if err != nil {
					return backendinterface.SnapshotPackageManifest{}, fmt.Errorf("tools image %s: %w", p, err)
				}
				sum, err := sha256File(p)
				if err != nil {
					return backendinterface.SnapshotPackageManifest{}, err
				}
				m.Files = append(m.Files, backendinterface.PackageFile{Rel: rel, Size: st.Size(), SHA256: sum})
			}
			b.mu.Lock()
			b.pinLocked(incarnationID)
			b.mu.Unlock()
			return m, nil
		}
		if !snapshotDirNamePattern.MatchString(meta.Parent) {
			return backendinterface.SnapshotPackageManifest{}, fmt.Errorf("snapshot chain corrupt: parent %q", meta.Parent)
		}
		dir = filepath.Join(root, meta.Parent)
	}
	return backendinterface.SnapshotPackageManifest{}, fmt.Errorf("snapshot chain walk exceeded %d links (cycle?)", maxChainLinks)
}

// OpenPackageFile implements backendinterface.PackageProvider: open one
// manifest-listed file, refreshing the GC pin.
func (b *Backend) OpenPackageFile(incarnationID, rel string) (io.ReadCloser, error) {
	if err := validateIncarnationID(incarnationID); err != nil {
		return nil, err
	}
	if err := validatePackageRel(rel); err != nil {
		return nil, err
	}
	var p string
	if strings.HasPrefix(rel, "tools/") {
		p = filepath.Join(b.cfg.Root, rel)
	} else {
		p = filepath.Join(b.snapshotDir(incarnationID), rel)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.pinLocked(incarnationID)
	b.mu.Unlock()
	return f, nil
}

// ReceiveSnapshotPackage implements backendinterface.PackageReceiver:
// stream every manifest file through fetch into a staging dir, verify each
// against its manifest sha256, then atomically install the chain (rename
// per link dir; existing link dirs are immutable and complete — skipped).
// The staged meta.json files are rewritten to point tools_image at this
// backend's tools dir before install. Any failure removes the staging dir:
// no partial package is ever visible, and a retry resumes cleanly.
func (b *Backend) ReceiveSnapshotPackage(m backendinterface.SnapshotPackageManifest, fetch func(rel string) (io.ReadCloser, error)) (string, error) {
	if err := validateIncarnationID(m.IncarnationID); err != nil {
		return "", err
	}
	if !snapshotDirNamePattern.MatchString(m.Tip) {
		return "", fmt.Errorf("firecrackerbackend: invalid snapshot tip %q", m.Tip)
	}
	if len(m.Files) == 0 {
		return "", fmt.Errorf("firecrackerbackend: empty snapshot package manifest")
	}
	root := b.snapshotDir(m.IncarnationID)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	staging := filepath.Join(root, ".xfer-"+m.Tip)
	os.RemoveAll(staging) // clear a crashed prior attempt; retry is clean
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return "", err
	}
	cleanup := func(err error) (string, error) {
		os.RemoveAll(staging)
		return "", err
	}
	seenTools := ""
	for _, pf := range m.Files {
		if err := validatePackageRel(pf.Rel); err != nil {
			return cleanup(err)
		}
		rc, err := fetch(pf.Rel)
		if err != nil {
			return cleanup(fmt.Errorf("fetch %s: %w", pf.Rel, err))
		}
		dst := filepath.Join(staging, pf.Rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			rc.Close()
			return cleanup(err)
		}
		err = func() error {
			defer rc.Close()
			w, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			if len(pf.Extents) == 0 {
				// Whole file is data (or a legacy manifest with no map).
				if _, err := io.Copy(w, rc); err != nil {
					w.Close()
					return err
				}
			} else {
				// Sparse file (ADR-006 diffs): write only the data extents,
				// skipping the hole bytes in the stream, then size the file
				// so trailing holes read back as zeros.
				pos := int64(0)
				buf := make([]byte, 1<<20)
				for _, ex := range pf.Extents {
					if ex.Offset > pos {
						if _, err := io.CopyN(io.Discard, rc, ex.Offset-pos); err != nil {
							w.Close()
							return err
						}
						pos = ex.Offset
					}
					for remaining := ex.Length; remaining > 0; {
						n := int64(len(buf))
						if remaining < n {
							n = remaining
						}
						if _, err := io.ReadFull(rc, buf[:n]); err != nil {
							w.Close()
							return err
						}
						if _, err := w.WriteAt(buf[:n], pos); err != nil {
							w.Close()
							return err
						}
						pos += n
						remaining -= n
					}
				}
				if err := w.Truncate(pf.Size); err != nil {
					w.Close()
					return err
				}
			}
			if err := w.Close(); err != nil {
				return err
			}
			// Verify what landed (holes read as zeros, so the digest of the
			// re-sparsified file equals the full-stream digest).
			got, err := sha256File(dst)
			if err != nil {
				return err
			}
			if got != pf.SHA256 {
				return &SnapshotIncompatibleError{Field: "transfer_sha256", Want: pf.SHA256, Got: got}
			}
			return nil
		}()
		if err != nil {
			return cleanup(err)
		}
		if strings.HasPrefix(pf.Rel, "tools/") {
			seenTools = pf.Rel
		}
	}
	// Rewrite the tools-image path in every staged meta.json to THIS
	// backend's tools dir (the manifest lists the image by content address;
	// meta.json itself is not hash-protected — CI-3 covers mem/vm.state).
	for _, pf := range m.Files {
		if !strings.HasSuffix(pf.Rel, "/meta.json") {
			continue
		}
		p := filepath.Join(staging, pf.Rel)
		data, err := os.ReadFile(p)
		if err != nil {
			return cleanup(err)
		}
		var meta snapshotMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			return cleanup(fmt.Errorf("staged meta %s corrupt: %w", pf.Rel, err))
		}
		if meta.ToolsImage != "" {
			if seenTools == "" {
				return cleanup(fmt.Errorf("manifest lists no tools image but %s references one", pf.Rel))
			}
			meta.ToolsImage = filepath.Join(b.cfg.Root, seenTools)
			data, err = json.Marshal(meta)
			if err != nil {
				return cleanup(err)
			}
			if err := os.WriteFile(p, data, 0o600); err != nil {
				return cleanup(err)
			}
		}
	}
	// Install: per-link rename (atomic, same filesystem). A link dir that
	// already exists is complete and immutable (CI-1) — leave it.
	installed := map[string]bool{}
	for _, pf := range m.Files {
		rel := pf.Rel
		if strings.HasPrefix(rel, "tools/") {
			if installed[rel] {
				continue
			}
			installed[rel] = true
			dst := filepath.Join(b.cfg.Root, rel)
			if _, err := os.Stat(dst); err == nil {
				continue // content-addressed: already present
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return cleanup(err)
			}
			if err := os.Rename(filepath.Join(staging, rel), dst); err != nil {
				return cleanup(err)
			}
			continue
		}
		link := strings.SplitN(rel, "/", 2)[0]
		if installed[link] {
			continue
		}
		installed[link] = true
		dst := filepath.Join(root, link)
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		if err := os.Rename(filepath.Join(staging, link), dst); err != nil {
			return cleanup(err)
		}
	}
	os.RemoveAll(staging)
	return filepath.Join(root, m.Tip), nil
}
