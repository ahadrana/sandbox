package hostagent

import (
	"fmt"
	"io"
	"path"

	"github.com/agent-sandbox/platform/runtime/backend-interface"
	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

// Cross-host snapshot transfer (ADR-009): RestoreFrom pulls a checkpoint's
// snapshot package from a PackageSource (a peer host, in-process or over
// the host-agent RPC) into this host's backend, then runs the unchanged
// ADR-008 restore — fence validation, capacity accounting, and idempotent
// same-fence replay included.

// RestoreFrom restores cp on THIS host, first pulling the snapshot package
// from src when the backend does not already hold it. An already-live
// incarnation (same-fence replay) skips the transfer entirely.
func (h *HostAgent) RestoreFrom(cp backendinterface.CheckpointData, src backendinterface.PackageSource) (backendinterface.Handle, error) {
	h.mu.Lock()
	_, known := h.incarnations[cp.IncarnationID]
	h.mu.Unlock()
	if known {
		// Live or paused here already: no transfer, plain restore replay.
		return h.Restore(cp)
	}
	recv, ok := h.backend.(backendinterface.PackageReceiver)
	if !ok {
		return backendinterface.Handle{}, fmt.Errorf("backend cannot receive snapshot packages: %w", supervisor.ErrUnsupported)
	}
	snapDir := cp.Metadata["snapshot_dir"]
	if snapDir == "" {
		return backendinterface.Handle{}, fmt.Errorf("checkpoint %s has no snapshot_dir: %w", cp.IncarnationID, ErrInvalidCheckpoint)
	}
	tip := path.Base(snapDir)
	m, err := src.SnapshotPackageManifest(cp.IncarnationID, tip)
	if err != nil {
		return backendinterface.Handle{}, fmt.Errorf("snapshot package manifest: %w", err)
	}
	localDir, err := recv.ReceiveSnapshotPackage(m, func(rel string) (io.ReadCloser, error) {
		return src.FetchPackageFile(cp.IncarnationID, rel)
	})
	if err != nil {
		return backendinterface.Handle{}, fmt.Errorf("snapshot package transfer: %w", err)
	}
	// Point a COPY of the metadata at the local package and restore through
	// the unchanged validated path (ADR-009 decision 4).
	md := make(map[string]string, len(cp.Metadata)+1)
	for k, v := range cp.Metadata {
		md[k] = v
	}
	md["snapshot_dir"] = localDir
	return h.Restore(backendinterface.CheckpointData{
		IncarnationID: cp.IncarnationID,
		Files:         cp.Files,
		Metadata:      md,
	})
}

// SnapshotPackageManifest serves the source side of a transfer (ADR-009):
// the host's backend enumerates its local package; serving it pins the
// chain against GC for a bounded lease.
func (h *HostAgent) SnapshotPackageManifest(incarnationID, tip string) (backendinterface.SnapshotPackageManifest, error) {
	prov, ok := h.backend.(backendinterface.PackageProvider)
	if !ok {
		return backendinterface.SnapshotPackageManifest{}, fmt.Errorf("backend cannot serve snapshot packages: %w", supervisor.ErrUnsupported)
	}
	return prov.SnapshotPackageManifest(incarnationID, tip)
}

// FetchPackageFile opens one manifest-listed package file on this host.
func (h *HostAgent) FetchPackageFile(incarnationID, rel string) (io.ReadCloser, error) {
	prov, ok := h.backend.(backendinterface.PackageProvider)
	if !ok {
		return nil, fmt.Errorf("backend cannot serve snapshot packages: %w", supervisor.ErrUnsupported)
	}
	return prov.OpenPackageFile(incarnationID, rel)
}
