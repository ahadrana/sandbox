package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/agent-sandbox/platform/domain"
)

// ErrIntegrityMismatch reports a digest verification failure on read.
var ErrIntegrityMismatch = errors.New("workspace integrity digest mismatch")

// Durable is a filesystem WorkspaceStore: content-addressed blobs plus
// digest-verified manifests, atomic head updates via rename.
type Durable struct {
	mu    sync.Mutex
	root  string
	clock domain.Clock
	ids   *domain.IDGen
}

type manifestFile struct {
	WorkspaceID      string            `json:"workspace_id"`
	Generation       int64             `json:"generation"`
	ParentGeneration *int64            `json:"parent_generation,omitempty"`
	CauseExecutionID *string           `json:"cause_execution_id,omitempty"`
	CommittedAt      string            `json:"committed_at"`
	ManifestRef      string            `json:"manifest_ref"`
	IntegrityDigest  string            `json:"integrity_digest"`
	Files            map[string]string `json:"files"` // path -> blob digest
}

type headFile struct {
	Workspace domain.Workspace `json:"workspace"`
	Pins      map[int64]int    `json:"pins"`
}

// OpenDurable opens (or creates) a durable workspace store rooted at root.
func OpenDurable(root string, clock domain.Clock, ids *domain.IDGen) (*Durable, error) {
	if err := os.MkdirAll(filepath.Join(root, "blobs"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, "workspaces"), 0o755); err != nil {
		return nil, err
	}
	return &Durable{root: root, clock: clock, ids: ids}, nil
}

func blobDigest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func (m *manifestFile) computeDigest() string {
	h := sha256.New()
	keys := make([]string, 0, len(m.Files))
	for k := range m.Files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(m.Files[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// syncDir fsyncs a directory so a rename inside it survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (d *Durable) wsDir(id string) string { return filepath.Join(d.root, "workspaces", id) }

func (d *Durable) headPath(id string) string { return filepath.Join(d.wsDir(id), "head.json") }

func (d *Durable) manifestPath(id string, gen int64) string {
	return filepath.Join(d.wsDir(id), "generations", fmt.Sprintf("%d.json", gen))
}

func (d *Durable) blobPath(digest string) string { return filepath.Join(d.root, "blobs", digest) }

func (d *Durable) readHead(id string) (*headFile, error) {
	data, err := os.ReadFile(d.headPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	var h headFile
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, err
	}
	if h.Pins == nil {
		h.Pins = map[int64]int{}
	}
	return &h, nil
}

func (d *Durable) writeHead(h *headFile) error {
	data, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return writeFileAtomic(d.headPath(h.Workspace.WorkspaceID), data)
}

func (d *Durable) readManifestFile(id string, gen int64) (*manifestFile, error) {
	data, err := os.ReadFile(d.manifestPath(id, gen))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	var m manifestFile
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.computeDigest() != m.IntegrityDigest {
		return nil, ErrIntegrityMismatch
	}
	return &m, nil
}

func (d *Durable) Create(tenantID, baseEnvironmentID string) (domain.Workspace, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := d.ids.Next("ws")
	ws := domain.Workspace{
		WorkspaceID:       id,
		TenantID:          tenantID,
		BaseEnvironmentID: baseEnvironmentID,
		HeadGeneration:    1,
	}
	m := &manifestFile{
		WorkspaceID: id,
		Generation:  1,
		CommittedAt: d.clock.Now().UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		ManifestRef: d.ids.Next("manifest"),
		Files:       map[string]string{},
	}
	m.IntegrityDigest = m.computeDigest()
	data, err := json.Marshal(m)
	if err != nil {
		return domain.Workspace{}, err
	}
	if err := writeFileAtomic(d.manifestPath(id, 1), data); err != nil {
		return domain.Workspace{}, err
	}
	if err := d.writeHead(&headFile{Workspace: ws, Pins: map[int64]int{}}); err != nil {
		return domain.Workspace{}, err
	}
	return ws, nil
}

func (d *Durable) Materialize(workspaceID string, generation int64) (map[string]string, error) {
	return d.ReadManifest(workspaceID, generation)
}

func (d *Durable) Commit(workspaceID string, parentGeneration int64, manifest map[string]string, causeExecutionID *string) (domain.WorkspaceGeneration, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	head, err := d.readHead(workspaceID)
	if err != nil {
		return domain.WorkspaceGeneration{}, err
	}
	if parentGeneration != head.Workspace.HeadGeneration {
		return domain.WorkspaceGeneration{}, domain.ErrGenerationConflict
	}
	m := &manifestFile{
		WorkspaceID:      workspaceID,
		Generation:       head.Workspace.HeadGeneration + 1,
		CauseExecutionID: causeExecutionID,
		CommittedAt:      d.clock.Now().UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		ManifestRef:      d.ids.Next("manifest"),
		Files:            map[string]string{},
	}
	parent := parentGeneration
	m.ParentGeneration = &parent
	for path, content := range manifest {
		digest := blobDigest(content)
		if _, err := os.Stat(d.blobPath(digest)); err != nil {
			if !os.IsNotExist(err) {
				return domain.WorkspaceGeneration{}, err
			}
			if err := writeFileAtomic(d.blobPath(digest), []byte(content)); err != nil {
				return domain.WorkspaceGeneration{}, err
			}
		}
		m.Files[path] = digest
	}
	m.IntegrityDigest = m.computeDigest()
	data, err := json.Marshal(m)
	if err != nil {
		return domain.WorkspaceGeneration{}, err
	}
	// Manifest first, then head: a crash between them leaves an unreferenced
	// generation, never a head pointing at a missing manifest.
	if err := writeFileAtomic(d.manifestPath(workspaceID, m.Generation), data); err != nil {
		return domain.WorkspaceGeneration{}, err
	}
	head.Workspace.HeadGeneration = m.Generation
	if err := d.writeHead(head); err != nil {
		return domain.WorkspaceGeneration{}, err
	}
	return generationOf(m), nil
}

func generationOf(m *manifestFile) domain.WorkspaceGeneration {
	t, _ := time.Parse(time.RFC3339Nano, m.CommittedAt)
	return domain.WorkspaceGeneration{
		WorkspaceID:      m.WorkspaceID,
		Generation:       m.Generation,
		ParentGeneration: m.ParentGeneration,
		ManifestRef:      m.ManifestRef,
		IntegrityDigest:  m.IntegrityDigest,
		CommittedAt:      t,
		CauseExecutionID: m.CauseExecutionID,
	}
}

func (d *Durable) GetHead(workspaceID string) (domain.WorkspaceGeneration, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	head, err := d.readHead(workspaceID)
	if err != nil {
		return domain.WorkspaceGeneration{}, err
	}
	m, err := d.readManifestFile(workspaceID, head.Workspace.HeadGeneration)
	if err != nil {
		return domain.WorkspaceGeneration{}, err
	}
	return generationOf(m), nil
}

// ReadManifest reads a generation, verifying the manifest digest and every
// blob digest.
func (d *Durable) ReadManifest(workspaceID string, generation int64) (map[string]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	m, err := d.readManifestFile(workspaceID, generation)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(m.Files))
	for path, digest := range m.Files {
		data, err := os.ReadFile(d.blobPath(digest))
		if err != nil {
			return nil, err
		}
		if blobDigest(string(data)) != digest {
			return nil, ErrIntegrityMismatch
		}
		out[path] = string(data)
	}
	return out, nil
}

func (d *Durable) Pin(workspaceID string, generation int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	head, err := d.readHead(workspaceID)
	if err != nil {
		return err
	}
	if _, err := d.readManifestFile(workspaceID, generation); err != nil {
		return err
	}
	head.Pins[generation]++
	return d.writeHead(head)
}

func (d *Durable) Unpin(workspaceID string, generation int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	head, err := d.readHead(workspaceID)
	if err != nil {
		return err
	}
	if head.Pins[generation] <= 0 {
		return domain.ErrNotFound
	}
	head.Pins[generation]--
	return d.writeHead(head)
}

// GC deletes unpinned non-head generations and unreferenced blobs.
func (d *Durable) GC(workspaceID string) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	head, err := d.readHead(workspaceID)
	if err != nil {
		return 0, err
	}
	removed := 0
	genDir := filepath.Join(d.wsDir(workspaceID), "generations")
	entries, err := os.ReadDir(genDir)
	if err != nil {
		return 0, err
	}
	referenced := map[string]bool{}
	for _, e := range entries {
		var gen int64
		if _, err := fmt.Sscanf(e.Name(), "%d.json", &gen); err != nil {
			continue
		}
		m, err := d.readManifestFile(workspaceID, gen)
		if err != nil {
			continue
		}
		if gen == head.Workspace.HeadGeneration || head.Pins[gen] > 0 {
			for _, digest := range m.Files {
				referenced[digest] = true
			}
			continue
		}
		if err := os.Remove(d.manifestPath(workspaceID, gen)); err != nil {
			return removed, err
		}
		removed++
	}
	// blobs/ is a shared content-addressed pool across all workspaces in the
	// store: before unlinking any blob, union in the references of every
	// other workspace's surviving generations.
	wsEntries, err := os.ReadDir(filepath.Join(d.root, "workspaces"))
	if err != nil {
		return removed, err
	}
	for _, we := range wsEntries {
		if !we.IsDir() || we.Name() == workspaceID {
			continue
		}
		otherGenDir := filepath.Join(d.root, "workspaces", we.Name(), "generations")
		genEntries, err := os.ReadDir(otherGenDir)
		if err != nil {
			continue
		}
		for _, e := range genEntries {
			var gen int64
			if _, err := fmt.Sscanf(e.Name(), "%d.json", &gen); err != nil {
				continue
			}
			m, err := d.readManifestFile(we.Name(), gen)
			if err != nil {
				continue
			}
			for _, digest := range m.Files {
				referenced[digest] = true
			}
		}
	}
	blobs, err := os.ReadDir(filepath.Join(d.root, "blobs"))
	if err != nil {
		return removed, err
	}
	for _, b := range blobs {
		if !referenced[b.Name()] {
			os.Remove(d.blobPath(b.Name()))
		}
	}
	return removed, nil
}
