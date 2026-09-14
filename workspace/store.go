// Package workspace defines the WorkspaceStore interface and an in-memory
// implementation with immutable committed generations.
package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"

	"github.com/agent-sandbox/platform/domain"
)

// Store is the durable workspace abstraction (DESIGN §6.4).
type Store interface {
	Create(tenantID, baseEnvironmentID string) (domain.Workspace, error)
	Materialize(workspaceID string, generation int64) (map[string]string, error)
	Commit(workspaceID string, parentGeneration int64, manifest map[string]string, causeExecutionID *string) (domain.WorkspaceGeneration, error)
	GetHead(workspaceID string) (domain.WorkspaceGeneration, error)
	ReadManifest(workspaceID string, generation int64) (map[string]string, error)
	Pin(workspaceID string, generation int64) error
	Unpin(workspaceID string, generation int64) error
	GC(workspaceID string) (int, error)
}

type generationData struct {
	gen      domain.WorkspaceGeneration
	manifest map[string]string
}

type workspaceData struct {
	ws          domain.Workspace
	generations map[int64]*generationData
	pins        map[int64]int
}

// Memory is an in-memory WorkspaceStore with generation semantics.
type Memory struct {
	mu    sync.Mutex
	clock domain.Clock
	ids   *domain.IDGen
	ws    map[string]*workspaceData
}

func NewMemory(clock domain.Clock, ids *domain.IDGen) *Memory {
	return &Memory{clock: clock, ids: ids, ws: map[string]*workspaceData{}}
}

func digestManifest(manifest map[string]string) string {
	h := sha256.New()
	keys := make([]string, 0, len(manifest))
	for k := range manifest {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(manifest[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func copyManifest(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (m *Memory) Create(tenantID, baseEnvironmentID string) (domain.Workspace, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.ids.Next("ws")
	ws := domain.Workspace{
		WorkspaceID:       id,
		TenantID:          tenantID,
		BaseEnvironmentID: baseEnvironmentID,
		HeadGeneration:    1,
	}
	data := &workspaceData{ws: ws, generations: map[int64]*generationData{}, pins: map[int64]int{}}
	manifest := map[string]string{}
	data.generations[1] = &generationData{
		gen: domain.WorkspaceGeneration{
			WorkspaceID:     id,
			Generation:      1,
			ManifestRef:     id + "/1",
			IntegrityDigest: digestManifest(manifest),
			CommittedAt:     m.clock.Now(),
		},
		manifest: manifest,
	}
	m.ws[id] = data
	return ws, nil
}

func (m *Memory) Materialize(workspaceID string, generation int64) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.ws[workspaceID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	g, ok := data.generations[generation]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return copyManifest(g.manifest), nil
}

func (m *Memory) Commit(workspaceID string, parentGeneration int64, manifest map[string]string, causeExecutionID *string) (domain.WorkspaceGeneration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.ws[workspaceID]
	if !ok {
		return domain.WorkspaceGeneration{}, domain.ErrNotFound
	}
	if parentGeneration != data.ws.HeadGeneration {
		return domain.WorkspaceGeneration{}, domain.ErrGenerationConflict
	}
	newGen := data.ws.HeadGeneration + 1
	parent := parentGeneration
	g := domain.WorkspaceGeneration{
		WorkspaceID:      workspaceID,
		Generation:       newGen,
		ParentGeneration: &parent,
		ManifestRef:      m.ids.Next("manifest"),
		IntegrityDigest:  digestManifest(manifest),
		CommittedAt:      m.clock.Now(),
		CauseExecutionID: causeExecutionID,
	}
	data.generations[newGen] = &generationData{gen: g, manifest: copyManifest(manifest)}
	data.ws.HeadGeneration = newGen
	return g, nil
}

func (m *Memory) GetHead(workspaceID string) (domain.WorkspaceGeneration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.ws[workspaceID]
	if !ok {
		return domain.WorkspaceGeneration{}, domain.ErrNotFound
	}
	return data.generations[data.ws.HeadGeneration].gen, nil
}

func (m *Memory) ReadManifest(workspaceID string, generation int64) (map[string]string, error) {
	return m.Materialize(workspaceID, generation)
}

func (m *Memory) Pin(workspaceID string, generation int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.ws[workspaceID]
	if !ok {
		return domain.ErrNotFound
	}
	if _, ok := data.generations[generation]; !ok {
		return domain.ErrNotFound
	}
	data.pins[generation]++
	return nil
}

func (m *Memory) Unpin(workspaceID string, generation int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.ws[workspaceID]
	if !ok {
		return domain.ErrNotFound
	}
	if data.pins[generation] > 0 {
		data.pins[generation]--
	}
	return nil
}

// GC removes unreferenced, unpinned, non-head generations.
func (m *Memory) GC(workspaceID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.ws[workspaceID]
	if !ok {
		return 0, domain.ErrNotFound
	}
	removed := 0
	for gen := range data.generations {
		if gen != data.ws.HeadGeneration && data.pins[gen] == 0 {
			delete(data.generations, gen)
			removed++
		}
	}
	return removed, nil
}
