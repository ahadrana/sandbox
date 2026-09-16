//go:build !linux

package firecrackerbackend

import (
	"os"

	"github.com/agent-sandbox/platform/runtime/backend-interface"
)

// fileExtents on platforms without SEEK_DATA/SEEK_HOLE treats the whole
// file as one data extent: correct (holes become zeros), just not sparse —
// the same trade the merge path makes on these platforms.
func fileExtents(path string) ([]backendinterface.FileExtent, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() == 0 {
		return nil, nil
	}
	return []backendinterface.FileExtent{{Offset: 0, Length: fi.Size()}}, nil
}
