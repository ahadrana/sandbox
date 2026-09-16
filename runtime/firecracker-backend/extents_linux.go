//go:build linux

package firecrackerbackend

import (
	"os"
	"syscall"

	"github.com/agent-sandbox/platform/runtime/backend-interface"
)

// fileExtents lists the data extents of a (possibly sparse) file via
// SEEK_DATA/SEEK_HOLE — the map a transfer receiver needs to re-materialize
// the holes instead of streaming them as literal zeros (ADR-009).
func fileExtents(path string) ([]backendinterface.FileExtent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	var out []backendinterface.FileExtent
	for off := int64(0); off < size; {
		data, err := syscall.Seek(int(f.Fd()), off, seekData)
		if err == syscall.ENXIO {
			break
		}
		if err != nil {
			return nil, err
		}
		hole, err := syscall.Seek(int(f.Fd()), data, seekHole)
		if err != nil {
			return nil, err
		}
		if hole > size {
			hole = size
		}
		out = append(out, backendinterface.FileExtent{Offset: data, Length: hole - data})
		off = hole
	}
	return out, nil
}
