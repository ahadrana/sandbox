//go:build linux

package firecrackerbackend

import (
	"fmt"
	"os"
	"syscall"
)

// Linux lseek whence values (not exported by the syscall package).
const (
	seekData = 3
	seekHole = 4
)

// applySparseFile copies every data extent of the sparse diff file over
// out at the same offsets (Firecracker writes dirtied pages at their
// guest-physical offsets). This is the host-side equivalent of
// Firecracker's snapshot-editor rebase (ADR-006).
func applySparseFile(diffPath, outPath string) error {
	in, err := os.Open(diffPath)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	size := fi.Size()
	out, err := os.OpenFile(outPath, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer out.Close()
	buf := make([]byte, 4<<20)
	for off := int64(0); off < size; {
		data, err := syscall.Seek(int(in.Fd()), off, seekData)
		if err == syscall.ENXIO {
			break // no more data extents
		}
		if err != nil {
			return fmt.Errorf("seek data: %w", err)
		}
		hole, err := syscall.Seek(int(in.Fd()), data, seekHole)
		if err != nil {
			return fmt.Errorf("seek hole: %w", err)
		}
		if hole > size {
			hole = size
		}
		for p := data; p < hole; {
			n := int64(len(buf))
			if hole-p < n {
				n = hole - p
			}
			if _, err := in.ReadAt(buf[:n], p); err != nil {
				return err
			}
			if _, err := out.WriteAt(buf[:n], p); err != nil {
				return err
			}
			p += n
		}
		off = hole
	}
	return nil
}
