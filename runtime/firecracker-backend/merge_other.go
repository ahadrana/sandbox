//go:build !linux

package firecrackerbackend

import "fmt"

// applySparseFile is unsupported off linux: the firecracker backend itself
// only runs on linux/KVM, and incremental restore fails loudly rather than
// silently mis-merging.
func applySparseFile(diffPath, outPath string) error {
	return fmt.Errorf("incremental snapshot merge unsupported on this platform")
}
