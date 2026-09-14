//go:build !linux

package firecrackerbackend

import "fmt"

// procUsage is unsupported off Linux; the backend itself only runs where
// Firecracker/KVM runs.
func procUsage(pid int) (float64, int64, error) {
	return 0, 0, fmt.Errorf("procfs stats unsupported on this platform")
}
