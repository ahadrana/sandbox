// Package hostfacts reports the host identity facts that gate snapshot
// restore compatibility (P0.4) and restore placement (P1.7): machine
// architecture, kernel release, and a CPU model discriminator. The facts
// mirror CubeSandbox's Cubelet/pkg/cubelet/versioninfo host-facts scheme
// (mechanism only, Apache-2.0): a snapshot taken under one kernel/CPU
// generation is only restorable on a host whose facts match.
package hostfacts

import (
	"os"
	"strings"
	"syscall"
)

// Facts describes the host a snapshot or microVM depends on.
type Facts struct {
	// Arch is the machine architecture (uname -m), e.g. "x86_64", "aarch64".
	Arch string
	// KernelRelease is uname -r, e.g. "6.8.0-1063-aws".
	KernelRelease string
	// CPUPart discriminates the CPU model. On aarch64 it is the hex CPU
	// part number from /proc/cpuinfo (e.g. "0xd40" for Neoverse V1); on
	// x86 it is a vendor:family:model:stepping composite.
	CPUPart string
}

// Current reads the facts of the host this process runs on.
func Current() Facts {
	return Facts{
		Arch:          unameField(func(u *syscall.Utsname) string { return charsToString(u.Machine[:]) }),
		KernelRelease: unameField(func(u *syscall.Utsname) string { return charsToString(u.Release[:]) }),
		CPUPart:       cpuPart(),
	}
}

func unameField(get func(*syscall.Utsname) string) string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	return get(&u)
}

func charsToString(c []int8) string {
	b := make([]byte, 0, len(c))
	for _, v := range c {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

// cpuPart parses the first processor block of /proc/cpuinfo. aarch64
// kernels report "CPU implementer"/"CPU part" per CPU; x86 reports
// vendor_id/cpu family/model/stepping. Unknown or unreadable yields "".
func cpuPart() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	var vendor, family, model, stepping string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			// End of the first processor block: stop, the first CPU's
			// identity is representative of a homogeneous host.
			break
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		switch key {
		case "CPU part":
			return val
		case "vendor_id":
			vendor = val
		case "cpu family":
			family = val
		case "model":
			model = val
		case "stepping":
			stepping = val
		}
	}
	if vendor == "" && family == "" && model == "" {
		return ""
	}
	return vendor + ":" + family + ":" + model + ":" + stepping
}
