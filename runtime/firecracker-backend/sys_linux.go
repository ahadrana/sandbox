//go:build linux

package firecrackerbackend

import "syscall"

func sysProcAttrNewGroup() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup SIGKILLs the process group led by the given process.
func killProcessGroup(pid int) {
	syscall.Kill(-pid, syscall.SIGKILL)
}
