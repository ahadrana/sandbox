//go:build !linux

package firecrackerbackend

import "syscall"

func sysProcAttrNewGroup() *syscall.SysProcAttr { return nil }

func killProcessGroup(pid int) {}
