// Command sudoshim is a static, flag-tolerant sudo stand-in for the
// host-agentd container image: the firecracker backend spawns the jailer
// (and, with networking, ip/iptables) via `sudo`; inside the privileged pod
// we already run as root, so the shim just strips leading flags and execs.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	args := os.Args[1:]
	for len(args) > 0 && len(args[0]) > 0 && args[0][0] == '-' {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "sudoshim: no command")
		os.Exit(1)
	}
	// The scratch image ships no coreutils; answer the trivial builtins the
	// backend's sudo probes rely on (`sudo -n true`).
	switch args[0] {
	case "true":
		os.Exit(0)
	case "false":
		os.Exit(1)
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sudoshim: %v\n", err)
		os.Exit(1)
	}
	if err := syscall.Exec(path, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "sudoshim exec %s: %v\n", args[0], err)
		os.Exit(1)
	}
}
