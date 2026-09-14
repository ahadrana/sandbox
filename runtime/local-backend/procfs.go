package localbackend

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

// Host-side /proc helpers: pid-level operations (signals for STOP/CONT
// checkpointing, ownership re-verification before kills, usage accounting)
// act on host processes directly and never cross the wire.

// scanProc lists live processes carrying the incarnation marker by scanning
// /proc; this catches background and daemonized descendants.
func scanProc(marker string) ([]supervisor.ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []supervisor.ProcessInfo
	for _, e := range entries {
		pid, err := atoi(e.Name())
		if err != nil {
			continue
		}
		environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil || len(environ) == 0 {
			continue // includes zombies and exited processes
		}
		if !hasEnvEntry(string(environ), marker) {
			continue
		}
		pgid := readPGID(pid)
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		out = append(out, supervisor.ProcessInfo{
			PID:     pid,
			PGID:    pgid,
			Command: strings.ReplaceAll(strings.TrimRight(string(cmdline), "\x00"), "\x00", " "),
		})
	}
	return out, nil
}

// mustInventory returns the owned process list, empty on scan error.
func mustInventory(marker string) []supervisor.ProcessInfo {
	inv, err := scanProc(marker)
	if err != nil {
		return nil
	}
	return inv
}

// markerOwned re-verifies, immediately before a kill, that pid still carries
// the incarnation marker — closing the PID-reuse window between the
// inventory scan and the SIGKILL. /proc environ reads are not atomic across
// an execve: a live process (e.g. sh exec'ing its command tail) briefly
// exposes an empty or TRUNCATED environ. A verdict is taken only from two
// consecutive identical non-empty reads; anything unstable (mid-exec) is
// retried, and a persistently empty environ (zombie) is not owned.
func markerOwned(marker string, pid int) bool {
	prev := ""
	for i := 0; i < 5; i++ {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil {
			return false
		}
		cur := string(data)
		if len(cur) > 0 && cur == prev {
			return hasEnvEntry(cur, marker)
		}
		prev = cur
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

// hasEnvEntry reports whether the NUL-separated environ contains the exact
// KEY=VALUE entry.
func hasEnvEntry(environ, entry string) bool {
	for _, e := range strings.Split(environ, "\x00") {
		if e == entry {
			return true
		}
	}
	return false
}

func readPGID(pid int) int {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return -1
	}
	s := string(stat)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return -1
	}
	fields := strings.Fields(s[i+1:])
	// after comm: state ppid pgrp
	if len(fields) < 3 {
		return -1
	}
	pgid, err := atoi(fields[2])
	if err != nil {
		return -1
	}
	return pgid
}

// hostUsage sums live CPU (utime+stime) and RSS from /proc for the given
// inventory — host-side accounting, never guest self-report (INV-016).
func hostUsage(inv []supervisor.ProcessInfo) (cpuSeconds float64, rssBytes int64) {
	for _, p := range inv {
		if stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.PID)); err == nil {
			str := string(stat)
			if i := strings.LastIndex(str, ")"); i >= 0 {
				fields := strings.Fields(str[i+1:])
				// after comm: state ppid pgrp session tty_nr tpgid flags
				// minflt cminflt majflt cmajflt utime stime
				if len(fields) >= 13 {
					utime, _ := atoi(fields[11])
					stime, _ := atoi(fields[12])
					cpuSeconds += float64(utime+stime) / 100.0
				}
			}
		}
		if status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", p.PID)); err == nil {
			for _, line := range strings.Split(string(status), "\n") {
				if strings.HasPrefix(line, "VmRSS:") {
					var kb int
					fmt.Sscanf(line, "VmRSS: %d kB", &kb)
					rssBytes += int64(kb) * 1024
				}
			}
		}
	}
	return cpuSeconds, rssBytes
}

func atoi(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
