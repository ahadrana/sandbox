//go:build linux

package firecrackerbackend

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// procUsage reads CPU seconds (utime+stime) and RSS bytes of pid from /proc.
func procUsage(pid int) (cpuSeconds float64, rssBytes int64, err error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0, err
	}
	// Fields after comm (which may contain spaces/parens): state is field 3.
	s := string(stat)
	rparen := strings.LastIndex(s, ")")
	if rparen < 0 {
		return 0, 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(s[rparen+1:])
	// fields[0]=state(field3) ... utime=field14 -> index 11, stime=field15 -> 12
	if len(fields) < 13 {
		return 0, 0, fmt.Errorf("short /proc/%d/stat", pid)
	}
	utime, err1 := strconv.ParseFloat(fields[11], 64)
	stime, err2 := strconv.ParseFloat(fields[12], 64)
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("parse /proc/%d/stat", pid)
	}
	ticks := float64(100) // USER_HZ is 100 on all supported Linux configs here
	cpuSeconds = (utime + stime) / ticks
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return cpuSeconds, 0, nil
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				kb, _ := strconv.ParseInt(f[1], 10, 64)
				rssBytes = kb * 1024
			}
		}
	}
	return cpuSeconds, rssBytes, nil
}
