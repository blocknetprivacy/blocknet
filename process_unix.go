//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// processActivity returns a monotonically-increasing counter of the process's
// CPU time (jiffies) plus disk I/O (bytes). It's used to tell "alive and busy"
// (a core loading the chain db on a cold start) from "alive but wedged" — a
// value that keeps climbing means the process is doing real work. The bool is
// false when the value can't be read (e.g. not Linux, where /proc is absent),
// in which case callers should assume the process IS making progress rather
// than risk killing a healthy core.
func processActivity(pid int) (uint64, bool) {
	var total uint64
	ok := false

	// CPU time: utime+stime from /proc/<pid>/stat. The comm field (2nd) can
	// contain spaces and parens, so parse the fields after the final ')'.
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		s := string(data)
		if i := strings.LastIndexByte(s, ')'); i >= 0 && i+1 < len(s) {
			f := strings.Fields(s[i+1:])
			// f[0]=state, f[1]=ppid, ... f[11]=utime, f[12]=stime
			if len(f) > 12 {
				utime, _ := strconv.ParseUint(f[11], 10, 64)
				stime, _ := strconv.ParseUint(f[12], 10, 64)
				total += utime + stime
				ok = true
			}
		}
	}

	// Disk I/O: read_bytes+write_bytes from /proc/<pid>/io (best-effort).
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/io", pid)); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "read_bytes:") || strings.HasPrefix(line, "write_bytes:") {
				if parts := strings.Fields(line); len(parts) == 2 {
					if n, e := strconv.ParseUint(parts[1], 10, 64); e == nil {
						total += n
						ok = true
					}
				}
			}
		}
	}

	return total, ok
}

func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func signalTerm(proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}
