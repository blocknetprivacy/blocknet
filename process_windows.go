//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008 | 0x00000200, // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
	}
}

// processActivity is unavailable on Windows; callers treat the false return as
// "assume the process is making progress" so a healthy core is never killed.
func processActivity(pid int) (uint64, bool) {
	return 0, false
}

func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(os.Signal(syscall.Signal(0)))
	if err == nil {
		return true
	}
	return false
}

func signalTerm(proc *os.Process) error {
	return proc.Kill()
}
