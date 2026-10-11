package main

import (
	"os"
	"os/exec"
)

func runCmd(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func ensureScheduleFromConfig(cfg *Config) {
	binPath, err := os.Executable()
	if err != nil {
		return
	}
	installSchedule(binPath, cfg.CheckIntervalDuration())
}
