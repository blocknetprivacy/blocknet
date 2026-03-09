package main

import (
	"os"
	"os/exec"
)

func runCmd(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func ensureScheduleFromConfig(cfg *Config) {
	if !cfg.AutoUpgrade {
		if scheduleInstalled() {
			uninstallSchedule()
		}
		return
	}
	binPath, err := os.Executable()
	if err != nil {
		return
	}
	installSchedule(binPath, cfg.CheckIntervalDuration())
}
