//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const taskName = "BlocknetAutoUpgrade"

func scheduleInstalled() bool {
	out, err := exec.Command("schtasks", "/query", "/tn", taskName).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), taskName)
}

func installSchedule(binPath string, interval time.Duration) error {
	if scheduleInstalled() {
		runCmd("schtasks", "/delete", "/tn", taskName, "/f")
	}

	minutes := int(interval.Minutes())
	if minutes < 60 {
		minutes = 60
	}

	err := runCmd("schtasks", "/create",
		"/tn", taskName,
		"/tr", fmt.Sprintf(`"%s" upgrade`, binPath),
		"/sc", "minute",
		"/mo", fmt.Sprintf("%d", minutes),
		"/f",
	)
	if err != nil {
		return fmt.Errorf("schtasks create: %w", err)
	}
	return nil
}

func uninstallSchedule() error {
	if !scheduleInstalled() {
		return nil
	}
	return runCmd("schtasks", "/delete", "/tn", taskName, "/f")
}
