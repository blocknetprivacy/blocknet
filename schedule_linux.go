//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func systemdUserDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user")
}

func servicePath() string { return filepath.Join(systemdUserDir(), "blocknet-upgrade.service") }
func timerPath() string   { return filepath.Join(systemdUserDir(), "blocknet-upgrade.timer") }

func scheduleInstalled() bool {
	_, err := os.Stat(timerPath())
	return err == nil
}

func installSchedule(binPath string, interval time.Duration) error {
	dir := systemdUserDir()
	os.MkdirAll(dir, 0755)

	service := fmt.Sprintf(`[Unit]
Description=Blocknet auto-upgrade check

[Service]
Type=oneshot
ExecStart=%s upgrade
`, binPath)

	hours := int(interval.Hours())
	if hours < 1 {
		hours = 1
	}
	onCalendar := "daily"
	if hours != 24 {
		onCalendar = fmt.Sprintf("*-*-* 0/%d:00:00", hours)
	}

	timer := fmt.Sprintf(`[Unit]
Description=Blocknet auto-upgrade timer

[Timer]
OnCalendar=%s
Persistent=true

[Install]
WantedBy=timers.target
`, onCalendar)

	if err := os.WriteFile(servicePath(), []byte(service), 0644); err != nil {
		return fmt.Errorf("write service: %w", err)
	}
	if err := os.WriteFile(timerPath(), []byte(timer), 0644); err != nil {
		return fmt.Errorf("write timer: %w", err)
	}

	runCmd("systemctl", "--user", "daemon-reload")
	if err := runCmd("systemctl", "--user", "enable", "--now", "blocknet-upgrade.timer"); err != nil {
		return fmt.Errorf("enable timer: %w", err)
	}
	return nil
}

func uninstallSchedule() error {
	runCmd("systemctl", "--user", "disable", "--now", "blocknet-upgrade.timer")
	os.Remove(servicePath())
	os.Remove(timerPath())
	runCmd("systemctl", "--user", "daemon-reload")
	return nil
}
