//go:build darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const launchdLabel = "com.blocknet.upgrade"

func launchdPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
}

func scheduleInstalled() bool {
	_, err := os.Stat(launchdPlistPath())
	return err == nil
}

func installSchedule(binPath string, interval time.Duration) error {
	plistPath := launchdPlistPath()
	os.MkdirAll(filepath.Dir(plistPath), 0755)

	logPath := filepath.Join(ConfigDir(), "upgrade.log")
	seconds := int(interval.Seconds())
	if seconds < 3600 {
		seconds = 3600
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>upgrade</string>
    </array>
    <key>StartInterval</key>
    <integer>%d</integer>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
</dict>
</plist>
`, launchdLabel, binPath, seconds, logPath, logPath)

	runCmd("launchctl", "bootout", fmt.Sprintf("gui/%d", os.Getuid()), plistPath)

	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	if err := runCmd("launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), plistPath); err != nil {
		return fmt.Errorf("launchctl bootstrap: %w", err)
	}
	return nil
}

func uninstallSchedule() error {
	plistPath := launchdPlistPath()
	runCmd("launchctl", "bootout", fmt.Sprintf("gui/%d", os.Getuid()), plistPath)
	return os.Remove(plistPath)
}
