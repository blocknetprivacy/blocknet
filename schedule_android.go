//go:build android

package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const cronMarker = "# blocknet-upgrade"

func readCrontab() (string, error) {
	if _, err := exec.LookPath("crontab"); err != nil {
		return "", fmt.Errorf("crontab not found; in Termux run: pkg install cronie termux-services && sv-enable crond")
	}
	out, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		return "", nil
	}
	return string(out), nil
}

func writeCrontab(content string) error {
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("could not write crontab: %v %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func withoutMarker(content string) []string {
	var keep []string
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "" || strings.Contains(line, cronMarker) {
			continue
		}
		keep = append(keep, line)
	}
	return keep
}

func scheduleInstalled() bool {
	content, err := readCrontab()
	return err == nil && strings.Contains(content, cronMarker)
}

func installSchedule(binPath string, interval time.Duration) error {
	content, err := readCrontab()
	if err != nil {
		return err
	}
	hours := int(interval.Hours())
	if hours < 1 {
		hours = 1
	}
	when := "0 0 * * *"
	if hours < 24 {
		when = fmt.Sprintf("0 */%d * * *", hours)
	}
	lines := append(withoutMarker(content), fmt.Sprintf("%s %s upgrade --nocolor %s", when, binPath, cronMarker))
	return writeCrontab(strings.Join(lines, "\n") + "\n")
}

func uninstallSchedule() error {
	content, err := readCrontab()
	if err != nil {
		return err
	}
	lines := withoutMarker(content)
	if len(lines) == 0 {
		return writeCrontab("")
	}
	return writeCrontab(strings.Join(lines, "\n") + "\n")
}
