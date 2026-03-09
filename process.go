package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// startCore spawns a core daemon as a detached background process, waits for
// it to become healthy (cookie + API status), and returns its PID.
func startCore(net Network, cc *CoreConfig, binPath string) (int, error) {
	dataDir := cc.ResolveDataDir(net)
	cookiePath := CookiePath(dataDir)
	os.Remove(cookiePath)

	flags := cc.BuildFlags(net)
	cmd := exec.Command(binPath, flags...)

	logPath := LogFile(net)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return 0, fmt.Errorf("open log %s: %w", logPath, err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil

	detachProcess(cmd)

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return 0, fmt.Errorf("start %s core: %w", net, err)
	}

	pid := cmd.Process.Pid

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := waitCoreHealthy(ctx, cc.APIAddr, cookiePath); err != nil {
		cmd.Process.Kill()
		logFile.Close()
		return 0, fmt.Errorf("%s core started but API not reachable: %w", net, err)
	}

	cmd.Process.Release()
	logFile.Close()

	return pid, nil
}

func waitCoreHealthy(ctx context.Context, apiAddr, cookiePath string) error {
	var token string
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		data, err := os.ReadFile(cookiePath)
		if err == nil && len(strings.TrimSpace(string(data))) > 0 {
			token = strings.TrimSpace(string(data))
			break
		}
		time.Sleep(250 * time.Millisecond)
	}

	client := NewCoreClientDirect(apiAddr, token)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		reqCtx, reqCancel := context.WithTimeout(ctx, 3*time.Second)
		_, err := client.Status(reqCtx)
		reqCancel()
		if err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func stopCore(net Network) error {
	pid, err := readCorePidFile(net)
	if err != nil {
		return fmt.Errorf("%s core not running (no pidfile)", net)
	}
	if !processAlive(pid) {
		os.Remove(CorePidFile(net))
		return fmt.Errorf("%s core not running (stale pidfile)", net)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}

	if err := signalTerm(proc); err != nil {
		proc.Kill()
	}

	for i := 0; i < 30; i++ {
		if !processAlive(pid) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if processAlive(pid) {
		proc.Kill()
	}

	os.Remove(CorePidFile(net))
	return nil
}

func readCorePidFile(net Network) (int, error) {
	data, err := os.ReadFile(CorePidFile(net))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func writeCorePidFile(net Network, pid int) error {
	return os.WriteFile(CorePidFile(net), []byte(strconv.Itoa(pid)+"\n"), 0644)
}
