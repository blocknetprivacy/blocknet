package main

import (
	"context"
	"encoding/json"
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
	// Never put a second core on one data dir: they fight over the chain db and
	// the API port, and the loser is a process nobody tracks.
	if pid, err := readCorePidFile(net); err == nil && processAlive(pid) {
		return 0, fmt.Errorf("%s core is already running (pid %d); stop it first", net, pid)
	}

	useSettings := coreUsesSettingsAPI(binPath)
	flags := cc.BuildFlags(net)
	if useSettings {
		if cc.APIAddr == "" {
			return 0, fmt.Errorf("%s: api_addr is required to configure this core", net)
		}
		flags = cc.BaseFlags(net)
	}

	pid, err := spawnCore(net, cc, binPath, flags)
	if err != nil || !useSettings {
		return pid, err
	}

	cookiePath := CookiePath(cc.ResolveDataDir(net))
	restart, err := applyCoreSettings(net, cc, cookiePath)
	if err != nil {
		stopCore(net)
		return 0, fmt.Errorf("%s: %w", net, err)
	}
	if !restart {
		return pid, nil
	}
	if err := stopCore(net); err != nil {
		return 0, fmt.Errorf("%s: restart to apply settings: %w", net, err)
	}
	return spawnCore(net, cc, binPath, flags)
}

func spawnCore(net Network, cc *CoreConfig, binPath string, flags []string) (int, error) {
	dataDir := cc.ResolveDataDir(net)
	cookiePath := CookiePath(dataDir)
	os.Remove(cookiePath)

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

	// Claim the pidfile now, not after the wait below. A cold start can take
	// minutes, and until the pid is on disk every other command sees no core:
	// stop finds nothing to stop, start spawns a second one on the same data dir.
	if err := writeCorePidFile(net, pid); err != nil {
		cmd.Process.Kill()
		logFile.Close()
		return 0, fmt.Errorf("write %s pidfile: %w", net, err)
	}

	// Wait for the core to open its API. A cold start loads the chain db and
	// dials peers before it binds the API, which can take a couple of minutes.
	// We never kill a core just for being slow: awaitCoreReady only fails if the
	// process actually exits or is genuinely wedged (alive but making zero
	// progress). A live, busy core is left to finish coming up.
	if err := awaitCoreReady(pid, cc.APIAddr, cookiePath, logPath); err != nil {
		if processAlive(pid) {
			cmd.Process.Kill() // wedged, not busy — reclaim it
		}
		os.Remove(CorePidFile(net))
		logFile.Close()
		return 0, fmt.Errorf("%s: %w", net, err)
	}

	go cmd.Wait()
	logFile.Close()

	return pid, nil
}

// awaitCoreReady blocks until the core's API responds, judging the core by
// evidence rather than a fixed deadline:
//   - API responds                       -> ready (nil)
//   - process has exited                 -> crashed (error)
//   - alive but no progress for a while  -> wedged (error) after coreStallTimeout
//
// While the process keeps using CPU or doing disk I/O it is "up but busy", and
// we wait for as long as it needs — a slow cold start is not a failure.
func awaitCoreReady(pid int, apiAddr, cookiePath, logPath string) error {
	const (
		pollInterval     = 500 * time.Millisecond
		coreStallTimeout = 2 * time.Minute
	)
	var lastActivity uint64
	haveActivity := false
	lastAdvance := time.Now()

	for {
		// An answer on the API address is only ours if the core reports our pid.
		// Another core already holding that address would otherwise pass this
		// core as ready while the one we started is still stuck or dying.
		if ok, apiPid := coreResponds(apiAddr, cookiePath); ok {
			if apiPid != 0 && apiPid != pid {
				return fmt.Errorf("api %s is served by another core (pid %d), not the one just started (pid %d)", apiAddr, apiPid, pid)
			}
			return nil
		}
		if !processAlive(pid) {
			return fmt.Errorf("core exited during startup (see %s)", logPath)
		}
		if act, ok := processActivity(pid); ok {
			if !haveActivity || act != lastActivity {
				lastActivity, haveActivity = act, true
				lastAdvance = time.Now()
			}
		} else {
			// Progress can't be measured here (non-Linux) — assume it's working.
			lastAdvance = time.Now()
		}
		if time.Since(lastAdvance) > coreStallTimeout {
			return fmt.Errorf("core is alive but made no progress for %s and its API never came up (see %s)", coreStallTimeout, logPath)
		}
		time.Sleep(pollInterval)
	}
}

// coreResponds reports whether the core's API is answering right now, and the
// pid of the process that answered. A pid of 0 means the core is too old to
// report one; callers then have to take the answer at face value.
func coreResponds(apiAddr, cookiePath string) (bool, int) {
	data, err := os.ReadFile(cookiePath)
	if err != nil {
		return false, 0
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return false, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := NewCoreClientDirect(apiAddr, token)
	raw, err := client.Status(ctx)
	if err != nil {
		return false, 0
	}
	var status struct {
		PID int `json:"pid"`
	}
	json.Unmarshal(raw, &status)
	return true, status.PID
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
