package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

const (
	watchdogInterval      = 5 * time.Second
	watchdogHealthTimeout = 3 * time.Second
	// watchdogWedgeTimeout is how long a core may be alive, unresponsive on its
	// API, AND making no progress before we treat it as genuinely wedged and
	// restart it. A cold start (loading the chain db, dialing peers) keeps the
	// process busy the whole time, so a normal — if slow — startup never trips
	// this; only a real hang does.
	watchdogWedgeTimeout = 2 * time.Minute
)

func cmdWatchdog(args []string) error {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	var networks []Network
	if len(args) > 0 {
		net, err := ParseNetwork(args[0])
		if err != nil {
			return err
		}
		networks = []Network{net}
	} else {
		for _, net := range []Network{Mainnet, Testnet} {
			cc := cfg.Cores[net]
			if cc != nil && cc.Enabled {
				networks = append(networks, net)
			}
		}
	}

	if len(networks) == 0 {
		return fmt.Errorf("no enabled cores to watch")
	}

	if pid, err := readWatchdogPid(); err == nil && processAlive(pid) {
		return fmt.Errorf("watchdog already running (pid %d)", pid)
	}
	if err := writeWatchdogPid(networks); err != nil {
		return fmt.Errorf("write watchdog pidfile: %w", err)
	}
	defer os.Remove(WatchdogPidFile())

	self, _ := os.Executable()

	dim, reset := "\033[38;2;160;160;160m", "\033[0m"
	green := "\033[38;2;170;255;0m"
	pink := "\033[38;2;255;0;170m"
	amber := "\033[38;2;255;170;0m"
	if NoColor {
		dim, reset, green, pink, amber = "", "", "", "", ""
	}
	netColor := func(net Network) string {
		if net == Testnet {
			return pink
		}
		return green
	}

	fmt.Printf("  %sWatchdog monitoring:%s", dim, reset)
	for _, net := range networks {
		fmt.Printf(" %s%s%s", netColor(net), net, reset)
	}
	fmt.Printf(" %s(every %s)%s\n", dim, watchdogInterval, reset)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	restart := func(net Network, why string) {
		nc := netColor(net)
		fmt.Printf("  %s%s%s %s%s — restarting...%s\n", nc, net, reset, amber, why, reset)
		netArg := string(net)
		run(self, "stop", netArg)
		run(self, "start", netArg)
		fmt.Printf("  %s%s%s %srestarted%s\n", nc, net, reset, dim, reset)
	}

	// Per-network state for wedge detection: when a core first went quiet, and
	// its last-seen activity counter.
	wedgeSince := make(map[Network]time.Time)
	lastActivity := make(map[Network]uint64)
	haveActivity := make(map[Network]bool)
	clear := func(net Network) {
		delete(wedgeSince, net)
		delete(lastActivity, net)
		delete(haveActivity, net)
	}

	ticker := time.NewTicker(watchdogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("\n  %sWatchdog stopped%s\n", dim, reset)
			return nil
		case <-ticker.C:
		}

		for _, net := range networks {
			cc := cfg.Cores[net]
			if cc == nil || cc.APIAddr == "" {
				continue
			}

			// Healthy API — the core is fully up, nothing to do.
			if checkHealth(cc.APIAddr) {
				clear(net)
				continue
			}

			// API is not answering. Decide by evidence, not a stopwatch: is the
			// core actually dead, or just still coming up / busy?
			pid, perr := readCorePidFile(net)
			if perr != nil || !processAlive(pid) {
				// The core process is gone — it crashed. Restart it.
				restart(net, "crashed")
				clear(net)
				continue
			}

			// Process is alive but the API is down. That's normal during a cold
			// start (the core loads the chain db before binding the API). As long
			// as it keeps using CPU or doing disk I/O it is up-but-busy — leave it.
			busy := false
			if act, ok := processActivity(pid); ok {
				if !haveActivity[net] || act != lastActivity[net] {
					busy = true
				}
				lastActivity[net] = act
				haveActivity[net] = true
			} else {
				busy = true // progress can't be measured — assume it's working
			}
			if busy {
				delete(wedgeSince, net)
				continue
			}

			// Alive, API down, and making no progress. Start/continue the wedge
			// timer; only restart once it's been stuck long enough to rule out a
			// slow-but-healthy boot.
			if wedgeSince[net].IsZero() {
				wedgeSince[net] = time.Now()
			}
			if time.Since(wedgeSince[net]) >= watchdogWedgeTimeout {
				restart(net, "wedged")
				clear(net)
			}
		}
	}
}

func checkHealth(apiAddr string) bool {
	base := apiAddr
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	base = strings.TrimRight(base, "/")

	ctx, cancel := context.WithTimeout(context.Background(), watchdogHealthTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/health", nil)
	if err != nil {
		return false
	}

	resp, err := (&http.Client{Timeout: watchdogHealthTimeout}).Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func readWatchdogPid() (int, error) {
	pid, _, err := readWatchdogState()
	return pid, err
}

func readWatchdogState() (int, []Network, error) {
	data, err := os.ReadFile(WatchdogPidFile())
	if err != nil {
		return 0, nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		return 0, nil, fmt.Errorf("empty watchdog pidfile")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil {
		return 0, nil, err
	}
	var nets []Network
	for _, line := range lines[1:] {
		if n := strings.TrimSpace(line); n != "" {
			nets = append(nets, Network(n))
		}
	}
	return pid, nets, nil
}

func run(bin string, args ...string) {
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "BNT_WATCHDOG=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func stopWatchdog() {
	if os.Getenv("BNT_WATCHDOG") == "1" {
		return
	}
	pid, err := readWatchdogPid()
	if err != nil || !processAlive(pid) {
		os.Remove(WatchdogPidFile())
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	proc.Signal(os.Interrupt)
	for i := 0; i < 10; i++ {
		if !processAlive(pid) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if processAlive(pid) {
		proc.Kill()
	}
	os.Remove(WatchdogPidFile())
}

func writeWatchdogPid(networks []Network) error {
	var buf strings.Builder
	buf.WriteString(strconv.Itoa(os.Getpid()))
	buf.WriteByte('\n')
	for _, net := range networks {
		buf.WriteString(string(net))
		buf.WriteByte('\n')
	}
	return os.WriteFile(WatchdogPidFile(), []byte(buf.String()), 0644)
}
