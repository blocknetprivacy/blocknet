package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

const (
	watchdogInterval        = 5 * time.Second
	watchdogHealthTimeout   = 3 * time.Second
	watchdogFailThreshold   = 3 // consecutive failures before restart
	watchdogMaxRestarts     = 3 // consecutive restart failures before cooldown
	watchdogRestartCooldown = 60 * time.Second
)

type netState struct {
	failures    int
	restarts    int
	lastRestart time.Time
}

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

	dim, reset := "\033[38;2;160;160;160m", "\033[0m"
	green := "\033[38;2;170;255;0m"
	pink := "\033[38;2;255;0;170m"
	if NoColor {
		dim, reset, green, pink = "", "", "", ""
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

	state := make(map[Network]*netState)
	for _, net := range networks {
		state[net] = &netState{}
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
			s := state[net]
			cc := cfg.Cores[net]
			if cc == nil || cc.APIAddr == "" {
				continue
			}

			_, pidErr := readCorePidFile(net)
			if pidErr != nil {
				s.failures = 0
				continue
			}

			if checkHealth(cc.APIAddr) {
				if s.failures > 0 {
					s.failures = 0
					s.restarts = 0
				}
				continue
			}

			s.failures++
			if s.failures < watchdogFailThreshold {
				continue
			}

			if s.restarts >= watchdogMaxRestarts {
				if time.Since(s.lastRestart) < watchdogRestartCooldown {
					continue
				}
				s.restarts = 0
			}

			nc := netColor(net)
			fmt.Printf("  %s%s%s %sunresponsive (%d checks), restarting...%s\n",
				nc, net, reset, dim, s.failures, reset)

			if err := restartForWatchdog(net, cc); err != nil {
				fmt.Fprintf(os.Stderr, "  %s%s%s restart failed: %v\n", nc, net, reset, err)
				s.restarts++
				s.lastRestart = time.Now()
				if s.restarts >= watchdogMaxRestarts {
					fmt.Fprintf(os.Stderr, "  %s%s%s %stoo many failures, backing off %s%s\n",
						nc, net, reset, dim, watchdogRestartCooldown, reset)
				}
			} else {
				fmt.Printf("  %s%s%s %srestarted successfully%s\n", nc, net, reset, dim, reset)
				s.failures = 0
				s.restarts = 0
				s.lastRestart = time.Now()
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

func restartForWatchdog(net Network, cc *CoreConfig) error {
	stopCore(net)

	resolved, err := ResolveInstalledVersion(cc.Version)
	if err != nil {
		return fmt.Errorf("resolve version: %w", err)
	}

	pid, err := startCore(net, cc, CoreBinaryPath(resolved))
	if err != nil {
		return err
	}

	return writeCorePidFile(net, pid)
}
