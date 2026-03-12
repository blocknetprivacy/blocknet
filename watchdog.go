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
	watchdogFailThreshold = 3
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

	failures := make(map[Network]int)
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

			if _, err := readCorePidFile(net); err != nil {
				failures[net] = 0
				continue
			}

			if checkHealth(cc.APIAddr) {
				failures[net] = 0
				continue
			}

			failures[net]++
			if failures[net] < watchdogFailThreshold {
				continue
			}

			nc := netColor(net)
			fmt.Printf("  %s%s%s %sunresponsive (%d checks), restarting...%s\n",
				nc, net, reset, amber, failures[net], reset)
			netArg := string(net)
			exec.Command(self, "stop", netArg).Run()
			exec.Command(self, "start", netArg).Run()
			fmt.Printf("  %s%s%s %srestarted%s\n", nc, net, reset, dim, reset)
			failures[net] = 0
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

func stopWatchdog() {
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
