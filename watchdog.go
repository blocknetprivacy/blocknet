package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
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
	// process busy the whole time, so a normal (if slow) startup never trips
	// this; only a real hang does.
	watchdogWedgeTimeout = 2 * time.Minute
)

func cmdWatchdog(args []string) error {
	if err := ExtraArgs(args, 1, "blocknet watchdog [mainnet|testnet]"); err != nil {
		return err
	}
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
	os.Remove(watchdogPausedFile()) // a new watchdog starts with no paused networks
	if err := writeWatchdogState(os.Getpid(), networks); err != nil {
		return fmt.Errorf("write watchdog pidfile: %w", err)
	}
	defer os.Remove(WatchdogPidFile())

	self, _ := os.Executable()

	_, _, amber, pink, dim, reset := Palette(NoColor)
	netColor := func(net Network) string { return NetColor(net, NoColor) }

	fmt.Printf("  %sWatchdog monitoring:%s", dim, reset)
	for _, net := range networks {
		fmt.Printf(" %s%s%s", netColor(net), net, reset)
	}
	fmt.Printf(" %s(every %s)%s\n", dim, FormatDuration(watchdogInterval), reset)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// stillWatched rereads the pidfile: health checks take seconds, and
	// "blocknet stop <net>" may have taken net out of the set meanwhile.
	stillWatched := func(net Network) bool {
		pid, nets, err := readWatchdogState()
		if err != nil || pid != os.Getpid() {
			return true
		}
		return slices.Contains(nets, net)
	}

	restart := func(net Network, why string) {
		if !stillWatched(net) {
			return
		}
		nc := netColor(net)
		if fresh, err := LoadConfig(ConfigFile()); err == nil {
			if cc := fresh.Cores[net]; cc == nil || !cc.Enabled {
				// start would refuse a disabled core: stop watching it instead.
				fmt.Printf("  %s%s%s %sis disabled, no longer watched%s\n", nc, net, reset, dim, reset)
				if err := dropFromWatchdog(net); err != nil {
					Warnf("could not update the watchdog pidfile: %v", err)
				}
				return
			}
		}
		fmt.Printf("  %s%s%s %s%s, restarting...%s\n", nc, net, reset, amber, why, reset)
		netArg := string(net)
		if why != "crashed" {
			// A crashed core has nothing to stop; start clears its stale pidfile.
			run(self, "stop", netArg)
		}
		err := run(self, "start", netArg)
		if err == nil {
			// start can return 0 without starting anything, so check.
			if pid, perr := readCorePidFile(net); perr != nil || !processAlive(pid) {
				err = fmt.Errorf("core is not running after start")
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s✗%s %s%s%s restart failed: %v\n", pink, reset, nc, net, reset, err)
			return
		}
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

		// "blocknet stop <net>" and "disable <net>" take a network out of the
		// pidfile, and "start <net>" puts it back. Follow it so a stopped core
		// is not brought back and a started one is watched again.
		if pid, nets, err := readWatchdogState(); err == nil && pid == os.Getpid() {
			var now []Network
			for _, net := range []Network{Mainnet, Testnet} {
				in, was := slices.Contains(nets, net), slices.Contains(networks, net)
				switch {
				case in && !was:
					fmt.Printf("  %s%s%s %swatched again%s\n", netColor(net), net, reset, dim, reset)
				case !in && was:
					fmt.Printf("  %s%s%s %sno longer watched%s\n", netColor(net), net, reset, dim, reset)
				}
				if in {
					now = append(now, net)
				}
			}
			networks = now
			if len(networks) == 0 {
				fmt.Printf("  %sWatchdog stopped%s\n", dim, reset)
				return nil
			}
		}
		// Follow config edits too (a network enabled later, a new API address).
		if fresh, err := LoadConfig(ConfigFile()); err == nil {
			cfg = fresh
		}

		for _, net := range networks {
			cc := cfg.Cores[net]
			if cc == nil || cc.APIAddr == "" {
				continue
			}

			// Healthy API: the core is fully up, nothing to do.
			if checkHealth(cc.APIAddr) {
				clear(net)
				continue
			}

			// API is not answering. Decide by evidence, not a stopwatch: is the
			// core actually dead, or just still coming up / busy?
			pid, perr := readCorePidFile(net)
			if perr != nil || !processAlive(pid) {
				// The core process is gone: it crashed. Restart it.
				restart(net, "crashed")
				clear(net)
				continue
			}

			// Process is alive but the API is down. That's normal during a cold
			// start (the core loads the chain db before binding the API). As long
			// as it keeps using CPU or doing disk I/O it is up-but-busy, so leave it.
			busy := false
			if act, ok := processActivity(pid); ok {
				if !haveActivity[net] || act != lastActivity[net] {
					busy = true
				}
				lastActivity[net] = act
				haveActivity[net] = true
			} else {
				busy = true // progress can't be measured, so assume it's working
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

var healthClient = &http.Client{Timeout: watchdogHealthTimeout}

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

	resp, err := healthClient.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
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

func run(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "BNT_WATCHDOG=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// unwatchNetwork takes one network out of the running watchdog's set. The
// watchdog rereads its pidfile every tick and drops networks that are gone.
// When no network is left, the watchdog is stopped.
func unwatchNetwork(net Network) {
	if os.Getenv("BNT_WATCHDOG") == "1" {
		return
	}
	pid, _, err := readWatchdogState()
	if err != nil || !processAlive(pid) {
		os.Remove(WatchdogPidFile())
		return
	}
	empty := false
	err = updateWatchdogState(func(nets []Network) []Network {
		kept := slices.DeleteFunc(slices.Clone(nets), func(n Network) bool { return n == net })
		empty = len(kept) == 0
		return kept
	})
	if err != nil {
		Warnf("could not update the watchdog pidfile: %v", err)
		return
	}
	if empty {
		stopWatchdog()
		return
	}
	setPaused(net, true)
}

// watchNetwork puts net back into a running watchdog's set, after "blocknet
// start <net>" brings back a core that "stop <net>" took out. A network the
// watchdog never watched stays unwatched.
func watchNetwork(net Network) {
	if os.Getenv("BNT_WATCHDOG") == "1" {
		return
	}
	pid, _, err := readWatchdogState()
	if err != nil || !processAlive(pid) || !isPaused(net) {
		return
	}
	setPaused(net, false)
	err = updateWatchdogState(func(nets []Network) []Network {
		if !slices.Contains(nets, net) {
			nets = append(nets, net)
		}
		return nets
	})
	if err != nil {
		Warnf("could not update the watchdog pidfile: %v", err)
	}
}

// dropFromWatchdog is the watchdog taking net out of its own set. Unlike
// unwatchNetwork it never stops the watchdog (the next tick does that when
// nothing is left).
func dropFromWatchdog(net Network) error {
	return updateWatchdogState(func(nets []Network) []Network {
		return slices.DeleteFunc(slices.Clone(nets), func(n Network) bool { return n == net })
	})
}

// updateWatchdogState rewrites the network list in the pidfile. Two commands
// doing this at once (say "stop mainnet" and "stop testnet") would each read
// the old list and the last write would win, so a small lock file serializes
// the read-modify-write. A lock left behind by a killed process is taken over
// after watchdogLockStale.
func updateWatchdogState(change func([]Network) []Network) error {
	unlock, err := lockWatchdogState()
	if err != nil {
		return err
	}
	defer unlock()
	pid, nets, err := readWatchdogState()
	if err != nil {
		return err
	}
	return writeWatchdogState(pid, change(nets))
}

const watchdogLockStale = 10 * time.Second

func lockWatchdogState() (func(), error) {
	lock := WatchdogPidFile() + ".lock"
	deadline := time.Now().Add(3 * time.Second)
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err == nil {
			f.Close()
			return func() { os.Remove(lock) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if info, serr := os.Stat(lock); serr == nil && time.Since(info.ModTime()) > watchdogLockStale {
			os.Remove(lock)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("watchdog pidfile is locked (%s)", lock)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func stopWatchdog() {
	if os.Getenv("BNT_WATCHDOG") == "1" {
		return
	}
	pid, err := readWatchdogPid()
	if err != nil || !processAlive(pid) {
		os.Remove(WatchdogPidFile())
		os.Remove(watchdogPausedFile())
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	proc.Signal(os.Interrupt)
	for deadline := time.Now().Add(2 * time.Second); processAlive(pid) && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if processAlive(pid) {
		proc.Kill()
	}
	os.Remove(WatchdogPidFile())
	os.Remove(watchdogPausedFile())
}

func writeWatchdogState(pid int, networks []Network) error {
	var buf strings.Builder
	buf.WriteString(strconv.Itoa(pid))
	buf.WriteByte('\n')
	for _, net := range networks {
		buf.WriteString(string(net))
		buf.WriteByte('\n')
	}
	// Write a uniquely named temp file and rename it, so the running watchdog
	// never reads a half-written file and two writers never share a temp file.
	dest := WatchdogPidFile()
	f, err := os.CreateTemp(filepath.Dir(dest), ".watchdog.pid.*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.WriteString(buf.String())
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp)
		return errors.Join(werr, cerr)
	}
	// On Windows the rename fails while another process has the pidfile open
	// for reading, so retry for a moment.
	for attempt := 0; ; attempt++ {
		err = os.Rename(tmp, dest)
		if err == nil || runtime.GOOS != "windows" || attempt >= 10 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// watchdogPausedFile lists networks that "stop <net>" took out of a running
// watchdog, so "start <net>" can put back only those.
func watchdogPausedFile() string {
	return WatchdogPidFile() + ".paused"
}

func readPaused() []Network {
	data, err := os.ReadFile(watchdogPausedFile())
	if err != nil {
		return nil
	}
	var nets []Network
	for _, line := range strings.Split(string(data), "\n") {
		if n := strings.TrimSpace(line); n != "" {
			nets = append(nets, Network(n))
		}
	}
	return nets
}

func isPaused(net Network) bool {
	return slices.Contains(readPaused(), net)
}

func setPaused(net Network, paused bool) {
	nets := slices.DeleteFunc(readPaused(), func(n Network) bool { return n == net })
	if paused {
		nets = append(nets, net)
	}
	if len(nets) == 0 {
		os.Remove(watchdogPausedFile())
		return
	}
	var buf strings.Builder
	for _, n := range nets {
		buf.WriteString(string(n) + "\n")
	}
	if err := os.WriteFile(watchdogPausedFile(), []byte(buf.String()), 0644); err != nil {
		Warnf("could not update the watchdog paused list: %v", err)
	}
}
