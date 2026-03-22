package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func validateConfig(cfg *Config, networks []Network) []string {
	var warns []string

	if mn, tn := cfg.Cores[Mainnet], cfg.Cores[Testnet]; mn != nil && tn != nil {
		if mn.APIAddr != "" && mn.APIAddr == tn.APIAddr {
			warns = append(warns, fmt.Sprintf("mainnet and testnet share the same API address (%s)", mn.APIAddr))
		}
		if mn.Listen != "" && mn.Listen == tn.Listen {
			warns = append(warns, fmt.Sprintf("mainnet and testnet share the same listen address (%s)", mn.Listen))
		}
		if mn.DataDir != "" && mn.DataDir == tn.DataDir {
			warns = append(warns, "mainnet and testnet share the same data directory")
		}
	}

	for _, n := range networks {
		cc := cfg.Cores[n]
		if cc == nil {
			continue
		}
		if cc.APIAddr == "" {
			warns = append(warns, fmt.Sprintf("%s has no API address — attach won't work", n))
		}
		if IsPinned(cc.Version) {
			if _, err := os.Stat(CoreBinaryPath(cc.Version)); os.IsNotExist(err) {
				warns = append(warns, fmt.Sprintf("%s is pinned to %s but it's not installed", n, cc.Version))
			}
		}
	}

	return warns
}

func cmdDoctor(_ []string) error {
	green, red, amber, dim, reset := "\033[38;2;170;255;0m", "\033[38;2;255;80;80m", "\033[38;2;255;170;0m", "\033[2m", "\033[0m"
	if NoColor {
		green, red, amber, dim, reset = "", "", "", "", ""
	}

	pass := func(msg string) { fmt.Printf("  %s✓%s %s\n", green, reset, msg) }
	fail := func(msg string) { fmt.Printf("  %s✗%s %s\n", red, reset, msg) }
	warn := func(msg string) { fmt.Printf("  %s·%s %s\n", amber, reset, msg) }
	info := func(msg string) { fmt.Printf("  %s·%s %s\n", dim, reset, msg) }

	issues := 0

	fmt.Println()

	// Config directory
	cfgDir := ConfigDir()
	if fi, err := os.Stat(cfgDir); err == nil && fi.IsDir() {
		pass(fmt.Sprintf("Config directory exists (%s)", cfgDir))
	} else {
		fail(fmt.Sprintf("Config directory missing (%s)", cfgDir))
		info("Run 'blocknet setup' to create it")
		issues++
	}

	// Config file
	cfgPath := ConfigFile()
	if _, err := os.Stat(cfgPath); err == nil {
		pass("Config file found")
	} else {
		info("No config file (using defaults)")
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		fail(fmt.Sprintf("Config file is invalid: %v", err))
		issues++
		cfg = DefaultConfig()
	}

	// Config validation
	allNets := []Network{Mainnet, Testnet}
	if warns := validateConfig(cfg, allNets); len(warns) > 0 {
		for _, w := range warns {
			fail(w)
			issues++
		}
	} else {
		pass("Config validation passed")
	}

	// Data directories
	for _, n := range allNets {
		cc := cfg.Cores[n]
		if cc == nil {
			continue
		}
		dd := cc.ResolveDataDir(n)
		if fi, err := os.Stat(dd); err == nil && fi.IsDir() {
			pass(fmt.Sprintf("%s data directory exists", n))
		} else {
			info(fmt.Sprintf("%s data directory will be created on first start (%s)", n, dd))
		}
	}

	// Wallets directory
	if fi, err := os.Stat(WalletsDir()); err == nil && fi.IsDir() {
		pass("Wallets directory exists")
	} else {
		info("Wallets directory will be created on first start")
	}

	// Wallet files
	for _, n := range allNets {
		cc := cfg.Cores[n]
		if cc == nil || cc.WalletFile == "" {
			continue
		}
		fi, err := os.Stat(cc.WalletFile)
		if err != nil {
			fail(fmt.Sprintf("%s wallet file not found (%s)", n, cc.WalletFile))
			issues++
			continue
		}
		if fi.Size() == 0 {
			fail(fmt.Sprintf("%s wallet file is empty (%s)", n, cc.WalletFile))
			issues++
			continue
		}
		pass(fmt.Sprintf("%s wallet file exists (%s)", n, filepath.Base(cc.WalletFile)))
		if runtime.GOOS != "windows" && fi.Mode().Perm()&0077 != 0 {
			fail(fmt.Sprintf("%s wallet permissions too open (mode %04o, want 0600)", n, fi.Mode().Perm()))
			issues++
		}
	}

	// Wallet backups
	if wEntries, err := os.ReadDir(WalletsDir()); err == nil {
		backupCount := 0
		for _, e := range wEntries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".wallet.dat") {
				backupCount++
			}
		}
		if backupCount > 0 {
			pass(fmt.Sprintf("%d wallet backup(s) in wallets directory", backupCount))
		} else {
			info("No wallet backups in wallets directory")
		}
	}

	// Installed cores
	coresDir := filepath.Join(ConfigDir(), "cores")
	entries, _ := os.ReadDir(coresDir)
	coreCount := 0
	for _, e := range entries {
		if e.IsDir() {
			coreCount++
		}
	}
	if coreCount > 0 {
		pass(fmt.Sprintf("%d core version(s) installed", coreCount))
	} else {
		fail("No core versions installed")
		info("Run 'blocknet install latest' to install one")
		issues++
	}

	// Check each configured version is available
	for _, n := range allNets {
		cc := cfg.Cores[n]
		if cc == nil || !cc.Enabled {
			continue
		}
		resolved, err := ResolveInstalledVersion(cc.Version)
		if err != nil {
			fail(fmt.Sprintf("%s core version %q not available: %v", n, cc.Version, err))
			issues++
		} else {
			binPath := CoreBinaryPath(resolved)
			if _, err := os.Stat(binPath); err == nil {
				pass(fmt.Sprintf("%s core binary exists (%s)", n, resolved))
			} else {
				fail(fmt.Sprintf("%s core binary missing at %s", n, binPath))
				issues++
			}
		}
	}

	// Public API exposure
	for _, n := range allNets {
		cc := cfg.Cores[n]
		if cc == nil || cc.APIAddr == "" {
			continue
		}
		host, _, err := net.SplitHostPort(cc.APIAddr)
		if err != nil {
			continue
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			fail(fmt.Sprintf("%s API bound to all interfaces (%s) — use 127.0.0.1", n, cc.APIAddr))
			issues++
		} else if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
			fail(fmt.Sprintf("%s API bound to non-loopback address (%s)", n, cc.APIAddr))
			issues++
		}
	}

	// Port availability for stopped cores
	for _, n := range allNets {
		cc := cfg.Cores[n]
		if cc == nil || !cc.Enabled || cc.APIAddr == "" {
			continue
		}
		pid, pidErr := readCorePidFile(n)
		if pidErr == nil && processAlive(pid) {
			pass(fmt.Sprintf("%s API port in use by running core (pid %d)", n, pid))
			continue
		}
		ln, err := net.Listen("tcp", cc.APIAddr)
		if err != nil {
			fail(fmt.Sprintf("%s API port %s is already in use by another process", n, cc.APIAddr))
			issues++
		} else {
			ln.Close()
			pass(fmt.Sprintf("%s API port %s is available", n, cc.APIAddr))
		}
	}

	// Running cores
	for _, n := range allNets {
		pid, err := readCorePidFile(n)
		if err != nil {
			info(fmt.Sprintf("%s core is not running", n))
			continue
		}
		if processAlive(pid) {
			pass(fmt.Sprintf("%s core is running (pid %d)", n, pid))
		} else {
			fail(fmt.Sprintf("%s has a stale pidfile (pid %d not running)", n, pid))
			info(fmt.Sprintf("Remove %s to fix", CorePidFile(n)))
			issues++
		}
	}

	// Cookie files for running cores
	for _, n := range allNets {
		cc := cfg.Cores[n]
		if cc == nil {
			continue
		}
		pid, pidErr := readCorePidFile(n)
		if pidErr != nil || !processAlive(pid) {
			continue
		}
		cookie := CookiePath(cc.ResolveDataDir(n))
		cfi, statErr := os.Stat(cookie)
		data, err := os.ReadFile(cookie)
		if err != nil {
			fail(fmt.Sprintf("%s cookie file not readable (%s)", n, cookie))
			issues++
		} else if len(strings.TrimSpace(string(data))) == 0 {
			fail(fmt.Sprintf("%s cookie file is empty", n))
			issues++
		} else {
			pass(fmt.Sprintf("%s cookie file is valid", n))
		}
		if statErr == nil && runtime.GOOS != "windows" && cfi.Mode().Perm()&0077 != 0 {
			fail(fmt.Sprintf("%s cookie permissions too open (mode %04o, want 0600)", n, cfi.Mode().Perm()))
			issues++
		}
	}

	// API health for running cores
	for _, n := range allNets {
		cc := cfg.Cores[n]
		if cc == nil || cc.APIAddr == "" {
			continue
		}
		pid, pidErr := readCorePidFile(n)
		if pidErr != nil || !processAlive(pid) {
			continue
		}
		if checkHealth(cc.APIAddr) {
			pass(fmt.Sprintf("%s API responding", n))
		} else {
			fail(fmt.Sprintf("%s API not responding", n))
			issues++
		}
	}

	// Wallet diagnostics from running cores
	for _, n := range allNets {
		cc := cfg.Cores[n]
		if cc == nil || cc.APIAddr == "" {
			continue
		}
		pid, pidErr := readCorePidFile(n)
		if pidErr != nil || !processAlive(pid) {
			continue
		}

		dataDir := cc.ResolveDataDir(n)
		client, clientErr := NewCoreClient(cc.APIAddr, CookiePath(dataDir))
		if clientErr != nil {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		raw, statusErr := client.Status(ctx)
		cancel()
		if statusErr != nil {
			continue
		}

		var status struct {
			Wallet *struct {
				DataVersion   int    `json:"data_version"`
				EncFormat     string `json:"enc_format"`
				AddrFormat    string `json:"addr_format"`
				CreatedAt     string `json:"created_at"`
				FileSizeBytes int64  `json:"file_size_bytes"`
			} `json:"wallet"`
		}
		json.Unmarshal(raw, &status)

		if status.Wallet == nil {
			info(fmt.Sprintf("%s wallet not loaded — some diagnostics omitted", n))
			continue
		}

		w := status.Wallet
		if w.DataVersion > 0 {
			pass(fmt.Sprintf("%s wallet data version: %d", n, w.DataVersion))
		} else {
			fail(fmt.Sprintf("%s wallet data version unavailable", n))
		}
		if w.EncFormat != "" {
			pass(fmt.Sprintf("%s wallet enc format: %s", n, w.EncFormat))
		} else {
			fail(fmt.Sprintf("%s wallet enc format unavailable", n))
		}
		if w.AddrFormat != "" {
			pass(fmt.Sprintf("%s wallet addr format: %s", n, w.AddrFormat))
		} else {
			fail(fmt.Sprintf("%s wallet addr format unavailable", n))
		}
		if w.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, w.CreatedAt); err == nil {
				pass(fmt.Sprintf("%s wallet age: %s", n, formatAge(t)))
			} else if t, err := time.Parse("2006-01-02T15:04:05Z", w.CreatedAt); err == nil {
				pass(fmt.Sprintf("%s wallet age: %s", n, formatAge(t)))
			} else {
				fail(fmt.Sprintf("%s wallet age unavailable", n))
			}
		} else {
			fail(fmt.Sprintf("%s wallet age unavailable", n))
		}
		if w.FileSizeBytes > 0 {
			pass(fmt.Sprintf("%s wallet size: %s", n, formatFileSize(w.FileSizeBytes)))
		} else {
			fail(fmt.Sprintf("%s wallet size unavailable", n))
		}
	}

	// Watchdog
	if wdPid, wdErr := readWatchdogPid(); wdErr == nil && processAlive(wdPid) {
		_, nets, _ := readWatchdogState()
		var netList []string
		for _, wn := range nets {
			netList = append(netList, string(wn))
		}
		if len(netList) > 0 {
			pass(fmt.Sprintf("Watchdog running (pid %d, watching %s)", wdPid, strings.Join(netList, ", ")))
		} else {
			pass(fmt.Sprintf("Watchdog running (pid %d)", wdPid))
		}
	} else {
		warn("Watchdog not running")
	}

	// Log sizes
	for _, n := range allNets {
		logPath := LogFile(n)
		if fi, err := os.Stat(logPath); err == nil {
			info(fmt.Sprintf("%s log: %s", n, formatFileSize(fi.Size())))
		}
	}

	// Auto-upgrade
	if cfg.AutoUpgrade {
		pass("Auto-upgrade enabled")
	} else {
		fail("Auto-upgrade disabled")
		issues++
	}

	fmt.Println()
	if issues == 0 {
		fmt.Printf("  %sAll checks passed%s\n\n", green, reset)
	} else {
		fmt.Printf("  %s%d issue(s) found%s\n\n", red, issues, reset)
	}
	return nil
}

func formatAge(created time.Time) string {
	now := time.Now().UTC()
	y := now.Year() - created.Year()
	m := int(now.Month()) - int(created.Month())
	d := now.Day() - created.Day()

	if d < 0 {
		m--
		prev := time.Date(now.Year(), now.Month(), 0, 0, 0, 0, 0, time.UTC)
		d += prev.Day()
	}
	if m < 0 {
		y--
		m += 12
	}

	var parts []string
	if y > 0 {
		parts = append(parts, fmt.Sprintf("%dy", y))
	}
	if m > 0 {
		parts = append(parts, fmt.Sprintf("%dm", m))
	}
	parts = append(parts, fmt.Sprintf("%dd", d))
	return strings.Join(parts, " ")
}

func formatFileSize(bytes int64) string {
	switch {
	case bytes < 1024:
		return fmt.Sprintf("%d B", bytes)
	case bytes < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	case bytes < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	default:
		return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
	}
}
