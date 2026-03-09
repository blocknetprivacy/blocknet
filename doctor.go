package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	green, red, dim, reset := "\033[38;2;170;255;0m", "\033[38;2;255;80;80m", "\033[2m", "\033[0m"
	if NoColor {
		green, red, dim, reset = "", "", "", ""
	}

	pass := func(msg string) { fmt.Printf("  %s✓%s %s\n", green, reset, msg) }
	fail := func(msg string) { fmt.Printf("  %s✗%s %s\n", red, reset, msg) }
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
	}

	fmt.Println()
	if issues == 0 {
		fmt.Printf("  %sAll checks passed%s\n\n", green, reset)
	} else {
		fmt.Printf("  %s%d issue(s) found%s\n\n", red, issues, reset)
	}
	return nil
}
