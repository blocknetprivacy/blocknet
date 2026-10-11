package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
			warns = append(warns, fmt.Sprintf("%s has no API address, so attach will not work", n))
		}
		if IsPinned(cc.Version) {
			if _, err := os.Stat(CoreBinaryPath(cc.Version)); os.IsNotExist(err) {
				warns = append(warns, fmt.Sprintf("%s is pinned to %s, which is not installed", n, cc.Version))
			}
		}
	}

	return warns
}

// doctorLabelWidth pads check labels so their details line up in one column.
const doctorLabelWidth = 20

func cmdDoctor(args []string) error {
	if err := ExtraArgs(args, 0, "blocknet doctor"); err != nil {
		return err
	}
	green, _, amber, pink, dim, reset := Palette(NoColor)

	issues, warnings := 0, 0
	line := func(mark, label, detail string) {
		if detail == "" {
			fmt.Printf("  %s %s\n", mark, label)
			return
		}
		fmt.Printf("  %s %s%s\n", mark, PadRight(label, doctorLabelWidth), detail)
	}
	// pass is a check that is fine, fail is an issue, warn is worth a look
	// but not an issue, info is neutral.
	pass := func(label, detail string) { line(green+"✓"+reset, label, detail) }
	fail := func(label, detail string) { issues++; line(pink+"✗"+reset, label, detail) }
	warn := func(label, detail string) { warnings++; line(amber+"!"+reset, label, detail) }
	info := func(label, detail string) { line(dim+"·"+reset, label, detail) }
	hint := func(msg string) { fmt.Printf("    %s→%s %s\n", dim, reset, msg) }
	section := func(head string) { fmt.Printf("\n%s\n\n", head) }

	allNets := []Network{Mainnet, Testnet}

	// Config

	section(SectionHead("Config", NoColor))

	cfgDir := ConfigDir()
	if fi, err := os.Stat(cfgDir); err == nil && fi.IsDir() {
		pass("Config directory", cfgDir)
	} else {
		fail("Config directory", "missing ("+cfgDir+")")
		hint("Run 'blocknet setup' to create it")
	}

	cfgPath := ConfigFile()
	if _, err := os.Stat(cfgPath); err == nil {
		pass("Config file", cfgPath)
	} else {
		info("Config file", "none, using defaults")
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		fail("Config file", fmt.Sprintf("invalid: %v", err))
		hint("Run 'blocknet setup' to write a new one")
		cfg = DefaultConfig()
	}

	if warns := validateConfig(cfg, allNets); len(warns) > 0 {
		for _, w := range warns {
			fail("Config check", w)
		}
	} else {
		pass("Config check", "no problems found")
	}

	coresDir := filepath.Join(ConfigDir(), "cores")
	entries, _ := os.ReadDir(coresDir)
	coreCount := 0
	for _, e := range entries {
		if e.IsDir() {
			coreCount++
		}
	}
	if coreCount > 0 {
		pass("Core versions", Plural(coreCount, "version")+" installed")
	} else {
		fail("Core versions", "none installed")
		hint("Run 'blocknet install latest' to install one")
	}

	if fi, err := os.Stat(WalletsDir()); err == nil && fi.IsDir() {
		pass("Wallets directory", WalletsDir())
	} else {
		info("Wallets directory", "will be created on first start")
	}

	if wEntries, err := os.ReadDir(WalletsDir()); err == nil {
		backupCount := 0
		for _, e := range wEntries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".wallet.dat") {
				backupCount++
			}
		}
		if backupCount > 0 {
			pass("Wallet files", Plural(backupCount, "file")+" in the wallets directory")
		} else {
			info("Wallet files", "none in the wallets directory")
		}
	}

	// Per network

	for _, n := range allNets {
		cc := cfg.Cores[n]
		if cc == nil {
			continue
		}

		title := strings.ToUpper(string(n)[:1]) + string(n)[1:]
		section(NetHead(n, title, NoColor))

		dd := cc.ResolveDataDir(n)
		if fi, err := os.Stat(dd); err == nil && fi.IsDir() {
			pass("Data directory", dd)
		} else {
			info("Data directory", "will be created on first start ("+dd+")")
		}

		// The core always gets the effective path, so check that one.
		walletPath := cc.EffectiveWalletFile(n)
		if fi, err := os.Stat(walletPath); err != nil {
			if cc.WalletFile == "" {
				info("Wallet file", "none yet ("+walletPath+")")
			} else {
				fail("Wallet file", "not found ("+walletPath+")")
				hint(fmt.Sprintf("Use 'blocknet attach %s' and run 'load' to pick a wallet", n))
			}
		} else if fi.Size() == 0 {
			fail("Wallet file", "empty ("+walletPath+")")
			hint("The file may be damaged. Use 'import' in attach to recover from your seed")
		} else {
			pass("Wallet file", walletPath)
			if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
				fail("Wallet permissions", fmt.Sprintf("too open (mode %04o, want 0600)", fi.Mode().Perm()))
				hint("chmod 600 " + walletPath)
			}
		}

		if cc.Enabled {
			resolved, err := ResolveInstalledVersion(cc.Version)
			if err != nil {
				fail("Core binary", fmt.Sprintf("version %q not available: %v", cc.Version, err))
			} else {
				binPath := CoreBinaryPath(resolved)
				if _, err := os.Stat(binPath); err == nil {
					pass("Core binary", resolved)
				} else {
					fail("Core binary", "missing ("+binPath+")")
					hint(fmt.Sprintf("Run 'blocknet install %s'", resolved))
				}
			}
		}

		if cc.APIAddr != "" {
			host, port, splitErr := net.SplitHostPort(cc.APIAddr)
			if splitErr == nil {
				if host == "" || host == "0.0.0.0" || host == "::" {
					fail("API address", fmt.Sprintf("bound to all interfaces (%s)", cc.APIAddr))
					hint(fmt.Sprintf("Set api_addr to \"127.0.0.1:%s\" in config.json", port))
				} else if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
					fail("API address", fmt.Sprintf("bound to a non-loopback address (%s)", cc.APIAddr))
					hint(fmt.Sprintf("Set api_addr to \"127.0.0.1:%s\" in config.json", port))
				}
			}
		}

		pid, pidErr := readCorePidFile(n)
		alive := pidErr == nil && processAlive(pid)

		if cc.Enabled && cc.APIAddr != "" && !alive {
			ln, listenErr := net.Listen("tcp", cc.APIAddr)
			if listenErr != nil {
				fail("API port", cc.APIAddr+" is in use by another process")
				if _, p, splitErr := net.SplitHostPort(cc.APIAddr); splitErr == nil {
					if runtime.GOOS == "windows" {
						hint(fmt.Sprintf("netstat -ano | findstr :%s", p))
					} else {
						hint(fmt.Sprintf("lsof -i :%s", p))
					}
				}
			} else {
				ln.Close()
				pass("API port", cc.APIAddr+" is free")
			}
		}

		if pidErr != nil {
			info("Core process", "not running")
		} else if alive {
			pass("Core process", fmt.Sprintf("running (pid %d)", pid))
		} else {
			fail("Core process", fmt.Sprintf("stale pidfile (pid %d is not running)", pid))
			hint(fmt.Sprintf("Remove %s to fix", CorePidFile(n)))
		}

		if alive {
			cookie := CookiePath(cc.ResolveDataDir(n))
			cfi, statErr := os.Stat(cookie)
			data, readErr := os.ReadFile(cookie)
			if readErr != nil {
				fail("Cookie file", "not readable ("+cookie+")")
				hint(fmt.Sprintf("Try 'blocknet restart %s'", n))
			} else if len(strings.TrimSpace(string(data))) == 0 {
				fail("Cookie file", "empty ("+cookie+")")
				hint(fmt.Sprintf("Try 'blocknet restart %s'", n))
			} else {
				pass("Cookie file", "valid")
			}
			if statErr == nil && runtime.GOOS != "windows" && cfi.Mode().Perm()&0o077 != 0 {
				fail("Cookie permissions", fmt.Sprintf("too open (mode %04o, want 0600)", cfi.Mode().Perm()))
				hint("chmod 600 " + cookie)
			}
		}

		if alive && cc.APIAddr != "" {
			if checkHealth(cc.APIAddr) {
				pass("API health", "responding")
			} else {
				fail("API health", "not responding")
				hint(fmt.Sprintf("Check 'blocknet logs %s' or try 'blocknet restart %s'", n, n))
			}
		}

		if alive && cc.APIAddr != "" {
			doctorWallet(cc, n, pass, warn, info)
		}

		if n == Mainnet && !cc.FullSync {
			st, cpErr := CheckCheckpoints(cc.ResolveDataDir(n))
			refresh := fmt.Sprintf("Run 'blocknet start %s' to download them", n)
			if alive {
				refresh = fmt.Sprintf("Run 'blocknet restart %s' to download them", n)
			}
			switch {
			case cpErr != nil:
				warn("Checkpoints", fmt.Sprintf("could not check: %v", cpErr))
			case st.Missing:
				warn("Checkpoints", "missing")
				hint(refresh)
			case st.Stale:
				warn("Checkpoints", fmt.Sprintf("out of date (bntpool has %d entries, up to height %d)", st.Entries, st.MaxHeight))
				hint(refresh)
			default:
				pass("Checkpoints", fmt.Sprintf("match bntpool (%d entries, up to height %d)", st.Entries, st.MaxHeight))
			}
		}

		if fi, logErr := os.Stat(LogFile(n)); logErr == nil {
			info("Log size", formatBytes(fi.Size()))
		}
	}

	// System

	section(SectionHead("System", NoColor))

	if wdPid, wdErr := readWatchdogPid(); wdErr == nil && processAlive(wdPid) {
		_, nets, _ := readWatchdogState()
		var netList []string
		for _, wn := range nets {
			netList = append(netList, string(wn))
		}
		if len(netList) > 0 {
			pass("Watchdog", fmt.Sprintf("running (pid %d, watching %s)", wdPid, strings.Join(netList, ", ")))
		} else {
			pass("Watchdog", fmt.Sprintf("running (pid %d)", wdPid))
		}
	} else {
		warn("Watchdog", "not running")
	}

	printUpgradeNotice(runningCoreNotice(cfg), NoColor)

	fmt.Println()
	switch {
	case issues > 0:
		fmt.Printf("  %s✗%s %s found\n\n", pink, reset, Plural(issues, "issue"))
	case warnings > 0:
		fmt.Printf("  %s✓%s All checks passed %s(%s)%s\n\n", green, reset, dim, Plural(warnings, "warning"), reset)
	default:
		fmt.Printf("  %s✓%s All checks passed\n\n", green, reset)
	}
	return nil
}

// doctorWallet reports what the running core says about its loaded wallet.
// Fields the core does not report are warnings, not issues.
func doctorWallet(cc *CoreConfig, n Network, pass, warn, info func(label, detail string)) {
	client, err := NewCoreClient(cc.APIAddr, CookiePath(cc.ResolveDataDir(n)))
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	raw, err := client.Status(ctx)
	cancel()
	if err != nil {
		return
	}
	var statusResp struct {
		Wallet *struct {
			DataVersion   int    `json:"data_version"`
			EncFormat     string `json:"enc_format"`
			AddrFormat    string `json:"addr_format"`
			CreatedAt     string `json:"created_at"`
			FileSizeBytes int64  `json:"file_size_bytes"`
		} `json:"wallet"`
	}
	json.Unmarshal(raw, &statusResp)

	w := statusResp.Wallet
	if w == nil {
		info("Wallet", "not loaded, some checks skipped")
		return
	}
	check := func(label string, ok bool, value string) {
		if ok {
			pass(label, value)
		} else {
			warn(label, "not reported by the core")
		}
	}
	check("Wallet version", w.DataVersion > 0, strconv.Itoa(w.DataVersion))
	check("Wallet encryption", w.EncFormat != "", w.EncFormat)
	check("Wallet addresses", w.AddrFormat != "", w.AddrFormat)
	age := ""
	if t, err := time.Parse(time.RFC3339, w.CreatedAt); err == nil {
		age = formatAge(t)
	}
	check("Wallet age", age != "", age)
	check("Wallet size", w.FileSizeBytes > 0, formatBytes(w.FileSizeBytes))
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
