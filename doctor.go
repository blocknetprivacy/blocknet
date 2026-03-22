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
	green, red, amber, pink, dim, reset := "\033[38;2;170;255;0m", "\033[38;2;255;80;80m", "\033[38;2;255;170;0m", "\033[38;2;255;0;170m", "\033[2m", "\033[0m"
	if NoColor {
		green, red, amber, pink, dim, reset = "", "", "", "", "", ""
	}

	pass := func(msg string) { fmt.Printf("  %s✓%s %s\n", green, reset, msg) }
	fail := func(msg string) { fmt.Printf("  %s✗%s %s\n", red, reset, msg) }
	warn := func(msg string) { fmt.Printf("  %s·%s %s\n", amber, reset, msg) }
	info := func(msg string) { fmt.Printf("  %s·%s %s\n", dim, reset, msg) }
	hint := func(msg string) { fmt.Printf("    %s→%s %s\n", dim, reset, msg) }
	section := func(name string) { fmt.Printf("\n%s\n", SectionHead(name, NoColor)) }

	issues := 0
	allNets := []Network{Mainnet, Testnet}

	// ── Config ──────────────────────────────────────────────

	section("Config")

	cfgDir := ConfigDir()
	if fi, err := os.Stat(cfgDir); err == nil && fi.IsDir() {
		pass(fmt.Sprintf("Config directory exists (%s)", cfgDir))
	} else {
		fail(fmt.Sprintf("Config directory missing (%s)", cfgDir))
		hint("Run 'blocknet setup' to create it")
		issues++
	}

	cfgPath := ConfigFile()
	if _, err := os.Stat(cfgPath); err == nil {
		pass("Config file found")
	} else {
		info("No config file (using defaults)")
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		fail(fmt.Sprintf("Config file is invalid: %v", err))
		hint("Run 'blocknet setup' to regenerate it")
		issues++
		cfg = DefaultConfig()
	}

	if warns := validateConfig(cfg, allNets); len(warns) > 0 {
		for _, w := range warns {
			fail(w)
			issues++
		}
	} else {
		pass("Config validation passed")
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
		pass(fmt.Sprintf("%d core version(s) installed", coreCount))
	} else {
		fail("No core versions installed")
		hint("Run 'blocknet install latest' to install one")
		issues++
	}

	if fi, err := os.Stat(WalletsDir()); err == nil && fi.IsDir() {
		pass("Wallets directory exists")
	} else {
		info("Wallets directory will be created on first start")
	}

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

	// ── Per-network ─────────────────────────────────────────

	for _, n := range allNets {
		cc := cfg.Cores[n]
		if cc == nil {
			continue
		}

		netColor := green
		if n == Testnet {
			netColor = pink
		}
		title := strings.ToUpper(string(n)[:1]) + string(n)[1:]
		fmt.Printf("\n%s#%s %s\n", netColor, reset, title)

		// Data directory
		dd := cc.ResolveDataDir(n)
		if fi, err := os.Stat(dd); err == nil && fi.IsDir() {
			pass("Data directory exists")
		} else {
			info(fmt.Sprintf("Data directory will be created on first start (%s)", dd))
		}

		// Wallet file
		if cc.WalletFile != "" {
			fi, err := os.Stat(cc.WalletFile)
			if err != nil {
			fail(fmt.Sprintf("Wallet file not found (%s)", cc.WalletFile))
			hint(fmt.Sprintf("Use 'blocknet attach %s' and run 'load' to pick a wallet", n))
			issues++
			} else if fi.Size() == 0 {
			fail(fmt.Sprintf("Wallet file is empty (%s)", cc.WalletFile))
			hint("File may be corrupted — use 'import' in attach mode to recover from seed")
			issues++
			} else {
				pass(fmt.Sprintf("Wallet file exists (%s)", filepath.Base(cc.WalletFile)))
				if runtime.GOOS != "windows" && fi.Mode().Perm()&0077 != 0 {
				fail(fmt.Sprintf("Wallet permissions too open (mode %04o, want 0600)", fi.Mode().Perm()))
				hint(fmt.Sprintf("chmod 600 %s", cc.WalletFile))
				issues++
				}
			}
		}

		// Core binary
		if cc.Enabled {
			resolved, err := ResolveInstalledVersion(cc.Version)
			if err != nil {
				fail(fmt.Sprintf("Core version %q not available: %v", cc.Version, err))
				issues++
			} else {
				binPath := CoreBinaryPath(resolved)
				if _, err := os.Stat(binPath); err == nil {
					pass(fmt.Sprintf("Core binary exists (%s)", resolved))
				} else {
				fail(fmt.Sprintf("Core binary missing at %s", binPath))
				hint(fmt.Sprintf("Run 'blocknet install %s'", resolved))
				issues++
				}
			}
		}

		// Public API exposure
		if cc.APIAddr != "" {
			host, port, splitErr := net.SplitHostPort(cc.APIAddr)
			if splitErr == nil {
				if host == "" || host == "0.0.0.0" || host == "::" {
					fail(fmt.Sprintf("API bound to all interfaces (%s) — use 127.0.0.1", cc.APIAddr))
					hint(fmt.Sprintf("Set api_addr to \"127.0.0.1:%s\" in config.json", port))
					issues++
				} else if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
					fail(fmt.Sprintf("API bound to non-loopback address (%s)", cc.APIAddr))
					hint(fmt.Sprintf("Set api_addr to \"127.0.0.1:%s\" in config.json", port))
					issues++
				}
			}
		}

		// Port / process state
		pid, pidErr := readCorePidFile(n)
		alive := pidErr == nil && processAlive(pid)

		if cc.Enabled && cc.APIAddr != "" {
			if alive {
				pass(fmt.Sprintf("API port in use by running core (pid %d)", pid))
			} else {
				ln, listenErr := net.Listen("tcp", cc.APIAddr)
				if listenErr != nil {
				fail(fmt.Sprintf("API port %s already in use by another process", cc.APIAddr))
				if _, p, splitErr := net.SplitHostPort(cc.APIAddr); splitErr == nil {
					if runtime.GOOS == "windows" {
						hint(fmt.Sprintf("netstat -ano | findstr :%s", p))
					} else {
						hint(fmt.Sprintf("lsof -i :%s", p))
					}
				}
				issues++
				} else {
					ln.Close()
					pass(fmt.Sprintf("API port %s is available", cc.APIAddr))
				}
			}
		}

		if pidErr != nil {
			info("Core is not running")
		} else if alive {
			pass(fmt.Sprintf("Core is running (pid %d)", pid))
		} else {
			fail(fmt.Sprintf("Stale pidfile (pid %d not running)", pid))
			hint(fmt.Sprintf("Remove %s to fix", CorePidFile(n)))
			issues++
		}

		// Cookie (running cores only)
		if alive {
			cookie := CookiePath(cc.ResolveDataDir(n))
			cfi, statErr := os.Stat(cookie)
			data, readErr := os.ReadFile(cookie)
			if readErr != nil {
				fail(fmt.Sprintf("Cookie file not readable (%s)", cookie))
				hint(fmt.Sprintf("Try 'blocknet restart %s'", n))
				issues++
			} else if len(strings.TrimSpace(string(data))) == 0 {
				fail("Cookie file is empty")
				hint(fmt.Sprintf("Try 'blocknet restart %s'", n))
				issues++
			} else {
				pass("Cookie file is valid")
			}
			if statErr == nil && runtime.GOOS != "windows" && cfi.Mode().Perm()&0077 != 0 {
				fail(fmt.Sprintf("Cookie permissions too open (mode %04o, want 0600)", cfi.Mode().Perm()))
				hint(fmt.Sprintf("chmod 600 %s", cookie))
				issues++
			}
		}

		// API health (running cores only)
		if alive && cc.APIAddr != "" {
			if checkHealth(cc.APIAddr) {
				pass("API responding")
			} else {
			fail("API not responding")
			hint(fmt.Sprintf("Check 'blocknet logs %s' or try 'blocknet restart %s'", n, n))
			issues++
			}
		}

		// Wallet diagnostics (running cores only)
		if alive && cc.APIAddr != "" {
			dataDir := cc.ResolveDataDir(n)
			client, clientErr := NewCoreClient(cc.APIAddr, CookiePath(dataDir))
			if clientErr == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				raw, statusErr := client.Status(ctx)
				cancel()
				if statusErr == nil {
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

					if statusResp.Wallet == nil {
						info("Wallet not loaded — some diagnostics omitted")
					} else {
						w := statusResp.Wallet
						if w.DataVersion > 0 {
							pass(fmt.Sprintf("Wallet data version: %d", w.DataVersion))
						} else {
							fail("Wallet data version unavailable")
						}
						if w.EncFormat != "" {
							pass(fmt.Sprintf("Wallet enc format: %s", w.EncFormat))
						} else {
							fail("Wallet enc format unavailable")
						}
						if w.AddrFormat != "" {
							pass(fmt.Sprintf("Wallet addr format: %s", w.AddrFormat))
						} else {
							fail("Wallet addr format unavailable")
						}
						if w.CreatedAt != "" {
							if t, parseErr := time.Parse(time.RFC3339, w.CreatedAt); parseErr == nil {
								pass(fmt.Sprintf("Wallet age: %s", formatAge(t)))
							} else if t, parseErr := time.Parse("2006-01-02T15:04:05Z", w.CreatedAt); parseErr == nil {
								pass(fmt.Sprintf("Wallet age: %s", formatAge(t)))
							} else {
								fail("Wallet age unavailable")
							}
						} else {
							fail("Wallet age unavailable")
						}
						if w.FileSizeBytes > 0 {
							pass(fmt.Sprintf("Wallet size: %s", formatFileSize(w.FileSizeBytes)))
						} else {
							fail("Wallet size unavailable")
						}
					}
				}
			}
		}

		// Log size
		logPath := LogFile(n)
		if fi, logErr := os.Stat(logPath); logErr == nil {
			info(fmt.Sprintf("Log: %s", formatFileSize(fi.Size())))
		}
	}

	// ── System ──────────────────────────────────────────────

	section("System")

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

	if cfg.AutoUpgrade {
		pass("Auto-upgrade enabled")
	} else {
		fail("Auto-upgrade disabled")
		hint("Set \"auto_upgrade\": true in config.json")
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
