package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func parseYes(input string, defaultYes bool) bool {
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" {
		return defaultYes
	}
	switch input {
	case "y", "ye", "yes", "yeah", "yah", "yep", "yup", "ya", "yee",
		"sure", "ok", "okay", "k", "alright", "aight":
		return true
	case "n", "no", "nah", "nope", "nay", "nuh", "nuhuh", "noway",
		"pass", "skip":
		return false
	}
	return defaultYes
}

func validateAddr(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q — expected host:port (e.g. 127.0.0.1:8332)", addr)
	}
	if host == "" {
		return fmt.Errorf("missing host in %q", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port in %q — must be 1-65535", addr)
	}
	return nil
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func downloadProgress(downloaded, total int64) {
	green, reset := "\033[38;2;170;255;0m", "\033[0m"
	if NoColor {
		green, reset = "", ""
	}
	width := 30
	if total > 0 {
		pct := float64(downloaded) / float64(total)
		filled := int(pct * float64(width))
		if filled > width {
			filled = width
		}
		bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
		fmt.Printf("\r  %s[%s]%s %3.0f%% %s", green, bar, reset, pct*100, formatBytes(downloaded))
	} else {
		fmt.Printf("\r  %s downloaded", formatBytes(downloaded))
	}
}

func cmdSetup(_ []string) error {
	reader := bufio.NewReader(os.Stdin)

	green, dim, cyan, bold, reset := "\033[38;2;170;255;0m", "\033[38;2;160;160;160m", "\033[38;2;0;170;255m", "\033[1m", "\033[0m"
	if NoColor {
		green, dim, cyan, bold, reset = "", "", "", "", ""
	}

	fmt.Println()
	fmt.Printf("  %sWelcome to Blocknet!%s\n", green, reset)
	fmt.Println()
	fmt.Println("  This will walk you through setting up your node.")
	fmt.Println("  You can always re-run this or edit the config file directly.")
	fmt.Println()

	// --- Existing config check ---
	cfgPath := ConfigFile()
	if _, err := os.Stat(cfgPath); err == nil {
		existing, loadErr := LoadConfig(cfgPath)
		if loadErr == nil {
			warn := "\033[38;2;255;170;0m"
			if NoColor {
				warn = ""
			}
			fmt.Printf("  %sA config already exists at \033[4m%s\033[24m:%s\n\n", warn, cfgPath, reset)

			if mc := existing.Cores[Mainnet]; mc != nil {
				tag := "disabled"
				if mc.Enabled {
					tag = fmt.Sprintf("enabled, API %s", mc.APIAddr)
				}
				fmt.Printf("    mainnet:      %s\n", tag)
			}
			if tc := existing.Cores[Testnet]; tc != nil {
				tag := "disabled"
				if tc.Enabled {
					tag = fmt.Sprintf("enabled, API %s", tc.APIAddr)
				}
				fmt.Printf("    testnet:      %s\n", tag)
			}
			upTag := "off"
			if existing.AutoUpgrade {
				upTag = "on"
			}
			fmt.Printf("    auto-upgrade: %s\n\n", upTag)

			fmt.Println("  Start fresh? This will replace your current config.")
			fmt.Printf("  yes or no %s(default: no)%s: ", cyan, reset)
			if !parseYes(readLine(reader), false) {
				fmt.Println()
				fmt.Println("  Setup cancelled. Your existing config is unchanged.")
				return nil
			}
			fmt.Println()
		}
	}

	cfg := DefaultConfig()

	// --- Auto-upgrade ---
	fmt.Printf("\n%s\n\n", SectionHead("Updates", NoColor))

	fmt.Println("  Keep your node updated automatically?")
	fmt.Printf("  %sWhen a new version comes out, blocknet will download%s\n", dim, reset)
	fmt.Printf("  %sand apply it for you.%s\n", dim, reset)
	fmt.Printf("  yes or no %s(default: yes)%s: ", cyan, reset)
	cfg.AutoUpgrade = parseYes(readLine(reader), true)
	fmt.Println()

	// --- Save config ---
	if err := EnsureConfigDir(); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := SaveConfig(cfgPath, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	fmt.Printf("  Config saved to %s%s%s\n\n", dim, cfgPath, reset)

	if cfg.AutoUpgrade {
		binPath, _ := os.Executable()
		if binPath != "" {
			if err := installSchedule(binPath, cfg.CheckIntervalDuration()); err != nil {
				fmt.Printf("  %sCouldn't set up auto-updates: %v%s\n", dim, err, reset)
			}
			fmt.Println()
		}
	}

	// --- Install core ---
	hasCore := false
	if resolved, err := ResolveInstalledVersion("latest"); err == nil {
		if _, err := os.Stat(CoreBinaryPath(resolved)); err == nil {
			hasCore = true
		}
	}

	if hasCore {
		fmt.Println("  A core version is already installed.")
		fmt.Println()
	} else {
		fmt.Printf("\n%s\n\n", SectionHead("Download", NoColor))

		fmt.Println("  You don't have a core installed yet.")
		fmt.Println("  Download the latest one now?")
		fmt.Printf("  %sThis is needed before you can start your node.%s\n", dim, reset)
		fmt.Printf("  yes or no %s(default: yes)%s: ", cyan, reset)
		if parseYes(readLine(reader), true) {
			fmt.Println()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			latest, err := LatestRelease(ctx)
			if err != nil {
				fmt.Printf("  %sCouldn't check for releases: %v%s\n", dim, err, reset)
				fmt.Println("  Check your internet connection and try: blocknet install latest")
			} else {
				asset := FindAsset(latest.Assets)
				if asset == nil {
					fmt.Printf("  %sNo download available for your platform in %s%s\n", dim, latest.Tag, reset)
					fmt.Println("  You can install manually later: blocknet install latest")
				} else {
					expectedSHA, err := ResolveAssetSHA256(ctx, latest.Assets, asset.Name)
					if err != nil {
						fmt.Printf("  %sChecksum lookup failed: %v%s\n", dim, err, reset)
						fmt.Println("  Try again later: blocknet install latest")
						fmt.Println()
					}
					if err == nil {
						fmt.Printf("  Downloading %s (%s)...\n", latest.Tag, asset.Name)
						destPath := CoreBinaryPath(latest.Tag)
						if err := DownloadAsset(ctx, asset.URL, destPath, expectedSHA, downloadProgress); err != nil {
							fmt.Println()
							fmt.Printf("  %sDownload failed: %v%s\n", dim, err, reset)
							fmt.Println("  Check your internet connection and try: blocknet install latest")
						} else {
							fmt.Println()
							fmt.Printf("  %s✓ verified%s\n", green, reset)
							fmt.Printf("  Installed %s\n", latest.Tag)
							hasCore = true
						}
					}
				}
			}
		}
		fmt.Println()
	}

	// --- Start now? ---
	if hasCore {
		fmt.Println("  Start your node now?")
		fmt.Printf("  yes or no %s(default: yes)%s: ", cyan, reset)
		if parseYes(readLine(reader), true) {
			fmt.Println()
			if err := cmdStart(nil); err != nil {
				fmt.Printf("  %sCouldn't start: %v%s\n\n", dim, err, reset)
			}
		} else {
			fmt.Println()
			fmt.Printf("  You can start later with: %sblocknet start%s\n", bold, reset)
		}
		fmt.Println()
	}

	// --- Shell integration ---
	if shell := detectShell(); shell != "" {
		rcFile := shellRCFile(shell)
		binPath, _ := os.Executable()

		fmt.Printf("\n%s\n\n", SectionHead("Shell", NoColor))

		fmt.Println("  Set up the 'bnt' shortcut so you can use blocknet from any terminal?")
		fmt.Printf("  %sAdds blocknet to your PATH and enables tab completion.%s\n", dim, reset)
		fmt.Printf("  yes or no %s(default: yes)%s: ", cyan, reset)
		if parseYes(readLine(reader), true) {
			if err := installShellIntegration(shell, rcFile, binPath); err != nil {
				fmt.Printf("  %sCouldn't set up shell: %v%s\n", dim, err, reset)
			} else {
				fmt.Println("  Done. Open a new terminal to use 'blocknet' and 'bnt'.")
			}
		}
		fmt.Println()
	}

	// --- Advanced settings gate ---
	fmt.Printf("\n%s\n\n", SectionHead("Advanced", NoColor))

	fmt.Println("  That covers the basics! Want to configure advanced settings?")
	fmt.Printf("  %s(testnet, API ports, explorer, network tuning)%s\n", dim, reset)
	fmt.Printf("  yes or no %s(default: yes)%s: ", cyan, reset)
	if parseYes(readLine(reader), true) {
		fmt.Println()

		// --- Testnet ---
		fmt.Printf("\n%s\n\n", ErrorHead("Testnet", NoColor))

		fmt.Println("  Enable testnet? A separate network for testing — coins have no value.")
		fmt.Printf("  yes or no %s(default: yes)%s: ", cyan, reset)
		if parseYes(readLine(reader), true) {
			cfg.Cores[Testnet].Enabled = true
			fmt.Println()

			fmt.Println("  Testnet API address — where tools connect to your testnet node.")
			fmt.Printf("  %s(default: 127.0.0.1:18332)%s: ", cyan, reset)
			if answer := readLine(reader); answer != "" {
				if err := validateAddr(answer); err != nil {
					fmt.Printf("  %s%v — using default%s\n", dim, err, reset)
				} else {
					cfg.Cores[Testnet].APIAddr = answer
				}
			}
			fmt.Println()

			fmt.Println("  Enable the testnet block explorer?")
			fmt.Printf("  %sServes a web-based block explorer you can open in your browser.%s\n", dim, reset)
			fmt.Printf("  yes or no %s(default: yes)%s: ", cyan, reset)
			if parseYes(readLine(reader), true) {
				fmt.Println()
				fmt.Println("  Testnet explorer address:")
				fmt.Printf("  %s(default: 127.0.0.1:18080)%s: ", cyan, reset)
				answer := readLine(reader)
				if answer == "" {
					cfg.Cores[Testnet].ExplorerAddr = "127.0.0.1:18080"
				} else if err := validateAddr(answer); err != nil {
					fmt.Printf("  %s%v — using default%s\n", dim, err, reset)
					cfg.Cores[Testnet].ExplorerAddr = "127.0.0.1:18080"
				} else {
					cfg.Cores[Testnet].ExplorerAddr = answer
				}
			}
		}
		fmt.Println()

		// --- Mainnet ---
		fmt.Printf("\n%s\n\n", SectionHead("Mainnet", NoColor))

		fmt.Println("  Mainnet API address — how tools like 'blocknet attach' connect to your node.")
		fmt.Printf("  %s(default: 127.0.0.1:8332)%s: ", cyan, reset)
		if answer := readLine(reader); answer != "" {
			if err := validateAddr(answer); err != nil {
				fmt.Printf("  %s%v — using default%s\n", dim, err, reset)
			} else {
				cfg.Cores[Mainnet].APIAddr = answer
			}
		}
		fmt.Println()

		fmt.Println("  Enable the mainnet block explorer?")
		fmt.Printf("  %sServes a web-based block explorer you can open in your browser.%s\n", dim, reset)
		fmt.Printf("  yes or no %s(default: yes)%s: ", cyan, reset)
		if parseYes(readLine(reader), true) {
			fmt.Println()
			fmt.Println("  Mainnet explorer address:")
			fmt.Printf("  %s(default: 127.0.0.1:8080)%s: ", cyan, reset)
			answer := readLine(reader)
			if answer == "" {
				cfg.Cores[Mainnet].ExplorerAddr = "127.0.0.1:8080"
			} else if err := validateAddr(answer); err != nil {
				fmt.Printf("  %s%v — using default%s\n", dim, err, reset)
				cfg.Cores[Mainnet].ExplorerAddr = "127.0.0.1:8080"
			} else {
				cfg.Cores[Mainnet].ExplorerAddr = answer
			}
		}
		fmt.Println()

		if err := SaveConfig(cfgPath, cfg); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
		fmt.Println("  Config updated.")
	}
	fmt.Println()

	fmt.Printf("  %sSetup complete!%s Here's what you can do next:\n\n", green, reset)
	fmt.Println("    blocknet status            See what's running")
	fmt.Println("    blocknet attach mainnet     Open the interactive shell")
	fmt.Println("    blocknet help               See all commands")
	fmt.Println()
	return nil
}

func detectShell() string {
	if runtime.GOOS == "windows" {
		return ""
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		return ""
	}

	base := filepath.Base(shell)
	switch base {
	case "bash":
		return "bash"
	case "zsh":
		return "zsh"
	case "fish":
		return "fish"
	}
	return ""
}

func shellRCFile(shell string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch shell {
	case "bash":
		rc := filepath.Join(home, ".bashrc")
		if _, err := os.Stat(rc); err == nil {
			return rc
		}
		return filepath.Join(home, ".bash_profile")
	case "zsh":
		return filepath.Join(home, ".zshrc")
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish")
	}
	return ""
}

func installShellIntegration(shell, rcFile, binPath string) error {
	if rcFile == "" {
		return fmt.Errorf("couldn't determine rc file for %s", shell)
	}

	existing, _ := os.ReadFile(rcFile)
	content := string(existing)

	var block []string

	if binPath != "" && !dirInPATH(filepath.Dir(binPath)) && !strings.Contains(content, filepath.Dir(binPath)) {
		switch shell {
		case "bash", "zsh":
			block = append(block, fmt.Sprintf(`export PATH="$PATH:%s"`, filepath.Dir(binPath)))
		case "fish":
			block = append(block, fmt.Sprintf(`fish_add_path %s`, filepath.Dir(binPath)))
		}
	}

	if !strings.Contains(content, "alias bnt") {
		switch shell {
		case "bash", "zsh":
			block = append(block, `alias bnt=blocknet`)
		case "fish":
			block = append(block, `alias bnt blocknet`)
		}
	}

	if !strings.Contains(content, "blocknet completions") {
		cmd := "blocknet"
		if binPath != "" {
			cmd = binPath
		}
		switch shell {
		case "bash":
			block = append(block, fmt.Sprintf(`eval "$(%s completions bash)"`, cmd))
		case "zsh":
			block = append(block, fmt.Sprintf(`eval "$(%s completions zsh)"`, cmd))
		case "fish":
			block = append(block, fmt.Sprintf(`%s completions fish | source`, cmd))
		}
	}

	if len(block) == 0 {
		return nil
	}

	if shell == "fish" {
		os.MkdirAll(filepath.Dir(rcFile), 0755)
	}

	f, err := os.OpenFile(rcFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "\n# Blocknet\n%s\n", strings.Join(block, "\n"))
	return err
}

func dirInPATH(dir string) bool {
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p == dir {
			return true
		}
	}
	return false
}

func readLine(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}
