package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
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
		return fmt.Errorf("invalid address %q: expected host:port, like 127.0.0.1:8332", addr)
	}
	if host == "" {
		return fmt.Errorf("missing host in %q", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port in %q: must be 1 to 65535", addr)
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
	green, _, _, _, _, reset := Palette(NoColor)
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

// errSetupCancelled means the user closed input (Ctrl-D) at a prompt.
var errSetupCancelled = errors.New("setup cancelled")

// setupCancelledError is a cancel that came after setup had already saved
// something. done lists what, for the cancel message.
type setupCancelledError struct{ done []string }

func (e *setupCancelledError) Error() string { return errSetupCancelled.Error() }
func (e *setupCancelledError) Is(target error) bool {
	return target == errSetupCancelled
}

func cmdSetup(args []string) error {
	if err := ExtraArgs(args, 0, "blocknet setup"); err != nil {
		return err
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("setup needs an interactive terminal")
	}
	err := runSetup(bufio.NewReader(os.Stdin))
	if errors.Is(err, errSetupCancelled) {
		// The cursor is still on the prompt line.
		fmt.Print("\n\n  Setup cancelled\n")
		var partial *setupCancelledError
		if errors.As(err, &partial) {
			fmt.Printf("  Already done: %s\n", strings.Join(partial.done, ", "))
		}
		fmt.Println()
		return nil
	}
	return err
}

func runSetup(reader *bufio.Reader) (err error) {
	green, cyan, _, _, dim, reset := Palette(NoColor)

	// done records what is already saved, so a later cancel can say so.
	var done []string
	defer func() {
		if len(done) > 0 && errors.Is(err, errSetupCancelled) {
			err = &setupCancelledError{done: done}
		}
	}()
	head := func(h string) { fmt.Printf("\n%s\n\n", h) }

	// askYes asks a yes or no question. hint is the text in parentheses.
	askYes := func(hint string, def bool) (bool, error) {
		fmt.Printf("  yes or no %s%s%s: ", cyan, hint, reset)
		answer, err := readLine(reader)
		if err != nil {
			return false, errSetupCancelled
		}
		return parseYes(answer, def), nil
	}

	head(SectionHead("Blocknet setup", NoColor))
	fmt.Println("  This walks you through setting up your node.")
	fmt.Println("  You can run it again or edit the config file at any time.")

	cfgPath := ConfigFile()
	cfg := DefaultConfig()
	hasExisting := false

	if _, err := os.Stat(cfgPath); err == nil {
		if loaded, loadErr := LoadConfig(cfgPath); loadErr == nil {
			cfg = loaded
			hasExisting = true
			fmt.Println()
			fmt.Printf("  Current config: %s%s%s\n", dim, cfgPath, reset)
			for _, n := range []Network{Mainnet, Testnet} {
				cc := cfg.Cores[n]
				if cc == nil {
					continue
				}
				tag := "disabled"
				if cc.Enabled {
					tag = fmt.Sprintf("enabled, API %s", cc.APIAddr)
				}
				label := strings.ToUpper(string(n)[:1]) + string(n)[1:] + ":"
				fmt.Printf("  %s%s\n", PadRight(label, 10), tag)
			}
		}
	}
	if cfg.Cores == nil {
		cfg.Cores = map[Network]*CoreConfig{}
	}
	if cfg.Cores[Mainnet] == nil {
		cfg.Cores[Mainnet] = DefaultConfig().Cores[Mainnet]
	}

	ynHint := func(current, def bool) string {
		if hasExisting {
			return fmt.Sprintf("(current: %s%s%s, default: %s)", green, YesNo(current), cyan, YesNo(def))
		}
		return fmt.Sprintf("(default: %s)", YesNo(def))
	}

	ynVal := func(current, def bool) bool {
		if hasExisting {
			return current
		}
		return def
	}

	// askAddr asks for a host:port. An empty answer keeps current (or def
	// when there is none); an invalid one warns and keeps it too.
	askAddr := func(current, def string) (string, error) {
		keep := current
		if keep == "" {
			keep = def
		}
		hint := fmt.Sprintf("(default: %s)", def)
		if hasExisting && current != "" {
			hint = fmt.Sprintf("(current: %s%s%s, default: %s)", green, current, cyan, def)
		}
		fmt.Printf("  %s%s%s: ", cyan, hint, reset)
		answer, err := readLine(reader)
		if err != nil {
			return "", errSetupCancelled
		}
		if answer == "" {
			return keep, nil
		}
		if err := validateAddr(answer); err != nil {
			Warnf("%v; using %s", err, keep)
			return keep, nil
		}
		return answer, nil
	}

	// askExplorer asks whether to serve a block explorer and on which address.
	askExplorer := func(net Network, cc *CoreConfig, def string) error {
		enabled := cc.ExplorerAddr != ""
		fmt.Printf("  Enable the %s block explorer?\n", net)
		fmt.Printf("  %sServes a block explorer you can open in your browser.%s\n", dim, reset)
		yes, err := askYes(ynHint(enabled, true), ynVal(enabled, true))
		if err != nil {
			return err
		}
		if !yes {
			cc.ExplorerAddr = ""
			return nil
		}
		fmt.Println()
		fmt.Printf("  Explorer address for %s:\n", net)
		addr, err := askAddr(cc.ExplorerAddr, def)
		if err != nil {
			return err
		}
		cc.ExplorerAddr = addr
		return nil
	}

	// Advanced settings
	head(SectionHead("Advanced", NoColor))
	fmt.Println("  Configure advanced settings?")
	fmt.Printf("  %s(testnet, API ports, explorer, checkpoints)%s\n", dim, reset)
	advanced, err := askYes("(default: yes)", true)
	if err != nil {
		return err
	}
	if advanced {
		// Testnet
		head(NetHead(Testnet, "Testnet", NoColor))
		testnetEnabled := cfg.Cores[Testnet] != nil && cfg.Cores[Testnet].Enabled
		fmt.Println("  Enable testnet? It is a separate network for testing. Its coins have no value.")
		yes, err := askYes(ynHint(testnetEnabled, true), ynVal(testnetEnabled, true))
		if err != nil {
			return err
		}
		if yes {
			if cfg.Cores[Testnet] == nil {
				cfg.Cores[Testnet] = &CoreConfig{Version: "latest", APIAddr: "127.0.0.1:18332"}
			}
			tc := cfg.Cores[Testnet]
			tc.Enabled = true
			fmt.Println()
			fmt.Println("  Testnet API address, where tools connect to your testnet node:")
			if tc.APIAddr, err = askAddr(tc.APIAddr, "127.0.0.1:18332"); err != nil {
				return err
			}
			fmt.Println()
			if err := askExplorer(Testnet, tc, "127.0.0.1:18080"); err != nil {
				return err
			}
		} else if cfg.Cores[Testnet] != nil {
			cfg.Cores[Testnet].Enabled = false
		}

		// Mainnet
		mc := cfg.Cores[Mainnet]
		head(NetHead(Mainnet, "Mainnet", NoColor))
		fmt.Println("  Mainnet API address, where tools like 'blocknet attach' connect to your node:")
		if mc.APIAddr, err = askAddr(mc.APIAddr, "127.0.0.1:8332"); err != nil {
			return err
		}
		fmt.Println()
		if err := askExplorer(Mainnet, mc, "127.0.0.1:8080"); err != nil {
			return err
		}

		// Checkpoints
		head(SectionHead("Sync", NoColor))
		currentCheckpoints := false
		for _, cc := range cfg.Cores {
			if cc.SaveCheckpoints {
				currentCheckpoints = true
				break
			}
		}
		fmt.Println("  Save checkpoints during sync?")
		fmt.Printf("  %sWrites a checkpoint every 100 blocks so future syncs can skip verified ranges.%s\n", dim, reset)
		save, err := askYes(ynHint(currentCheckpoints, false), ynVal(currentCheckpoints, false))
		if err != nil {
			return err
		}
		for _, cc := range cfg.Cores {
			cc.SaveCheckpoints = save
		}
	}

	// Save config
	head(SectionHead("Config", NoColor))
	if err := EnsureConfigDir(); err != nil {
		return fmt.Errorf("could not create the config directory: %w", err)
	}
	if err := SaveConfig(cfgPath, cfg); err != nil {
		return fmt.Errorf("could not save config: %w", err)
	}
	fmt.Printf("  %s✓%s Saved to %s%s%s\n", green, reset, dim, cfgPath, reset)
	done = append(done, "config saved to "+cfgPath)

	if binPath, _ := os.Executable(); binPath != "" {
		if err := installSchedule(binPath, cfg.CheckIntervalDuration()); err != nil {
			Warnf("could not set up auto-updates: %v", err)
		} else {
			fmt.Printf("  %s✓%s Auto-updates scheduled\n", green, reset)
			done = append(done, "auto-updates scheduled")
		}
	}

	// Install core
	head(SectionHead("Core", NoColor))
	hasCore := false
	if resolved, err := ResolveInstalledVersion("latest"); err == nil {
		if _, err := os.Stat(CoreBinaryPath(resolved)); err == nil {
			hasCore = true
		}
	}

	if hasCore {
		fmt.Println("  A core version is already installed.")
	} else {
		fmt.Println("  You don't have a core installed yet. Download the latest one now?")
		fmt.Printf("  %sYou need one before you can start your node.%s\n", dim, reset)
		yes, err := askYes("(default: yes)", true)
		if err != nil {
			return err
		}
		if yes {
			hasCore = setupDownloadCore()
			if hasCore {
				done = append(done, "core installed")
			}
		}
	}

	// Shell integration
	if shell := detectShell(); shell != "" {
		rcFile := shellRCFile(shell)
		binPath, _ := os.Executable()

		head(SectionHead("Shell", NoColor))
		fmt.Println("  Set up the 'bnt' shortcut so you can use blocknet from any terminal?")
		fmt.Printf("  %sAdds blocknet to your PATH and turns on tab completion.%s\n", dim, reset)
		yes, err := askYes("(default: yes)", true)
		if err != nil {
			return err
		}
		if yes {
			changed, err := installShellIntegration(shell, rcFile, binPath)
			switch {
			case err != nil:
				Warnf("could not set up the shell: %v", err)
			case changed:
				fmt.Printf("  %s✓%s Updated %s. Open a new terminal to use 'blocknet' and 'bnt'.\n", green, reset, rcFile)
			default:
				fmt.Printf("  %s✓%s Already set up in %s\n", green, reset, rcFile)
			}
		}
	}

	// Start now
	started := false
	if hasCore {
		head(SectionHead("Start", NoColor))
		fmt.Println("  Start your node now?")
		yes, err := askYes("(default: yes)", true)
		if err != nil {
			return err
		}
		if yes {
			// The "# Start" heading above stands for the start output too.
			fmt.Println()
			if err := startNetworks(nil, "", "blocknet start [mainnet|testnet]", nil); err != nil {
				Warnf("could not start: %v", err)
			} else {
				// cmdStart ends with a blank line of its own.
				started = true
			}
		} else {
			fmt.Printf("  You can start later with: %sblocknet start%s\n", green, reset)
		}
	}

	if !started {
		fmt.Println()
	}
	fmt.Printf("%s\n\n", SectionHead("Setup complete", NoColor))
	next := [][2]string{
		{"blocknet status", "See what's running"},
		{"blocknet attach mainnet", "Open the interactive shell"},
		{"blocknet help", "See all commands"},
	}
	for _, row := range next {
		fmt.Printf("  %s%s%s%s\n", PadRight(row[0], 26), dim, row[1], reset)
	}
	fmt.Println()
	return nil
}

// setupDownloadCore downloads and installs the latest core. It reports
// failures as warnings and returns whether a core is now installed.
func setupDownloadCore() bool {
	green, _, _, _, _, reset := Palette(NoColor)
	retry := "  Check your internet connection and try: blocknet install latest"
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	latest, err := LatestRelease(ctx)
	if err != nil {
		Warnf("could not check for releases: %v", err)
		fmt.Println(retry)
		return false
	}
	asset := FindAsset(latest.Assets)
	if asset == nil {
		Warnf("%s has no download for your platform", latest.Tag)
		fmt.Println("  You can install one later: blocknet install latest")
		return false
	}
	expectedSHA, err := ResolveAssetSHA256(ctx, latest.Assets, asset.Name)
	if err != nil {
		Warnf("could not get the checksum for %s: %v", latest.Tag, err)
		fmt.Println("  Try again later: blocknet install latest")
		return false
	}
	fmt.Printf("  Downloading %s (%s)\n", latest.Tag, asset.Name)
	if err := DownloadAsset(ctx, asset.URL, CoreBinaryPath(latest.Tag), expectedSHA, downloadProgress); err != nil {
		fmt.Println()
		Warnf("could not download %s: %v", latest.Tag, err)
		fmt.Println(retry)
		return false
	}
	fmt.Println()
	fmt.Printf("  %s✓%s Verified and installed %s\n", green, reset, latest.Tag)
	return true
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

// installShellIntegration adds the PATH entry, the bnt alias and completions
// to rcFile. It reports whether it changed the file.
func installShellIntegration(shell, rcFile, binPath string) (bool, error) {
	if rcFile == "" {
		return false, fmt.Errorf("could not find the rc file for %s", shell)
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
		return false, nil
	}

	if err := os.MkdirAll(filepath.Dir(rcFile), 0o755); err != nil {
		return false, err
	}

	f, err := os.OpenFile(rcFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false, err
	}
	if _, err := fmt.Fprintf(f, "\n# Blocknet\n%s\n", strings.Join(block, "\n")); err != nil {
		f.Close()
		return false, err
	}
	return true, f.Close()
}

func dirInPATH(dir string) bool {
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p == dir {
			return true
		}
	}
	return false
}

// readLine reads one answer. It returns io.EOF (or another read error) when
// input ends, so callers can stop instead of taking every default.
func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
