package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func cmdStart(args []string) error {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}
	if err := EnsureConfigDir(); err != nil {
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
		if len(networks) == 0 {
			return fmt.Errorf("no cores enabled in config — enable one or specify a network")
		}
	}

	if warns := validateConfig(cfg, networks); len(warns) > 0 {
		for _, w := range warns {
			fmt.Fprintf(os.Stderr, "  warning: %s\n", w)
		}
	}

	if cfg.AutoUpgrade {
		maybeAutoUpgrade(cfg)
		ensureScheduleFromConfig(cfg)
	}

	green, pink, dim, reset := "\033[38;2;170;255;0m", "\033[38;2;255;0;170m", "\033[38;2;160;160;160m", "\033[0m"
	if NoColor {
		green, pink, dim, reset = "", "", "", ""
	}
	netColor := func(net Network) string {
		if net == Testnet {
			return pink
		}
		return green
	}

	for _, net := range networks {
		if pid, err := readCorePidFile(net); err == nil && processAlive(pid) {
			fmt.Printf("  %s%s%s already running %s(pid %d)%s\n", netColor(net), net, reset, dim, pid, reset)
			continue
		}

		cc := cfg.Cores[net]
		if cc == nil {
			cc = &CoreConfig{Enabled: true, Version: "latest"}
			if net == Mainnet {
				cc.APIAddr = "127.0.0.1:8332"
			} else {
				cc.APIAddr = "127.0.0.1:18332"
			}
		}
		if !cc.Enabled {
			fmt.Printf("  %s%s%s is disabled — run %sblocknet enable %s%s first\n", netColor(net), net, reset, green, net, reset)
			continue
		}

		resolved, err := ResolveInstalledVersion(cc.Version)
		if err != nil {
			return fmt.Errorf("%s: %w", net, err)
		}
		binPath := CoreBinaryPath(resolved)

		fmt.Printf("  Starting %s%s%s core %s(%s)...%s\n", netColor(net), net, reset, dim, resolved, reset)
		pid, err := startCore(net, cc, binPath)
		if err != nil {
			return err
		}

		writeCorePidFile(net, pid)
		if cc.ExplorerAddr != "" {
			fmt.Printf("  %s✓%s %s%s%s running %s(pid %d, api %s, explorer %s)%s\n", green, reset, netColor(net), net, reset, dim, pid, cc.APIAddr, cc.ExplorerAddr, reset)
		} else {
			fmt.Printf("  %s✓%s %s%s%s running %s(pid %d, api %s)%s\n", green, reset, netColor(net), net, reset, dim, pid, cc.APIAddr, reset)
		}
	}
	return nil
}

func cmdStop(args []string) error {
	var networks []Network
	if len(args) > 0 {
		net, err := ParseNetwork(args[0])
		if err != nil {
			return err
		}
		networks = []Network{net}
	} else {
		networks = []Network{Mainnet, Testnet}
	}

	stopWatchdog()

	green, pink, dim, reset := "\033[38;2;170;255;0m", "\033[38;2;255;0;170m", "\033[38;2;160;160;160m", "\033[0m"
	if NoColor {
		green, pink, dim, reset = "", "", "", ""
	}
	_ = green

	stopped := 0
	for _, net := range networks {
		if err := stopCore(net); err != nil {
			if len(args) > 0 {
				return err
			}
			continue
		}
		stopped++
		nc := green
		if net == Testnet {
			nc = pink
		}
		fmt.Printf("  %s%s%s core %sstopped%s\n", nc, net, reset, dim, reset)
	}
	if stopped == 0 && len(args) == 0 {
		fmt.Printf("  %sNo cores running%s\n", dim, reset)
	}
	return nil
}

func cmdRestart(args []string) error {
	cmdStop(args)
	return cmdStart(args)
}

func cmdStatus(_ []string) error {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	if cfg.AutoUpgrade {
		maybeAutoUpgrade(cfg)
	}

	green, pink, dim, reset := "\033[38;2;170;255;0m", "\033[38;2;255;0;170m", "\033[2m", "\033[0m"
	if NoColor {
		green, pink, dim, reset = "", "", "", ""
	}

	watchedNets := make(map[Network]bool)
	if wdPid, _, err := readWatchdogState(); err == nil && processAlive(wdPid) {
		_, nets, _ := readWatchdogState()
		for _, n := range nets {
			watchedNets[n] = true
		}
	}

	for _, net := range []Network{Mainnet, Testnet} {
		cc := cfg.Cores[net]
		if cc == nil {
			continue
		}

		netColor := green
		if net == Testnet {
			netColor = pink
		}

		enabledTag := fmt.Sprintf("%senabled%s", netColor, reset)
		if !cc.Enabled {
			enabledTag = fmt.Sprintf("%sdisabled%s", dim, reset)
		}

		pid, pidErr := readCorePidFile(net)
		alive := pidErr == nil && processAlive(pid)
		healthy := alive && cc.APIAddr != "" && checkHealth(cc.APIAddr)

		amber := "\033[38;2;255;170;0m"
		if NoColor {
			amber = ""
		}

		runTag := fmt.Sprintf("%sstopped%s", dim, reset)
		if alive && healthy {
			runTag = fmt.Sprintf("%srunning%s", netColor, reset)
		} else if alive {
			runTag = fmt.Sprintf("%sunresponsive%s", amber, reset)
		}

		monitorTag := ""
		if watchedNets[net] {
			monitorTag = fmt.Sprintf(" [%smonitored%s]", netColor, reset)
		}

		versionLabel := cc.Version
		if IsPinned(cc.Version) {
			versionLabel = fmt.Sprintf("%s %s(pinned)%s", cc.Version, dim, reset)
		} else if resolved, err := ResolveInstalledVersion(cc.Version); err == nil && resolved != cc.Version {
			versionLabel = fmt.Sprintf("%s (%s)", resolved, cc.Version)
		}

		fmt.Printf("\n%s#%s %s [%s] [%s]%s\n", netColor, reset, net, runTag, enabledTag, monitorTag)
		fmt.Printf("  Version: %s\n", versionLabel)

		if !healthy || cc.APIAddr == "" {
			continue
		}

		dataDir := cc.ResolveDataDir(net)
		client, err := NewCoreClient(cc.APIAddr, CookiePath(dataDir))
		if err != nil {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		raw, err := client.Status(ctx)
		cancel()
		if err != nil {
			continue
		}

		var status struct {
			Height  uint64 `json:"chain_height"`
			Peers   int    `json:"peers"`
			Syncing bool   `json:"syncing"`
		}
		json.Unmarshal(raw, &status)

		fmt.Printf("  Height:   %d\n", status.Height)
		fmt.Printf("  Peers:    %d\n", status.Peers)
		fmt.Printf("  Syncing:  %v\n", status.Syncing)
		fmt.Printf("  API:      %s\n", cc.APIAddr)
		if cc.ExplorerAddr != "" {
			fmt.Printf("  Explorer: %s\n", cc.ExplorerAddr)
		}
	}
	fmt.Println()
	return nil
}

func cmdAttach(args []string) error {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	var targetNet Network
	if len(args) > 0 {
		targetNet, err = ParseNetwork(args[0])
		if err != nil {
			return err
		}
	} else {
		var enabled []Network
		for _, net := range []Network{Mainnet, Testnet} {
			cc := cfg.Cores[net]
			if cc != nil && cc.Enabled && cc.APIAddr != "" {
				enabled = append(enabled, net)
			}
		}
		switch len(enabled) {
		case 0:
			return fmt.Errorf("no cores enabled with an API address")
		case 1:
			targetNet = enabled[0]
		default:
			targetNet = Mainnet
		}
	}

	cc := cfg.Cores[targetNet]
	if cc == nil || cc.APIAddr == "" {
		return fmt.Errorf("%s has no API address configured", targetNet)
	}

	dataDir := cc.ResolveDataDir(targetNet)
	client, err := NewCoreClient(cc.APIAddr, CookiePath(dataDir))
	if err != nil {
		return fmt.Errorf("cannot connect to %s core: %w", targetNet, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_, err = client.Status(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("%s core is not reachable at %s", targetNet, cc.APIAddr)
	}

	session := NewAttachSession(client, targetNet, NoColor)
	return session.Run()
}

func cmdEnable(args []string) error  { return setEnabled(args, true) }
func cmdDisable(args []string) error { return setEnabled(args, false) }

func setEnabled(args []string, enabled bool) error {
	if len(args) == 0 {
		word := "enable"
		if !enabled {
			word = "disable"
		}
		return fmt.Errorf("usage: blocknet %s <mainnet|testnet>", word)
	}

	net, err := ParseNetwork(args[0])
	if err != nil {
		return err
	}

	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	cc := cfg.Cores[net]
	if cc == nil {
		return fmt.Errorf("no config for %s", net)
	}

	cc.Enabled = enabled
	if !enabled {
		stopWatchdog()
	}
	if err := EnsureConfigDir(); err != nil {
		return err
	}
	if err := SaveConfig(ConfigFile(), cfg); err != nil {
		return err
	}

	green, pink, dim, reset := "\033[38;2;170;255;0m", "\033[38;2;255;0;170m", "\033[38;2;160;160;160m", "\033[0m"
	if NoColor {
		green, pink, dim, reset = "", "", "", ""
	}
	nc := green
	if net == Testnet {
		nc = pink
	}
	label := "enabled"
	labelColor := green
	if !enabled {
		label = "disabled"
		labelColor = dim
	}
	fmt.Printf("  %s%s%s %s%s%s\n", nc, net, reset, labelColor, label, reset)
	return nil
}

func cmdUpgrade(_ []string) error {
	green, cyan, amber, dim, reset := "\033[38;2;170;255;0m", "\033[38;2;0;170;255m", "\033[38;2;255;170;0m", "\033[38;2;160;160;160m", "\033[0m"
	if NoColor {
		green, cyan, amber, dim, reset = "", "", "", "", ""
	}

	fmt.Printf("\n%s\n\n", SectionHead("Upgrade", NoColor))
	fmt.Printf("  %sChecking for new releases...%s\n", dim, reset)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	latest, err := LatestRelease(ctx)
	if err != nil {
		return fmt.Errorf("fetch releases: %w", err)
	}

	fmt.Printf("  Latest: %s%s%s %s(%s)%s\n", green, latest.Tag, reset, dim, latest.Date.Format("Jan 02, 2006"), reset)

	destPath := CoreBinaryPath(latest.Tag)
	if _, err := os.Stat(destPath); err == nil {
		fmt.Printf("  %s%s already installed%s\n\n", dim, latest.Tag, reset)
		return nil
	}

	asset := FindAsset(latest.Assets)
	if asset == nil {
		return fmt.Errorf("release %s does not include a binary for your platform (%s)\n  this is expected for early releases before multi-platform builds were added\n  try a newer version: blocknet install latest", latest.Tag, BinaryName())
	}
	expectedSHA, err := ResolveAssetSHA256(ctx, latest.Assets, asset.Name)
	if err != nil {
		return fmt.Errorf("checksum: %w", err)
	}

	fmt.Printf("  %sDownloading %s...%s\n", cyan, asset.Name, reset)
	dlCtx, dlCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer dlCancel()

	if err := DownloadAsset(dlCtx, asset.URL, destPath, expectedSHA, downloadProgress); err != nil {
		fmt.Println()
		return fmt.Errorf("download: %w", err)
	}
	fmt.Printf("\n  %s✓ verified%s", green, reset)
	fmt.Printf("\n  %s✓%s Installed %s%s%s\n", green, reset, green, latest.Tag, reset)

	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	restarted := 0
	for _, net := range []Network{Mainnet, Testnet} {
		cc := cfg.Cores[net]
		if cc == nil || IsPinned(cc.Version) {
			continue
		}
		pid, pidErr := readCorePidFile(net)
		if pidErr != nil || !processAlive(pid) {
			continue
		}
		fmt.Printf("  %sRestarting %s core with %s...%s\n", amber, net, latest.Tag, reset)
		stopCore(net)
		newPid, err := startCore(net, cc, destPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s✗ %s restart failed: %v%s\n", "\033[38;2;255;0;170m", net, err, reset)
			continue
		}
		writeCorePidFile(net, newPid)
		fmt.Printf("  %s✓%s %s core running %s(pid %d)%s\n", green, reset, net, dim, newPid, reset)
		restarted++
	}

	if restarted == 0 {
		fmt.Printf("  %sRestart running cores to use the new version%s\n", dim, reset)
	}
	fmt.Println()
	return nil
}

func cmdList(_ []string) error {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	releases, err := ListReleases(ctx)
	if err != nil {
		return fmt.Errorf("fetch releases: %w", err)
	}

	inUse := make(map[string][]Network)
	for _, net := range []Network{Mainnet, Testnet} {
		cc := cfg.Cores[net]
		if cc == nil || !cc.Enabled {
			continue
		}
		v := strings.ToLower(cc.Version)
		if v == "latest" {
			if resolved, err := ResolveInstalledVersion("latest"); err == nil {
				inUse[resolved] = append(inUse[resolved], net)
			}
		} else {
			inUse[cc.Version] = append(inUse[cc.Version], net)
		}
	}

	installed := make(map[string]bool)
	for _, r := range releases {
		if _, err := os.Stat(CoreBinaryPath(r.Tag)); err == nil {
			installed[r.Tag] = true
		}
	}
	if _, err := os.Stat(CoreBinaryPath("nightly")); err == nil {
		installed["nightly"] = true
	}

	cyan, green, pink, dim, reset := "\033[38;2;0;170;255m", "\033[38;2;170;255;0m", "\033[38;2;255;0;170m", "\033[38;2;160;160;160m", "\033[0m"
	if NoColor {
		cyan, green, pink, dim, reset = "", "", "", "", ""
	}

	fmt.Printf("\n%s\n\n", SectionHead("Versions", NoColor))
	fmt.Printf("  %s%-12s %-18s %s%s\n", dim, "version", "date", "status", reset)
	fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 50), reset)

	formatNets := func(nets []Network) string {
		var parts []string
		for _, net := range nets {
			c := green
			if net == Testnet {
				c = pink
			}
			parts = append(parts, fmt.Sprintf("%s[%s]%s", c, net, reset))
		}
		return strings.Join(parts, " ")
	}

	nightlyStatus := ""
	if nets, ok := inUse["nightly"]; ok {
		nightlyStatus = formatNets(nets)
	} else if installed["nightly"] {
		nightlyStatus = fmt.Sprintf("%sinstalled%s", cyan, reset)
	}
	fmt.Printf("  %-12s %-18s %s\n", "nightly", "latest", nightlyStatus)

	for _, r := range releases {
		if r.Prerelease {
			continue
		}
		date := r.Date.Format("Jan 02, 2006")
		status := ""
		if nets, ok := inUse[r.Tag]; ok {
			status = formatNets(nets)
		} else if installed[r.Tag] {
			status = fmt.Sprintf("%sinstalled%s", cyan, reset)
		} else {
			date = fmt.Sprintf("%s%s%s", dim, date, reset)
		}
		fmt.Printf("  %-12s %-18s %s\n", r.Tag, date, status)
	}
	fmt.Println()
	return nil
}

func cmdInstall(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: blocknet install <version>")
	}
	version := args[0]

	green, cyan, dim, reset := "\033[38;2;170;255;0m", "\033[38;2;0;170;255m", "\033[38;2;160;160;160m", "\033[0m"
	if NoColor {
		green, cyan, dim, reset = "", "", "", ""
	}

	fmt.Printf("\n%s\n\n", SectionHead("Install", NoColor))
	fmt.Printf("  %sFinding %s...%s\n", dim, version, reset)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if strings.EqualFold(version, "latest") {
		latest, err := LatestRelease(ctx)
		if err != nil {
			return fmt.Errorf("fetch releases: %w", err)
		}
		version = latest.Tag
		fmt.Printf("  Latest is %s%s%s\n", green, version, reset)
	}

	destPath := CoreBinaryPath(version)
	if version != "nightly" {
		if _, err := os.Stat(destPath); err == nil {
			fmt.Printf("  %s%s already installed%s\n\n", dim, version, reset)
			return nil
		}
	}

	releases, err := ListReleases(ctx)
	if err != nil {
		return fmt.Errorf("fetch releases: %w", err)
	}

	var asset *Asset
	var expectedSHA string
	for _, r := range releases {
		if r.Tag != version {
			continue
		}
		asset = FindAsset(r.Assets)
		if asset == nil {
			break
		}
		expectedSHA, err = ResolveAssetSHA256(ctx, r.Assets, asset.Name)
		if err != nil {
			return fmt.Errorf("checksum: %w", err)
		}
		break
	}
	if asset == nil {
		return fmt.Errorf("release %s does not include a binary for your platform (%s)\n  this is expected for early releases before multi-platform builds were added\n  try: blocknet list (to see available versions)", version, BinaryName())
	}

	fmt.Printf("  %sDownloading %s%s\n", cyan, asset.Name, reset)
	dlCtx, dlCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer dlCancel()

	if err := DownloadAsset(dlCtx, asset.URL, destPath, expectedSHA, downloadProgress); err != nil {
		fmt.Println()
		return fmt.Errorf("download: %w", err)
	}
	fmt.Printf("\n  %s✓ verified%s", green, reset)
	fmt.Printf("\n  %s✓%s Installed %s%s%s\n\n", green, reset, green, version, reset)
	return nil
}

func cmdUninstall(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: blocknet uninstall <version>")
	}
	version := args[0]

	dim, reset := "\033[38;2;160;160;160m", "\033[0m"
	if NoColor {
		dim, reset = "", ""
	}

	dir := CoreDir(version)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("%s is not installed", version)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove %s: %w", dir, err)
	}
	fmt.Printf("\n  %sUninstalled %s%s\n\n", dim, version, reset)
	return nil
}

func cmdUse(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: blocknet use <version> [mainnet|testnet]")
	}
	version := args[0]

	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	if len(args) >= 2 {
		net, err := ParseNetwork(args[1])
		if err != nil {
			return err
		}
		cc := cfg.Cores[net]
		if cc == nil {
			return fmt.Errorf("no config for %s", net)
		}
		cc.Version = version
		fmt.Printf("  %s set to %s\n", net, version)
	} else {
		for _, net := range []Network{Mainnet, Testnet} {
			if cc := cfg.Cores[net]; cc != nil {
				cc.Version = version
			}
		}
		fmt.Printf("  All cores set to %s\n", version)
	}

	if err := EnsureConfigDir(); err != nil {
		return err
	}
	return SaveConfig(ConfigFile(), cfg)
}

func cmdConfig(_ []string) error {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("\n%s\n\n", SectionHead("Config", NoColor))
	fmt.Println(ColorizeJSON(string(data), NoColor))
	return nil
}

func cmdLogs(args []string) error {
	net := Mainnet
	if len(args) > 0 {
		var err error
		net, err = ParseNetwork(args[0])
		if err != nil {
			return err
		}
	}

	path := LogFile(net)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("no log file for %s (has it been started?)", net)
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, _ := f.Stat()
	offset := int64(0)
	if info.Size() > 8192 {
		offset = info.Size() - 8192
	}
	f.Seek(offset, io.SeekStart)
	if offset > 0 {
		buf := make([]byte, 1)
		for {
			_, err := f.Read(buf)
			if err != nil || buf[0] == '\n' {
				break
			}
		}
	}
	io.Copy(os.Stdout, f)

	fmt.Printf("\n  following %s log... (ctrl+c to stop)\n\n", net)

	for {
		n, err := io.Copy(os.Stdout, f)
		if err != nil {
			return err
		}
		if n == 0 {
			time.Sleep(250 * time.Millisecond)
		}
	}
}

func cmdCleanup(_ []string) error {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	inUse := make(map[string]bool)
	for _, net := range []Network{Mainnet, Testnet} {
		cc := cfg.Cores[net]
		if cc == nil {
			continue
		}
		if resolved, err := ResolveInstalledVersion(cc.Version); err == nil {
			inUse[resolved] = true
		}
		if IsPinned(cc.Version) {
			inUse[cc.Version] = true
		}
	}

	coresDir := filepath.Join(ConfigDir(), "cores")
	entries, err := os.ReadDir(coresDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("  No core versions installed")
			return nil
		}
		return err
	}

	var removed int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ver := e.Name()
		if inUse[ver] {
			continue
		}
		dir := filepath.Join(coresDir, ver)
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not remove %s: %v\n", ver, err)
			continue
		}
		fmt.Printf("  Removed %s\n", ver)
		removed++
	}

	if removed == 0 {
		fmt.Println("  Nothing to clean up")
	} else {
		fmt.Printf("  Cleaned up %d version(s)\n", removed)
	}
	return nil
}
