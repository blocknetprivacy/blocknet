package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// defaultCoreConfig is the stock config for one network, the same one a fresh
// config file gets.
func defaultCoreConfig(net Network) *CoreConfig {
	if cc := DefaultConfig().Cores[net]; cc != nil {
		return cc
	}
	return &CoreConfig{Version: "latest"}
}

// ensureCoreConfig returns the config for net, adding the default one when
// the config file has none.
func ensureCoreConfig(cfg *Config, net Network) *CoreConfig {
	if cfg.Cores == nil {
		cfg.Cores = make(map[Network]*CoreConfig)
	}
	if cfg.Cores[net] == nil {
		cfg.Cores[net] = defaultCoreConfig(net)
	}
	return cfg.Cores[net]
}

// pickNetwork chooses a network when the user named none: the only enabled
// one, else mainnet. With needAPI, only cores with an API address count.
func pickNetwork(cfg *Config, needAPI bool) (Network, int) {
	var enabled []Network
	for _, net := range []Network{Mainnet, Testnet} {
		cc := cfg.Cores[net]
		if cc != nil && cc.Enabled && (!needAPI || cc.APIAddr != "") {
			enabled = append(enabled, net)
		}
	}
	if len(enabled) == 1 {
		return enabled[0], 1
	}
	return Mainnet, len(enabled)
}

// versionsInUse maps each installed core version to the networks that run
// it: what "latest" or "nightly" resolves to, plus every pinned version.
// With enabledOnly, disabled cores do not count.
func versionsInUse(cfg *Config, enabledOnly bool) map[string][]Network {
	inUse := make(map[string][]Network)
	add := func(ver string, net Network) {
		if !slices.Contains(inUse[ver], net) {
			inUse[ver] = append(inUse[ver], net)
		}
	}
	for _, net := range []Network{Mainnet, Testnet} {
		cc := cfg.Cores[net]
		if cc == nil || (enabledOnly && !cc.Enabled) {
			continue
		}
		if resolved, err := ResolveInstalledVersion(cc.Version); err == nil {
			add(resolved, net)
		}
		if IsPinned(cc.Version) {
			add(cc.Version, net)
		}
	}
	return inUse
}

// inUseBy returns the networks using ver. Versions compare without case:
// macOS and Windows folders are case-insensitive, so "V1.0.0" and "v1.0.0"
// are the same installed core.
func inUseBy(inUse map[string][]Network, ver string) ([]Network, bool) {
	var nets []Network
	found := false
	for v, ns := range inUse {
		if strings.EqualFold(v, ver) {
			found = true
			for _, n := range ns {
				if !slices.Contains(nets, n) {
					nets = append(nets, n)
				}
			}
		}
	}
	slices.Sort(nets)
	return nets, found
}

func joinNetworks(nets []Network) string {
	parts := make([]string, len(nets))
	for i, n := range nets {
		parts[i] = string(n)
	}
	return strings.Join(parts, " and ")
}

// normalizeVersion lowercases the tracking names, checks the rest is a safe
// folder name, and maps it to the installed folder's real name when only the
// case differs.
func normalizeVersion(v string) (string, error) {
	if l := strings.ToLower(v); l == "latest" || l == "nightly" {
		return l, nil
	}
	if err := ValidateVersionName(v); err != nil {
		return "", err
	}
	return canonicalVersion(v), nil
}

func cmdStart(args []string) error {
	return startNetworks(args, "Start", "blocknet start [mainnet|testnet]", nil)
}

func cmdRestart(args []string) error {
	return startNetworks(args, "Restart", "blocknet restart [mainnet|testnet]", func(networks []Network) {
		// Keep the watchdog watching: the core comes straight back.
		if err := stopNetworks(networks, true, false); err != nil {
			Warnf("%v", err)
		}
	})
}

// startNetworks starts the named network, or every enabled one. before runs
// after the heading and before anything starts (restart uses it to stop).
// An empty title prints no heading (setup has printed its own).
func startNetworks(args []string, title, usage string, before func([]Network)) error {
	if err := ExtraArgs(args, 1, usage); err != nil {
		return err
	}
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
			return fmt.Errorf("no cores enabled: run blocknet enable <mainnet|testnet> or name a network")
		}
	}

	green, _, _, _, dim, reset := Palette(NoColor)
	nc := func(net Network) string { return NetColor(net, NoColor) }

	if title != "" {
		fmt.Printf("\n%s\n\n", SectionHead(title, NoColor))
	}

	for _, w := range validateConfig(cfg, networks) {
		Warnf("%s", w)
	}

	if before != nil {
		before(networks)
	}

	maybeAutoUpgrade(cfg)
	ensureScheduleFromConfig(cfg)

	for _, net := range networks {
		if pid, err := readCorePidFile(net); err == nil && processAlive(pid) {
			fmt.Printf("  %s%s%s already running %s(pid %d)%s\n", nc(net), net, reset, dim, pid, reset)
			watchNetwork(net)
			continue
		}

		cc := cfg.Cores[net]
		if cc == nil {
			cc = defaultCoreConfig(net)
			cc.Enabled = true
		}
		if !cc.Enabled {
			fmt.Printf("  %s%s%s is disabled. Run %sblocknet enable %s%s first.\n", nc(net), net, reset, green, net, reset)
			continue
		}

		resolved, err := ResolveInstalledVersion(cc.Version)
		if err != nil {
			return fmt.Errorf("%s: %w", net, err)
		}
		binPath := CoreBinaryPath(resolved)

		refreshCheckpointsBeforeStart(net, cc)

		fmt.Printf("  Starting %s%s%s core %s(%s)...%s\n", nc(net), net, reset, dim, resolved, reset)
		pid, err := startCore(net, cc, binPath)
		if err != nil {
			return err
		}
		// "stop <net>" took it out of a running watchdog's set: put it back.
		watchNetwork(net)

		if cc.ExplorerAddr != "" {
			fmt.Printf("  %s✓%s %s%s%s running %s(pid %d, api %s, explorer %s)%s\n", green, reset, nc(net), net, reset, dim, pid, cc.APIAddr, cc.ExplorerAddr, reset)
		} else {
			fmt.Printf("  %s✓%s %s%s%s running %s(pid %d, api %s)%s\n", green, reset, nc(net), net, reset, dim, pid, cc.APIAddr, reset)
		}
	}
	printUpgradeNotice(runningCoreNotice(cfg), NoColor)
	fmt.Println()
	return nil
}

func cmdStop(args []string) error {
	if err := ExtraArgs(args, 1, "blocknet stop [mainnet|testnet]"); err != nil {
		return err
	}
	networks := []Network{Mainnet, Testnet}
	if len(args) > 0 {
		net, err := ParseNetwork(args[0])
		if err != nil {
			return err
		}
		networks = []Network{net}
	}

	fmt.Printf("\n%s\n\n", SectionHead("Stop", NoColor))
	if err := stopNetworks(networks, len(args) > 0, true); err != nil {
		return err
	}
	fmt.Println()
	return nil
}

// stopNetworks stops each core. A core that is not running is not an error.
// With explicit (the user named the network) a real failure is returned;
// otherwise it is shown as a warning and the next core is stopped. With
// unwatch, each network is also taken out of the watchdog's set.
func stopNetworks(networks []Network, explicit, unwatch bool) error {
	_, _, _, _, dim, reset := Palette(NoColor)

	stopped, failed := 0, 0
	for _, net := range networks {
		if unwatch {
			unwatchNetwork(net)
		}
		err := stopCore(net)
		switch {
		case err == nil:
			stopped++
			fmt.Printf("  %s%s%s core stopped\n", NetColor(net, NoColor), net, reset)
		case errors.Is(err, errCoreNotRunning):
			if explicit {
				fmt.Printf("  %s%s%s core %snot running%s\n", NetColor(net, NoColor), net, reset, dim, reset)
			}
		case explicit:
			return err
		default:
			failed++
			Warnf("%v", err)
		}
	}
	if stopped == 0 && failed == 0 && !explicit {
		fmt.Printf("  %sNo cores running%s\n", dim, reset)
	}
	return nil
}

func cmdStatus(args []string) error {
	if err := ExtraArgs(args, 0, "blocknet status"); err != nil {
		return err
	}
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	spawnAutoUpgrade(cfg)

	_, _, amber, _, dim, reset := Palette(NoColor)

	notice := builtinUpgradeNotice

	watchedNets := make(map[Network]bool)
	if wdPid, nets, err := readWatchdogState(); err == nil && processAlive(wdPid) {
		for _, n := range nets {
			watchedNets[n] = true
		}
	}

	// One column for every value: the longest label is "Explorer:".
	row := func(label, value string) {
		fmt.Printf("  %s %s\n", PadRight(label+":", len("Explorer:")), value)
	}

	for _, net := range []Network{Mainnet, Testnet} {
		cc := cfg.Cores[net]
		if cc == nil {
			continue
		}

		netColor := NetColor(net, NoColor)

		enabledTag := fmt.Sprintf("%senabled%s", netColor, reset)
		if !cc.Enabled {
			enabledTag = fmt.Sprintf("%sdisabled%s", dim, reset)
		}

		pid, pidErr := readCorePidFile(net)
		alive := pidErr == nil && processAlive(pid)
		healthy := alive && cc.APIAddr != "" && checkHealth(cc.APIAddr)

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

		label := fmt.Sprintf("%s [%s] [%s]%s", net, runTag, enabledTag, monitorTag)
		fmt.Printf("\n%s\n\n", NetHead(net, label, NoColor))
		row("Version", versionLabel)

		if !healthy || cc.APIAddr == "" {
			continue
		}

		dataDir := cc.ResolveDataDir(net)
		client, err := NewCoreClient(cc.APIAddr, CookiePath(dataDir))
		if err != nil {
			continue
		}

		ctx, cancel := withPatience(defaultAPITimeout)
		raw, err := client.Status(ctx)
		cancel()
		if err != nil {
			continue
		}
		notice = upgradeNoticeFrom(raw)

		var status struct {
			Height  uint64 `json:"chain_height"`
			Peers   int    `json:"peers"`
			Syncing bool   `json:"syncing"`
		}
		json.Unmarshal(raw, &status)

		row("Height", fmt.Sprintf("%d", status.Height))
		row("Peers", fmt.Sprintf("%d", status.Peers))
		row("Syncing", YesNo(status.Syncing))
		row("API", cc.APIAddr)
		if cc.ExplorerAddr != "" {
			row("Explorer", cc.ExplorerAddr)
		}
	}
	printUpgradeNotice(notice, NoColor)
	fmt.Println()
	return nil
}

func cmdAttach(args []string) error {
	if err := ExtraArgs(args, 1, "blocknet attach [mainnet|testnet]"); err != nil {
		return err
	}
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
		var n int
		targetNet, n = pickNetwork(cfg, true)
		if n == 0 {
			return fmt.Errorf("no cores enabled with an API address")
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

	var lastErr error
	deadline := time.Now().Add(defaultAPITimeout)
	warned := false
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, lastErr = client.Status(ctx)
		cancel()
		if lastErr == nil {
			break
		}
		if !warned && time.Now().Add(3*time.Second).Before(deadline) {
			fmt.Printf("  Waiting for %s core at %s...\n", targetNet, cc.APIAddr)
			warned = true
		}
		time.Sleep(25 * time.Millisecond)
	}
	if lastErr != nil {
		return fmt.Errorf("%s core is not reachable at %s: %v", targetNet, cc.APIAddr, lastErr)
	}

	session := NewAttachSession(client, targetNet, NoColor)
	return session.Run()
}

func cmdEnable(args []string) error  { return setEnabled(args, true) }
func cmdDisable(args []string) error { return setEnabled(args, false) }

func setEnabled(args []string, enabled bool) error {
	word, title := "enable", "Enable"
	if !enabled {
		word, title = "disable", "Disable"
	}
	usage := fmt.Sprintf("blocknet %s <mainnet|testnet>", word)
	if len(args) == 0 {
		return fmt.Errorf("usage: %s", usage)
	}
	if err := ExtraArgs(args, 1, usage); err != nil {
		return err
	}

	net, err := ParseNetwork(args[0])
	if err != nil {
		return err
	}

	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	cc := ensureCoreConfig(cfg, net)
	cc.Enabled = enabled
	if err := EnsureConfigDir(); err != nil {
		return err
	}
	if err := SaveConfig(ConfigFile(), cfg); err != nil {
		return err
	}
	if !enabled {
		unwatchNetwork(net)
	}

	green, _, _, _, _, reset := Palette(NoColor)
	fmt.Printf("\n%s\n\n", SectionHead(title, NoColor))
	fmt.Printf("  %s✓%s %s%s%s %sd\n\n", green, reset, NetColor(net, NoColor), net, reset, word)
	return nil
}

func cmdUpgrade(args []string) error {
	if err := ExtraArgs(args, 0, "blocknet upgrade"); err != nil {
		return err
	}
	green, _, _, _, dim, reset := Palette(NoColor)

	fmt.Printf("\n%s\n\n", SectionHead("Upgrade", NoColor))
	fmt.Printf("  %sChecking for new releases...%s\n", dim, reset)

	if tag, err := selfUpgrade(); err != nil {
		Warnf("blocknet self-upgrade failed: %v", err)
	} else if tag != "" {
		fmt.Printf("  %s✓%s Blocknet upgraded to %s%s%s\n", green, reset, green, tag, reset)
	}

	stableErr := upgradeStable()

	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}
	if usesNightly(cfg) {
		fmt.Printf("  %sChecking nightly...%s\n", dim, reset)
		updated, err := refreshNightly(downloadProgress)
		switch {
		case err != nil:
			Warnf("nightly upgrade failed: %v", err)
		case updated:
			fmt.Println()
			fmt.Printf("  %s✓%s Installed new nightly build\n", green, reset)
			restartTracking(cfg, "nightly", "nightly", CoreBinaryPath("nightly"))
		default:
			fmt.Printf("  %sNightly already up to date%s\n", dim, reset)
		}
	}
	if stableErr == nil {
		fmt.Println()
	}
	return stableErr
}

func upgradeStable() error {
	green, cyan, amber, pink, dim, reset := Palette(NoColor)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	latest, err := LatestRelease(ctx)
	if err != nil {
		return fmt.Errorf("fetch releases: %w", err)
	}

	fmt.Printf("  Latest: %s%s%s %s(%s)%s\n", green, latest.Tag, reset, dim, latest.Date.Format("Jan 02, 2006"), reset)

	destPath := CoreBinaryPath(latest.Tag)
	if _, err := os.Stat(destPath); err == nil {
		fmt.Printf("  %s%s is already installed%s\n", dim, latest.Tag, reset)
		return nil
	}

	asset := FindAsset(latest.Assets)
	if asset == nil {
		return fmt.Errorf("latest release %s has no binary for your platform (%s)", latest.Tag, CoreAssetPrefix())
	}
	expectedSHA, err := ResolveAssetSHA256(ctx, latest.Assets, asset.Name)
	if err != nil {
		return fmt.Errorf("checksum: %w", err)
	}

	fmt.Printf("  %sDownloading %s%s\n", cyan, asset.Name, reset)
	dlCtx, dlCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer dlCancel()

	if err := DownloadAsset(dlCtx, asset.URL, destPath, expectedSHA, downloadProgress); err != nil {
		fmt.Println()
		return fmt.Errorf("download: %w", err)
	}
	fmt.Println()
	fmt.Printf("  %s✓%s Checksum verified\n", green, reset)
	fmt.Printf("  %s✓%s Installed %s%s%s\n", green, reset, green, latest.Tag, reset)

	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	restarted := 0
	for _, net := range runningCores(cfg, "latest") {
		cc := cfg.Cores[net]
		fmt.Printf("  %sRestarting %s core with %s...%s\n", amber, net, latest.Tag, reset)
		if err := stopCore(net); err != nil && !errors.Is(err, errCoreNotRunning) {
			Warnf("%v", err)
		}
		refreshCheckpointsBeforeStart(net, cc)
		newPid, err := startCore(net, cc, destPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s✗%s %s%s%s restart failed: %v\n", pink, reset, NetColor(net, NoColor), net, reset, err)
			continue
		}
		fmt.Printf("  %s✓%s %s%s%s core running %s(pid %d)%s\n", green, reset, NetColor(net, NoColor), net, reset, dim, newPid, reset)
		restarted++
	}

	if restarted == 0 {
		fmt.Printf("  %sRestart running cores to use the new version%s\n", dim, reset)
	}
	return nil
}

func cmdList(args []string) error {
	if err := ExtraArgs(args, 0, "blocknet list"); err != nil {
		return err
	}
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

	inUse := versionsInUse(cfg, true)

	installed := make(map[string]bool)
	for _, r := range releases {
		if _, err := os.Stat(CoreBinaryPath(r.Tag)); err == nil {
			installed[r.Tag] = true
		}
	}
	if _, err := os.Stat(CoreBinaryPath("nightly")); err == nil {
		installed["nightly"] = true
	}

	_, _, _, _, dim, reset := Palette(NoColor)

	const dateFormat = "Jan 02, 2006"
	nightlyDate := "-"
	tagWidth := len("nightly")
	for _, r := range releases {
		if r.Tag == "nightly" {
			if !r.Date.IsZero() {
				nightlyDate = r.Date.Format(dateFormat)
			}
			continue
		}
		if !r.Prerelease && len(r.Tag) > tagWidth {
			tagWidth = len(r.Tag)
		}
	}
	dateWidth := len(dateFormat) + 2

	formatNets := func(nets []Network) string {
		var parts []string
		for _, net := range nets {
			parts = append(parts, fmt.Sprintf("%s[%s]%s", NetColor(net, NoColor), net, reset))
		}
		return strings.Join(parts, " ")
	}
	status := func(tag string) string {
		if nets, ok := inUseBy(inUse, tag); ok {
			return formatNets(nets)
		}
		if installed[tag] {
			return "installed"
		}
		return ""
	}
	printRow := func(tag, date, st string) {
		line := fmt.Sprintf("  %s  %s %s", PadRight(tag, tagWidth), PadRight(date, dateWidth), st)
		fmt.Println(strings.TrimRight(line, " "))
	}

	fmt.Printf("\n%s\n\n", SectionHead("Versions", NoColor))
	fmt.Printf("  %s%s  %s %s%s\n", dim, PadRight("Version", tagWidth), PadRight("Date", dateWidth), "Status", reset)
	fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", tagWidth+dateWidth+23), reset)

	printRow("nightly", nightlyDate, status("nightly"))

	for _, r := range releases {
		if r.Prerelease || r.Tag == "nightly" {
			continue
		}
		date := r.Date.Format(dateFormat)
		st := status(r.Tag)
		if st == "" {
			date = fmt.Sprintf("%s%s%s", dim, date, reset)
		}
		printRow(r.Tag, date, st)
	}
	fmt.Println()
	return nil
}

func cmdInstall(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: blocknet install <version>")
	}
	if err := ExtraArgs(args, 1, "blocknet install <version>"); err != nil {
		return err
	}
	version, err := normalizeVersion(args[0])
	if err != nil {
		return err
	}

	green, cyan, _, _, dim, reset := Palette(NoColor)

	fmt.Printf("\n%s\n\n", SectionHead("Install", NoColor))
	fmt.Printf("  %sFinding %s...%s\n", dim, version, reset)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if version == "latest" {
		latest, err := LatestRelease(ctx)
		if err != nil {
			return fmt.Errorf("fetch releases: %w", err)
		}
		version = latest.Tag
		if err := ValidateVersionName(version); err != nil {
			return err
		}
		fmt.Printf("  Latest is %s%s%s\n", green, version, reset)
	}

	destPath := CoreBinaryPath(version)
	if version != "nightly" {
		if _, err := os.Stat(destPath); err == nil {
			fmt.Printf("  %s%s is already installed%s\n\n", dim, version, reset)
			return nil
		}
	}

	releases, err := ListReleases(ctx)
	if err != nil {
		return fmt.Errorf("fetch releases: %w", err)
	}

	var release *Release
	for i := range releases {
		if strings.EqualFold(releases[i].Tag, version) {
			release = &releases[i]
			break
		}
	}
	if release == nil {
		return fmt.Errorf("version %s not found (run blocknet list)", version)
	}
	if err := ValidateVersionName(release.Tag); err != nil {
		return err
	}
	version = release.Tag
	destPath = CoreBinaryPath(version)
	asset := FindAsset(release.Assets)
	if asset == nil {
		return fmt.Errorf("release %s has no binary for your platform (%s). Run blocknet list to pick a newer version", version, CoreAssetPrefix())
	}
	expectedSHA, err := ResolveAssetSHA256(ctx, release.Assets, asset.Name)
	if err != nil {
		return fmt.Errorf("checksum: %w", err)
	}

	fmt.Printf("  %sDownloading %s%s\n", cyan, asset.Name, reset)
	dlCtx, dlCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer dlCancel()

	if err := DownloadAsset(dlCtx, asset.URL, destPath, expectedSHA, downloadProgress); err != nil {
		fmt.Println()
		return fmt.Errorf("download: %w", err)
	}
	if version == "nightly" {
		if err := os.WriteFile(nightlyMarker(), []byte(expectedSHA+"\n"), 0644); err != nil {
			Warnf("could not save the nightly checksum: %v", err)
		}
	}
	fmt.Println()
	fmt.Printf("  %s✓%s Checksum verified\n", green, reset)
	fmt.Printf("  %s✓%s Installed %s%s%s\n\n", green, reset, green, version, reset)
	return nil
}

func cmdUninstall(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: blocknet uninstall <version>")
	}
	if err := ExtraArgs(args, 1, "blocknet uninstall <version>"); err != nil {
		return err
	}
	version, err := normalizeVersion(args[0])
	if err != nil {
		return err
	}

	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}
	if nets, ok := inUseBy(versionsInUse(cfg, false), version); ok {
		return fmt.Errorf("%s is in use by %s. Switch to another version first with blocknet use <version> %s", version, joinNetworks(nets), nets[0])
	}

	dir := CoreDir(version)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("%s is not installed", version)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove %s: %w", dir, err)
	}

	green, _, _, _, _, reset := Palette(NoColor)
	fmt.Printf("\n%s\n\n", SectionHead("Uninstall", NoColor))
	fmt.Printf("  %s✓%s Removed %s\n\n", green, reset, version)
	return nil
}

func cmdUse(args []string) error {
	const usage = "blocknet use <version> [mainnet|testnet]"
	if len(args) == 0 {
		return fmt.Errorf("usage: %s", usage)
	}
	if err := ExtraArgs(args, 2, usage); err != nil {
		return err
	}
	version, err := normalizeVersion(args[0])
	if err != nil {
		return err
	}
	if version != "latest" {
		if _, err := os.Stat(CoreBinaryPath(version)); err != nil {
			return fmt.Errorf("%s is not installed (run blocknet install %s)", version, version)
		}
	}

	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	green, _, _, _, dim, reset := Palette(NoColor)
	var msg string
	if len(args) >= 2 {
		net, err := ParseNetwork(args[1])
		if err != nil {
			return err
		}
		ensureCoreConfig(cfg, net).Version = version
		msg = fmt.Sprintf("%s%s%s set to %s", NetColor(net, NoColor), net, reset, version)
	} else {
		set := 0
		for _, net := range []Network{Mainnet, Testnet} {
			if cc := cfg.Cores[net]; cc != nil {
				cc.Version = version
				set++
			}
		}
		if set == 0 {
			ensureCoreConfig(cfg, Mainnet).Version = version
		}
		msg = fmt.Sprintf("All cores set to %s", version)
	}

	if err := EnsureConfigDir(); err != nil {
		return err
	}
	if err := SaveConfig(ConfigFile(), cfg); err != nil {
		return err
	}

	fmt.Printf("\n%s\n\n", SectionHead("Use", NoColor))
	fmt.Printf("  %s✓%s %s\n", green, reset, msg)
	fmt.Printf("  %sRestart running cores to use it%s\n\n", dim, reset)
	return nil
}

func cmdConfig(args []string) error {
	if err := ExtraArgs(args, 0, "blocknet config"); err != nil {
		return err
	}
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("\n%s\n\n", SectionHead("Config", NoColor))
	for _, line := range strings.Split(ColorizeJSON(string(data), NoColor), "\n") {
		fmt.Printf("  %s\n", line)
	}
	fmt.Println()
	return nil
}

func cmdLogs(args []string) error {
	if err := ExtraArgs(args, 1, "blocknet logs [mainnet|testnet]"); err != nil {
		return err
	}
	var net Network
	if len(args) > 0 {
		var err error
		net, err = ParseNetwork(args[0])
		if err != nil {
			return err
		}
	} else {
		cfg, err := LoadConfig(ConfigFile())
		if err != nil {
			return err
		}
		net, _ = pickNetwork(cfg, false)
	}

	path := LogFile(net)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("no log file for %s (has it been started?)", net)
	}
	if err != nil {
		return err
	}
	defer func() { f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	offset := int64(0)
	if info.Size() > 8192 {
		offset = info.Size() - 8192
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	if offset > 0 {
		buf := make([]byte, 1)
		for {
			_, err := f.Read(buf)
			if err != nil || buf[0] == '\n' {
				break
			}
		}
	}
	if _, err := io.Copy(os.Stdout, f); err != nil {
		return err
	}

	_, _, _, _, dim, reset := Palette(NoColor)
	fmt.Printf("\n  %sFollowing %s log (ctrl+c to stop)%s\n\n", dim, net, reset)

	for {
		n, err := io.Copy(os.Stdout, f)
		if err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		time.Sleep(100 * time.Millisecond)

		// The log was truncated or replaced: start over from the top of the
		// new file instead of waiting forever past its end.
		cur, err := os.Stat(path)
		if err != nil {
			continue
		}
		pos, perr := f.Seek(0, io.SeekCurrent)
		open, serr := f.Stat()
		if perr == nil && serr == nil && cur.Size() >= pos && os.SameFile(cur, open) {
			continue
		}
		nf, err := os.Open(path)
		if err != nil {
			continue
		}
		f.Close()
		f = nf
		fmt.Printf("\n  %s%s log restarted%s\n\n", dim, net, reset)
	}
}

func cmdCleanup(args []string) error {
	if err := ExtraArgs(args, 0, "blocknet cleanup"); err != nil {
		return err
	}
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	inUse := versionsInUse(cfg, false)

	fmt.Printf("\n%s\n\n", SectionHead("Cleanup", NoColor))

	coresDir := filepath.Join(ConfigDir(), "cores")
	entries, err := os.ReadDir(coresDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("  No core versions installed\n\n")
			return nil
		}
		return err
	}

	green, _, _, _, _, reset := Palette(NoColor)
	var removed int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ver := e.Name()
		if _, ok := inUseBy(inUse, ver); ok {
			continue
		}
		dir := filepath.Join(coresDir, ver)
		if err := os.RemoveAll(dir); err != nil {
			Warnf("could not remove %s: %v", ver, err)
			continue
		}
		fmt.Printf("  %s✓%s Removed %s\n", green, reset, ver)
		removed++
	}

	if removed == 0 {
		fmt.Println("  Nothing to clean up")
	} else {
		fmt.Printf("  Cleaned up %s\n", Plural(removed, "version"))
	}
	fmt.Println()
	return nil
}
