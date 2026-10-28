package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func lastCheckFile() string {
	return filepath.Join(ConfigDir(), ".last_upgrade_check")
}

func readLastCheck() time.Time {
	data, err := os.ReadFile(lastCheckFile())
	if err != nil {
		return time.Time{}
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}

func writeLastCheck() {
	os.MkdirAll(filepath.Dir(lastCheckFile()), 0755)
	os.WriteFile(lastCheckFile(), []byte(strconv.FormatInt(time.Now().Unix(), 10)+"\n"), 0644)
}

func spawnAutoUpgrade(cfg *Config) {
	if time.Since(readLastCheck()) < cfg.CheckIntervalDuration() {
		return
	}
	writeLastCheck()

	self, err := os.Executable()
	if err != nil {
		return
	}
	logFile, err := os.OpenFile(filepath.Join(ConfigDir(), "upgrade.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer logFile.Close()

	cmd := exec.Command(self, "upgrade", "--nocolor")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	detachProcess(cmd)
	if cmd.Start() == nil {
		cmd.Process.Release()
	}
}

func maybeAutoUpgrade(cfg *Config) {
	interval := cfg.CheckIntervalDuration()
	last := readLastCheck()
	if time.Since(last) < interval {
		return
	}

	writeLastCheck()

	if tag, err := selfUpgrade(); err != nil {
		Warnf("could not upgrade blocknet: %v", err)
	} else if tag != "" {
		fmt.Printf("  Upgraded blocknet to %s\n", tag)
	}

	autoUpgradeStable(cfg)
	if usesNightly(cfg) {
		autoUpgradeNightly(cfg)
	}
}

func autoUpgradeStable(cfg *Config) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	latest, err := LatestRelease(ctx)
	if err != nil {
		return
	}

	destPath := CoreBinaryPath(latest.Tag)
	if _, err := os.Stat(destPath); err == nil {
		return
	}

	asset := FindAsset(latest.Assets)
	if asset == nil {
		return
	}
	expectedSHA, err := ResolveAssetSHA256(ctx, latest.Assets, asset.Name)
	if err != nil {
		Warnf("could not get the checksum for %s: %v", latest.Tag, err)
		return
	}

	fmt.Printf("  New core version available: %s\n", latest.Tag)
	fmt.Printf("  Downloading %s\n", asset.Name)

	dlCtx, dlCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer dlCancel()

	if err := DownloadAsset(dlCtx, asset.URL, destPath, expectedSHA, nil); err != nil {
		Warnf("could not download %s: %v", latest.Tag, err)
		return
	}

	green, _, _, _, _, reset := Palette(NoColor)
	fmt.Printf("  %s✓%s Verified and installed %s\n", green, reset, latest.Tag)

	restartTracking(cfg, "latest", latest.Tag, destPath)
}

func autoUpgradeNightly(cfg *Config) {
	updated, err := refreshNightly(nil)
	if err != nil {
		Warnf("could not upgrade nightly: %v", err)
		return
	}
	if !updated {
		return
	}
	fmt.Println("  Installed a new nightly build")
	restartTracking(cfg, "nightly", "nightly", CoreBinaryPath("nightly"))
}

func restartTracking(cfg *Config, track, label, binPath string) int {
	green, _, _, _, dim, reset := Palette(NoColor)
	restarted := 0
	for _, net := range runningCores(cfg, track) {
		nc := NetColor(net, NoColor)
		fmt.Printf("  Restarting %s%s%s core with %s...\n", nc, net, reset, label)
		stopCore(net)
		refreshCheckpointsBeforeStart(net, cfg.Cores[net])
		newPid, err := startCore(net, cfg.Cores[net], binPath)
		if err != nil {
			Warnf("could not restart %s: %v", net, err)
			continue
		}
		fmt.Printf("  %s✓%s Restarted %s%s%s core %s(pid %d)%s\n", green, reset, nc, net, reset, dim, newPid, reset)
		restarted++
	}
	return restarted
}

func tracksVersion(cc *CoreConfig, track string) bool {
	return cc != nil && strings.EqualFold(cc.Version, track)
}

func usesNightly(cfg *Config) bool {
	return tracksVersion(cfg.Cores[Mainnet], "nightly") || tracksVersion(cfg.Cores[Testnet], "nightly")
}

func runningCores(cfg *Config, track string) []Network {
	var nets []Network
	for _, net := range []Network{Mainnet, Testnet} {
		if !tracksVersion(cfg.Cores[net], track) {
			continue
		}
		if pid, err := readCorePidFile(net); err == nil && processAlive(pid) {
			nets = append(nets, net)
		}
	}
	return nets
}

func nightlyMarker() string {
	return filepath.Join(CoreDir("nightly"), ".sha256")
}

func refreshNightly(onProgress func(downloaded, total int64)) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	releases, err := ListReleases(ctx)
	if err != nil {
		return false, err
	}
	var rel *Release
	for i := range releases {
		if releases[i].Tag == "nightly" {
			rel = &releases[i]
			break
		}
	}
	if rel == nil {
		return false, fmt.Errorf("no nightly release published")
	}
	asset := FindAsset(rel.Assets)
	if asset == nil {
		return false, fmt.Errorf("nightly has no binary for %s", CoreAssetPrefix())
	}
	sum, err := ResolveAssetSHA256(ctx, rel.Assets, asset.Name)
	if err != nil {
		return false, err
	}

	destPath := CoreBinaryPath("nightly")
	if old, err := os.ReadFile(nightlyMarker()); err == nil && strings.EqualFold(strings.TrimSpace(string(old)), sum) {
		if _, err := os.Stat(destPath); err == nil {
			return false, nil
		}
	}

	dlCtx, dlCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer dlCancel()
	if err := DownloadAsset(dlCtx, asset.URL, destPath, sum, onProgress); err != nil {
		return false, err
	}
	if err := os.WriteFile(nightlyMarker(), []byte(sum+"\n"), 0644); err != nil {
		return false, err
	}
	return true, nil
}
