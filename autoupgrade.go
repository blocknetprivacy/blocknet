package main

import (
	"context"
	"fmt"
	"os"
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

func maybeAutoUpgrade(cfg *Config) {
	interval := cfg.CheckIntervalDuration()
	last := readLastCheck()
	if time.Since(last) < interval {
		return
	}

	writeLastCheck()

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
		fmt.Fprintf(os.Stderr, "  warning: auto-upgrade checksum unavailable: %v\n", err)
		return
	}

	fmt.Printf("  New core version available: %s\n", latest.Tag)
	fmt.Printf("  Downloading %s...\n", asset.Name)

	dlCtx, dlCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer dlCancel()

	if err := DownloadAsset(dlCtx, asset.URL, destPath, expectedSHA, nil); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: auto-upgrade download failed: %v\n", err)
		return
	}

	fmt.Printf("  \033[38;2;170;255;0m✓ verified\033[0m\n")
	fmt.Printf("  Installed %s\n", latest.Tag)

	for _, net := range []Network{Mainnet, Testnet} {
		cc := cfg.Cores[net]
		if cc == nil || IsPinned(cc.Version) {
			continue
		}
		pid, pidErr := readCorePidFile(net)
		if pidErr != nil || !processAlive(pid) {
			continue
		}
		fmt.Printf("  Restarting %s core with %s...\n", net, latest.Tag)
		stopCore(net)
		newPid, err := startCore(net, cc, destPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: %s restart failed: %v\n", net, err)
			continue
		}
		writeCorePidFile(net, newPid)
		fmt.Printf("  %s core restarted (pid %d)\n", net, newPid)
	}
}
