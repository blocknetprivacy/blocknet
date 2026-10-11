package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const selfReleasesURL = "https://api.github.com/repos/blocknetprivacy/blocknet/releases"

func selfAssetName() string {
	return strings.Replace(CoreAssetPrefix(), "blocknet-core-", "blocknet-", 1) + ".zip"
}

func selfUpgrade() (string, error) {
	if _, ok := ParseVersion(Version); !ok || !IsPinned(Version) {
		return "", nil
	}

	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	old := exe + ".old"
	os.Remove(old)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	releases, err := listReleasesFrom(ctx, selfReleasesURL)
	if err != nil {
		return "", err
	}
	var latest *Release
	for i := range releases {
		if !releases[i].Prerelease {
			latest = &releases[i]
			break
		}
	}
	if latest == nil || CompareVersions(latest.Tag, Version) <= 0 {
		return "", nil
	}

	var asset *Asset
	for i, a := range latest.Assets {
		if a.Name == selfAssetName() {
			asset = &latest.Assets[i]
			break
		}
	}
	if asset == nil {
		return "", fmt.Errorf("release %s has no %s", latest.Tag, selfAssetName())
	}
	sum, err := ResolveAssetSHA256(ctx, latest.Assets, asset.Name)
	if err != nil {
		return "", err
	}

	dlCtx, dlCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer dlCancel()

	tmp := exe + ".new"
	if err := downloadAssetAs(dlCtx, asset.URL, tmp, sum, "blocknet", nil); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(exe, old); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Rename(old, exe)
		os.Remove(tmp)
		return "", err
	}
	if runtime.GOOS != "windows" {
		os.Remove(old)
	}
	return latest.Tag, nil
}
