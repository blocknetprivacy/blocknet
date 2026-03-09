package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveInstalledVersion maps a version string from config to an actual
// installed version directory name.
//   - "latest" → highest semver tag found in the cores directory
//   - "nightly" → "nightly" (must be installed)
//   - "v0.7.0" → "v0.7.0" (must be installed)
func ResolveInstalledVersion(version string) (string, error) {
	switch strings.ToLower(version) {
	case "latest":
		coresDir := filepath.Join(ConfigDir(), "cores")
		entries, err := os.ReadDir(coresDir)
		if err != nil {
			return "", fmt.Errorf("no cores installed (run 'blocknet install <version>')")
		}
		var best string
		for _, e := range entries {
			if !e.IsDir() || e.Name() == "nightly" {
				continue
			}
			if _, err := os.Stat(CoreBinaryPath(e.Name())); err != nil {
				continue
			}
			if best == "" || CompareVersions(e.Name(), best) > 0 {
				best = e.Name()
			}
		}
		if best == "" {
			return "", fmt.Errorf("no core versions installed (run 'blocknet install <version>')")
		}
		return best, nil

	case "nightly":
		if _, err := os.Stat(CoreBinaryPath("nightly")); err != nil {
			return "", fmt.Errorf("nightly not installed (run 'blocknet install nightly')")
		}
		return "nightly", nil

	default:
		if _, err := os.Stat(CoreBinaryPath(version)); err != nil {
			return "", fmt.Errorf("version %s not installed (run 'blocknet install %s')", version, version)
		}
		return version, nil
	}
}
