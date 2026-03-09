package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func ConfigDir() string {
	if dir := os.Getenv("BNT_CONFIG_DIR"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "bnt")
}

func ConfigFile() string {
	return filepath.Join(ConfigDir(), "config.json")
}

func CoreDir(version string) string {
	return filepath.Join(ConfigDir(), "cores", version)
}

func CoreBinaryPath(version string) string {
	return filepath.Join(CoreDir(version), BinaryName())
}

func LogFile(net Network) string {
	return filepath.Join(ConfigDir(), fmt.Sprintf("%s.log", net))
}

func CorePidFile(net Network) string {
	return filepath.Join(ConfigDir(), fmt.Sprintf("core.%s.pid", net))
}

func DataDir(net Network) string {
	return filepath.Join(ConfigDir(), "data", string(net))
}

func WalletsDir() string {
	return filepath.Join(ConfigDir(), "wallets")
}

func CookiePath(dataDir string) string {
	return filepath.Join(dataDir, "api.cookie")
}

// BinaryName returns the core binary filename for the current platform.
// Core binaries are named blocknet-core-<arch>-<os>.
func BinaryName() string {
	arch := runtime.GOARCH
	osName := runtime.GOOS

	switch arch {
	case "arm64":
		// keep as-is
	case "amd64":
		// keep as-is
	default:
		arch = runtime.GOARCH
	}

	switch osName {
	case "darwin":
		osName = "macos"
	case "windows":
		osName = "windows"
	case "linux":
		osName = "linux"
	}

	name := fmt.Sprintf("blocknet-core-%s-%s", arch, osName)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func EnsureConfigDir() error {
	for _, dir := range []string{ConfigDir(), WalletsDir()} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return nil
}
