package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

var versionNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// maxVersionNameLen keeps version folder names well under filesystem limits.
const maxVersionNameLen = 64

// ValidateVersionName rejects version names that are not a plain folder
// name, such as "", ".", "..", anything with a path separator, or anything
// longer than maxVersionNameLen. Every
// version taken from the user goes through it before it reaches CoreDir.
func ValidateVersionName(version string) error {
	if len(version) > maxVersionNameLen {
		return fmt.Errorf("invalid version: longer than %d characters", maxVersionNameLen)
	}
	if version == "" || version == "." || version == ".." ||
		!versionNameRe.MatchString(version) || filepath.Base(version) != version {
		return fmt.Errorf("invalid version %q: use a tag like v0.7.0, latest or nightly", version)
	}
	return nil
}

// CoreDir is the folder for one installed core version. Validate user input
// with ValidateVersionName first.
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

func WatchdogPidFile() string {
	return filepath.Join(ConfigDir(), "watchdog.pid")
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

// CoreAssetPrefix returns the platform-specific stem used to match release
// asset filenames (e.g. "blocknet-core-amd64-windows"). It intentionally
// omits any file extension so it can prefix-match against .zip asset names.
func CoreAssetPrefix() string {
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

	return fmt.Sprintf("blocknet-core-%s-%s", arch, osName)
}

// BinaryName returns the core binary filename for the current platform.
func BinaryName() string {
	name := CoreAssetPrefix()
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
