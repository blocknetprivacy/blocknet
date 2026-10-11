package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateVersionName(t *testing.T) {
	good := []string{"v0.7.0", "v1.2.3-rc1", "nightly", "latest", "1.0"}
	for _, v := range good {
		if err := ValidateVersionName(v); err != nil {
			t.Errorf("ValidateVersionName(%q) = %v, want nil", v, err)
		}
	}
	bad := []string{"", ".", "..", "../x", "a/b", `a\b`, "/abs", ".hidden", "-flag", "v1 0", "v1\x00", "~", "a/../..", `..\..`}
	for _, v := range bad {
		if err := ValidateVersionName(v); err == nil {
			t.Errorf("ValidateVersionName(%q) = nil, want an error", v)
		}
	}
}

func TestValidVersionStaysInCoresDir(t *testing.T) {
	t.Setenv("BNT_CONFIG_DIR", t.TempDir())
	cores := filepath.Join(ConfigDir(), "cores") + string(filepath.Separator)
	for _, v := range []string{"v0.7.0", "nightly", "a..b"} {
		if ValidateVersionName(v) != nil {
			continue
		}
		if dir := CoreDir(v); !strings.HasPrefix(dir, cores) {
			t.Errorf("CoreDir(%q) = %q, escapes %q", v, dir, cores)
		}
	}
}

func TestUninstallRejectsTraversal(t *testing.T) {
	t.Setenv("BNT_CONFIG_DIR", t.TempDir())
	for _, v := range []string{"..", ".", "../..", "a/b"} {
		if err := cmdUninstall([]string{v}); err == nil || !strings.Contains(err.Error(), "invalid version") {
			t.Errorf("cmdUninstall(%q) = %v, want invalid version", v, err)
		}
	}
}

func TestValidateVersionNameCapsLength(t *testing.T) {
	err := ValidateVersionName("v" + strings.Repeat("1", 300))
	if err == nil || !strings.Contains(err.Error(), "invalid version") {
		t.Fatalf("got %v, want an invalid version error", err)
	}
	if err := ValidateVersionName("v" + strings.Repeat("1", maxVersionNameLen-1)); err != nil {
		t.Fatalf("name at the limit rejected: %v", err)
	}
}

// installFakeCore makes cores/<ver>/<binary> so the version counts as installed.
func installFakeCore(t *testing.T, ver string) {
	t.Helper()
	if err := os.MkdirAll(CoreDir(ver), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(CoreBinaryPath(ver), []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
}

func TestVersionCaseIsResolvedToInstalledFolder(t *testing.T) {
	t.Setenv("BNT_CONFIG_DIR", t.TempDir())
	installFakeCore(t, "v1.0.0")

	cfg := DefaultConfig()
	ensureCoreConfig(cfg, Mainnet).Version = "v1.0.0"
	if err := SaveConfig(ConfigFile(), cfg); err != nil {
		t.Fatal(err)
	}

	// The in-use core must not be removable by typing it in another case.
	err := cmdUninstall([]string{"V1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("uninstall V1.0.0 = %v, want an in use error", err)
	}
	if _, err := os.Stat(CoreBinaryPath("v1.0.0")); err != nil {
		t.Fatalf("v1.0.0 was removed: %v", err)
	}

	// use saves the folder's real name.
	captureStdout(t, func() {
		if err := cmdUse([]string{"V1.0.0", "mainnet"}); err != nil {
			t.Fatalf("use V1.0.0: %v", err)
		}
	})
	loaded, err := LoadConfig(ConfigFile())
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Cores[Mainnet].Version; got != "v1.0.0" {
		t.Fatalf("saved version %q, want v1.0.0", got)
	}

	// A config saved by an older build with the wrong case still protects it.
	loaded.Cores[Mainnet].Version = "V1.0.0"
	if err := SaveConfig(ConfigFile(), loaded); err != nil {
		t.Fatal(err)
	}
	if _, ok := inUseBy(versionsInUse(loaded, false), "v1.0.0"); !ok {
		t.Fatal("v1.0.0 not in use when config says V1.0.0")
	}
}

func TestUseRejectsNightlyWhenNotInstalled(t *testing.T) {
	t.Setenv("BNT_CONFIG_DIR", t.TempDir())
	err := cmdUse([]string{"nightly"})
	if err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("use nightly = %v, want not installed", err)
	}
}

func TestDisplayVersionHasOneV(t *testing.T) {
	old := Version
	defer func() { Version = old }()
	for in, want := range map[string]string{"": "dev", "v1.1.0": "v1.1.0", "1.1.0": "v1.1.0", "vv1.1.0": "v1.1.0"} {
		Version = in
		if got := displayVersion(); got != want {
			t.Errorf("displayVersion() with Version %q = %q, want %q", in, got, want)
		}
	}
}
