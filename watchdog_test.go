package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestWatchdogStateUpdates(t *testing.T) {
	t.Setenv("BNT_CONFIG_DIR", t.TempDir())
	t.Setenv("BNT_WATCHDOG", "")
	if err := EnsureConfigDir(); err != nil {
		t.Fatal(err)
	}
	// This test process stands in for a live watchdog.
	if err := writeWatchdogState(os.Getpid(), []Network{Mainnet, Testnet}); err != nil {
		t.Fatal(err)
	}

	unwatchNetwork(Testnet)
	if _, nets, _ := readWatchdogState(); !slices.Equal(nets, []Network{Mainnet}) {
		t.Fatalf("after unwatch testnet: %v", nets)
	}
	watchNetwork(Testnet)
	if _, nets, _ := readWatchdogState(); !slices.Equal(nets, []Network{Mainnet, Testnet}) {
		t.Fatalf("after watch testnet: %v", nets)
	}
	if err := dropFromWatchdog(Mainnet); err != nil {
		t.Fatal(err)
	}
	if _, nets, _ := readWatchdogState(); !slices.Equal(nets, []Network{Testnet}) {
		t.Fatalf("after drop mainnet: %v", nets)
	}

	// No temp or lock files are left behind.
	left, _ := filepath.Glob(filepath.Join(ConfigDir(), "*watchdog*"))
	if len(left) != 1 || left[0] != WatchdogPidFile() {
		t.Fatalf("files left: %v", left)
	}
}
