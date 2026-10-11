package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDesiredSettingsResetsUnsetFieldsWithNull(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	got, err := (&CoreConfig{}).DesiredSettings(Mainnet)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"listen", "seed", "full_sync", "save_checkpoints", "explorer_addr", "wallet_file", "p2p_max_inbound", "p2p_max_outbound", "p2p_whitelist"} {
		v, ok := got[k]
		if !ok || v != nil {
			t.Errorf("%s = %v (present %v), want null", k, v, ok)
		}
	}
	if len(got) != 9 {
		t.Errorf("sent %d fields, want 9: %v", len(got), got)
	}
}

func TestDesiredSettingsSendsConfiguredValues(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "wl.json")
	os.WriteFile(file, []byte(`["12D3KooWFile"]`), 0644)
	cc := &CoreConfig{
		Listen:            "/ip4/0.0.0.0/tcp/1234",
		Seed:              true,
		WalletFile:        "/w.dat",
		P2PMaxInbound:     5,
		P2PWhitelistPeers: []string{"12D3KooWFlag"},
		P2PWhitelistFile:  file,
	}
	got, err := cc.DesiredSettings(Mainnet)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"listen":           "/ip4/0.0.0.0/tcp/1234",
		"seed":             true,
		"full_sync":        nil,
		"save_checkpoints": nil,
		"explorer_addr":    nil,
		"wallet_file":      "/w.dat",
		"p2p_max_inbound":  5,
		"p2p_max_outbound": nil,
		"p2p_whitelist":    []string{"12D3KooWFlag", "12D3KooWFile"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}
