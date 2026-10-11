package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const settingsAPIVersion = "0.21.0"

func coreUsesSettingsAPI(binPath string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, "--version").Output()
	if err != nil {
		return false
	}
	v := strings.TrimSpace(string(out))
	if _, ok := ParseVersion(v); !ok {
		return false
	}
	return CompareVersions(v, settingsAPIVersion) >= 0
}

func (cc *CoreConfig) BaseFlags(net Network) []string {
	var flags []string
	if net == Testnet {
		flags = append(flags, "--testnet")
	}
	if cc.APIAddr != "" {
		flags = append(flags, "--api", cc.APIAddr)
	}
	return append(flags, "--data", cc.ResolveDataDir(net))
}

func (cc *CoreConfig) DesiredSettings(net Network) (map[string]any, error) {
	orNull := func(set bool, v any) any {
		if set {
			return v
		}
		return nil
	}
	whitelist, err := cc.whitelistIDs(net)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"listen":           orNull(cc.Listen != "", cc.Listen),
		"seed":             orNull(cc.Seed, true),
		"full_sync":        orNull(cc.FullSync, true),
		"save_checkpoints": orNull(cc.SaveCheckpoints, true),
		"explorer_addr":    orNull(cc.ExplorerAddr != "", cc.ExplorerAddr),
		"wallet_file":      cc.EffectiveWalletFile(net),
		"p2p_max_inbound":  orNull(cc.P2PMaxInbound > 0, cc.P2PMaxInbound),
		"p2p_max_outbound": orNull(cc.P2PMaxOutbound > 0, cc.P2PMaxOutbound),
		"p2p_whitelist":    orNull(len(whitelist) > 0, whitelist),
	}, nil
}

func (cc *CoreConfig) whitelistIDs(net Network) ([]string, error) {
	ids := append([]string{}, cc.P2PWhitelistPeers...)
	file := cc.P2PWhitelistFile
	if file == "" {
		if dir, err := os.UserConfigDir(); err == nil {
			file = filepath.Join(dir, "blocknet", string(net), "whitelist.json")
			if _, err := os.Stat(file); err != nil {
				return ids, nil
			}
		}
	}
	if file == "" {
		return ids, nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("could not read whitelist file %s: %w", file, err)
	}
	var fromFile []string
	if err := json.Unmarshal(data, &fromFile); err != nil {
		return nil, fmt.Errorf("invalid whitelist file %s: expected a JSON array of peer ID strings: %w", file, err)
	}
	for _, id := range fromFile {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func applyCoreSettings(net Network, cc *CoreConfig, cookiePath string) (bool, error) {
	desired, err := cc.DesiredSettings(net)
	if err != nil {
		return false, err
	}
	client, err := NewCoreClient(cc.APIAddr, cookiePath)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw, err := client.Patch(ctx, "/api/settings", desired)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 400 {
			return false, fmt.Errorf("core rejected settings from config.json: %s", apiErr.Message)
		}
		return false, fmt.Errorf("could not apply settings: %w", err)
	}
	var resp struct {
		RestartRequired []string `json:"restart_required"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, fmt.Errorf("could not apply settings: %w", err)
	}
	return len(resp.RestartRequired) > 0, nil
}
