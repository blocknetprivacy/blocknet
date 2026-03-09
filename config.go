package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	AutoUpgrade   bool                   `json:"auto_upgrade"`
	CheckInterval string                 `json:"check_interval"`
	Cores         map[Network]*CoreConfig `json:"cores"`
}

type CoreConfig struct {
	Enabled         bool     `json:"enabled"`
	Version         string   `json:"version"`
	DataDir         string   `json:"data_dir"`
	WalletFile      string   `json:"wallet_file"`
	FullSync        bool     `json:"full_sync"`
	SaveCheckpoints bool     `json:"save_checkpoints"`
	Listen          string   `json:"listen"`
	Seed            bool     `json:"seed"`
	APIAddr         string   `json:"api_addr"`
	ExplorerAddr    string   `json:"explorer_addr"`
	P2PMaxInbound   int      `json:"p2p_max_inbound"`
	P2PMaxOutbound  int      `json:"p2p_max_outbound"`
	P2PWhitelistPeers []string `json:"p2p_whitelist_peers"`
	P2PWhitelistFile  string   `json:"p2p_whitelist_file"`
}

func DefaultConfig() *Config {
	return &Config{
		AutoUpgrade:   true,
		CheckInterval: "24h",
		Cores: map[Network]*CoreConfig{
			Mainnet: {
				Enabled: true,
				Version: "latest",
				APIAddr: "127.0.0.1:8332",
			},
			Testnet: {
				Enabled: false,
				Version: "latest",
				APIAddr: "127.0.0.1:18332",
			},
		},
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	stripped := StripJSONComments(data)

	cfg := DefaultConfig()
	if err := json.Unmarshal(stripped, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}

func SaveConfig(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0644)
}

func (cfg *Config) CheckIntervalDuration() time.Duration {
	d, err := time.ParseDuration(cfg.CheckInterval)
	if err != nil {
		return 24 * time.Hour
	}
	return d
}

// ResolveDataDir returns the configured data directory or the platform default.
func (cc *CoreConfig) ResolveDataDir(net Network) string {
	if cc.DataDir != "" {
		return cc.DataDir
	}
	return DataDir(net)
}

// BuildFlags translates a CoreConfig into command-line flags for the core binary.
func (cc *CoreConfig) BuildFlags(net Network) []string {
	var flags []string

	if net == Testnet {
		flags = append(flags, "--testnet")
	}

	if cc.APIAddr != "" {
		flags = append(flags, "--api", cc.APIAddr)
	}

	flags = append(flags, "--data", cc.ResolveDataDir(net))

	if cc.WalletFile != "" {
		flags = append(flags, "--wallet", cc.WalletFile)
	}

	if cc.Listen != "" {
		flags = append(flags, "--listen", cc.Listen)
	}

	if cc.Seed {
		flags = append(flags, "--seed")
	}

	if cc.ExplorerAddr != "" {
		flags = append(flags, "--explorer", cc.ExplorerAddr)
	}

	if cc.FullSync {
		flags = append(flags, "--full-sync")
	}

	if cc.SaveCheckpoints {
		flags = append(flags, "--save-checkpoints")
	}

	if cc.P2PMaxInbound > 0 {
		flags = append(flags, "--p2p-max-inbound", strconv.Itoa(cc.P2PMaxInbound))
	}

	if cc.P2PMaxOutbound > 0 {
		flags = append(flags, "--p2p-max-outbound", strconv.Itoa(cc.P2PMaxOutbound))
	}

	for _, peer := range cc.P2PWhitelistPeers {
		flags = append(flags, "--p2p-whitelist-peer", peer)
	}

	if cc.P2PWhitelistFile != "" {
		flags = append(flags, "--p2p-whitelist", cc.P2PWhitelistFile)
	}

	flags = append(flags, "--no-version-check")

	return flags
}

// StripJSONComments removes // and # line comments from JSON source. It
// respects string literals so URLs containing // are preserved. The result
// is valid JSON suitable for encoding/json.Unmarshal.
func StripJSONComments(src []byte) []byte {
	out := make([]byte, 0, len(src))
	i := 0
	for i < len(src) {
		ch := src[i]

		// Inside a JSON string — copy verbatim until closing quote.
		if ch == '"' {
			out = append(out, ch)
			i++
			for i < len(src) {
				c := src[i]
				out = append(out, c)
				i++
				if c == '\\' && i < len(src) {
					out = append(out, src[i])
					i++
				} else if c == '"' {
					break
				}
			}
			continue
		}

		// // line comment — skip to end of line.
		if ch == '/' && i+1 < len(src) && src[i+1] == '/' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}

		// # line comment — skip to end of line.
		if ch == '#' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}

		out = append(out, ch)
		i++
	}
	return out
}
