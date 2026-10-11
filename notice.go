package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const builtinUpgradeNotice = "Blocknet plans a network upgrade around 2027-02-16. After it, you will have 1 year to move your coins to the new format, until about 2028-02-16. Coins not moved by then cannot be spent. The wallet will guide you."

func upgradeNoticeFrom(statusRaw json.RawMessage) string {
	var st struct {
		NetworkUpgrade *struct {
			Notice string `json:"notice"`
		} `json:"network_upgrade"`
	}
	if json.Unmarshal(statusRaw, &st) == nil && st.NetworkUpgrade != nil {
		if n := strings.TrimSpace(st.NetworkUpgrade.Notice); n != "" {
			return n
		}
	}
	return builtinUpgradeNotice
}

func runningCoreNotice(cfg *Config) string {
	for _, net := range []Network{Mainnet, Testnet} {
		cc := cfg.Cores[net]
		if cc == nil || cc.APIAddr == "" {
			continue
		}
		if pid, err := readCorePidFile(net); err != nil || !processAlive(pid) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		raw, err := NewCoreClientDirect(cc.APIAddr, "").Status(ctx)
		cancel()
		if err == nil {
			return upgradeNoticeFrom(raw)
		}
	}
	return builtinUpgradeNotice
}

func printUpgradeNotice(text string, noColor bool) {
	amber, reset := "\033[38;2;255;170;0m", "\033[0m"
	if noColor {
		amber, reset = "", ""
	}
	fmt.Println()
	for i, line := range wrapWords(text, 72) {
		if i == 0 {
			fmt.Printf("  %s%s%s\n", amber, line, reset)
		} else {
			fmt.Printf("  %s\n", line)
		}
	}
}

func wrapWords(text string, width int) []string {
	var lines []string
	line := ""
	for _, w := range strings.Fields(text) {
		if line != "" && len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
