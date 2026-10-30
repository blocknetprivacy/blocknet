package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	priorityUsage      = "priority [normal|fast|urgent|custom <extra>]"
	feePriorityVersion = "0.24.0"
	crazyFeeMultiple   = 100
)

var feeLevels = []struct {
	name  string
	extra uint64
}{{"normal", 0}, {"fast", 10}, {"urgent", 40}}

func levelExtra(name string) (uint64, bool) {
	for _, l := range feeLevels {
		if l.name == name {
			return l.extra, true
		}
	}
	return 0, false
}

func feeLevelsText() string {
	parts := make([]string, 0, len(feeLevels)+1)
	for _, l := range feeLevels {
		parts = append(parts, fmt.Sprintf("%s +%d", l.name, l.extra))
	}
	return strings.Join(append(parts, "custom (your own extra)"), " · ")
}

type feeChoice struct {
	name  string
	extra uint64
	base  uint64
}

func (c feeChoice) rate() uint64 { return c.base + c.extra }

func (c feeChoice) needsYes() bool { return c.name == "urgent" || c.name == "custom" }

func (c feeChoice) crazy() bool {
	return c.name == "custom" && c.base > 0 && c.rate()/crazyFeeMultiple >= c.base
}

func (c feeChoice) label() string {
	if c.base == 0 {
		return c.name
	}
	return fmt.Sprintf("%s, %d per byte", c.name, c.rate())
}

func (c feeChoice) multiple() string {
	return strings.TrimSuffix(strconv.FormatFloat(float64(c.rate())/float64(c.base), 'f', 1, 64), ".0") + "x"
}

func coreSupportsFeePriority(net Network) bool {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil || cfg.Cores[net] == nil {
		return false
	}
	v := cfg.Cores[net].Version
	if strings.EqualFold(v, "nightly") {
		return true
	}
	if strings.EqualFold(v, "latest") {
		if v, err = ResolveInstalledVersion(v); err != nil {
			return false
		}
	}
	if _, ok := ParseVersion(v); !ok {
		return false
	}
	return CompareVersions(v, feePriorityVersion) >= 0
}

func (s *AttachSession) baseFeePerByte(ctx context.Context) (uint64, bool) {
	if !coreSupportsFeePriority(s.network) {
		return 0, false
	}
	raw, err := s.client.Get(ctx, "/api/mempool")
	if err != nil {
		return 0, false
	}
	var st struct {
		Base uint64 `json:"base_fee_per_byte"`
	}
	if json.Unmarshal(raw, &st) != nil || st.Base == 0 {
		return 0, false
	}
	return st.Base, true
}

func parseFeeLevel(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "", false
	}
	for _, l := range feeLevels {
		if strings.HasPrefix(l.name, name) {
			return l.name, true
		}
	}
	if strings.HasPrefix("custom", name) {
		return "custom", true
	}
	return "", false
}

func parseExtraFee(s string) (uint64, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("extra per byte must be a whole number, 0 or more")
	}
	return n, nil
}

func defaultFeeChoice() feeChoice {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return feeChoice{name: "normal"}
	}
	if cfg.FeePriority == "custom" {
		return feeChoice{name: "custom", extra: cfg.FeeExtraPerByte}
	}
	if extra, ok := levelExtra(cfg.FeePriority); ok {
		return feeChoice{name: cfg.FeePriority, extra: extra}
	}
	return feeChoice{name: "normal"}
}

func (s *AttachSession) cmdPriority(args []string) error {
	if len(args) == 0 {
		c := defaultFeeChoice()
		fmt.Printf("\n%s\n\n", SectionHead("Fee priority", s.noColor))
		if base, ok := s.baseFeePerByte(context.Background()); ok {
			c.base = base
			fmt.Printf("  Default:  %s (%d per byte)\n", c.name, c.rate())
		} else {
			fmt.Printf("  Default:  %s\n", c.name)
		}
		fmt.Printf("  Levels:   %s\n", feeLevelsText())
		fmt.Println("  Change:   priority fast")
		return nil
	}

	name, ok := parseFeeLevel(args[0])
	if !ok {
		return fmt.Errorf("usage: %s", priorityUsage)
	}
	c := feeChoice{name: name}
	if name == "custom" {
		if len(args) < 2 {
			return fmt.Errorf("usage: priority custom <extra per byte>")
		}
		extra, err := parseExtraFee(args[1])
		if err != nil {
			return err
		}
		c.extra = extra
	} else if len(args) > 1 {
		return fmt.Errorf("usage: %s", priorityUsage)
	} else {
		c.extra, _ = levelExtra(name)
	}

	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg.FeePriority = c.name
	cfg.FeeExtraPerByte = 0
	if c.name == "custom" {
		cfg.FeeExtraPerByte = c.extra
	}
	if err := EnsureConfigDir(); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := SaveConfig(ConfigFile(), cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	fmt.Printf("  Default fee priority is now %s (+%d per byte).\n", c.name, c.extra)
	return nil
}

func (s *AttachSession) askFeePriority(ctx context.Context) (feeChoice, error) {
	base, ok := s.baseFeePerByte(ctx)
	if !ok {
		fmt.Println("  This core does not support fee priority, so the normal fee is used.")
		return feeChoice{name: "normal"}, nil
	}
	def := defaultFeeChoice()
	def.base = base
	var name string
	for {
		fmt.Printf("  Priority [normal/fast/urgent/custom] (Enter = %s): ", def.name)
		line, readErr := s.reader.ReadString('\n')
		if strings.TrimSpace(line) == "" {
			return def, nil
		}
		var ok bool
		if name, ok = parseFeeLevel(line); ok {
			break
		}
		if readErr != nil {
			return feeChoice{}, fmt.Errorf("priority must be normal, fast, urgent or custom")
		}
		fmt.Println("  Type normal, fast, urgent or custom.")
	}
	if name != "custom" {
		extra, _ := levelExtra(name)
		return feeChoice{name: name, extra: extra, base: base}, nil
	}
	for {
		fmt.Printf("  Extra per byte, on top of the base %d: ", base)
		line, readErr := s.reader.ReadString('\n')
		extra, err := parseExtraFee(line)
		if err == nil {
			return feeChoice{name: "custom", extra: extra, base: base}, nil
		}
		if readErr != nil {
			return feeChoice{}, err
		}
		fmt.Println("  Type a whole number, 0 or more.")
	}
}

func (s *AttachSession) printFeeWarning(c feeChoice, total uint64) {
	_, _, amber, pink, _, reset := Palette(s.noColor)
	switch c.name {
	case "normal":
		return
	case "fast":
		fmt.Printf("  %s! You pay %s the normal fee to jump ahead of normal sends.%s\n", amber, c.multiple(), reset)
		return
	case "urgent":
		fmt.Printf("  %s! You pay %s the normal fee. Only use this if it must confirm now.%s\n", pink, c.multiple(), reset)
	default:
		fmt.Printf("  %s! Custom fees are easy to get wrong. This is %s the normal fee.%s\n", pink, c.multiple(), reset)
		if c.crazy() {
			fmt.Printf("  %s! THIS FEE IS CRAZY. Nobody needs %s the normal fee to get into a block.%s\n", pink, c.multiple(), reset)
		}
	}
	fmt.Printf("  %s! Total spend: %s%s\n", pink, FormatAmount(total), reset)
}

func (s *AttachSession) confirmFee(c feeChoice, fee uint64) bool {
	if c.needsYes() {
		fmt.Printf("  Type yes to pay %s in fees: ", FormatAmount(fee))
		line, _ := s.reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(line)) != "yes" {
			return false
		}
		if !c.crazy() {
			return true
		}
		fmt.Printf("  This is crazy. Type yes again to really pay %s in fees: ", FormatAmount(fee))
		line, _ = s.reader.ReadString('\n')
		return strings.ToLower(strings.TrimSpace(line)) == "yes"
	}
	fmt.Print("  Confirm [y/N]: ")
	line, _ := s.reader.ReadString('\n')
	return strings.ToLower(strings.TrimSpace(line)) == "y"
}

func (s *AttachSession) cmdBump(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: bump <txid>")
	}
	txid := strings.ToLower(strings.TrimSpace(args[0]))
	if raw, err := hex.DecodeString(txid); err != nil || len(raw) != 32 {
		return fmt.Errorf("txid must be 64 hex characters")
	}
	ctx := context.Background()
	if _, ok := s.baseFeePerByte(ctx); !ok {
		return fmt.Errorf("this core cannot speed up sends. Update it to v%s or newer", feePriorityVersion)
	}
	fee, err := s.askFeePriority(ctx)
	if err != nil {
		return err
	}

	req := map[string]any{"txid": txid, "extra_fee_per_byte": fee.extra, "dry_run": true}
	raw, err := s.client.Post(ctx, "/api/wallet/send/bump", req)
	if err != nil {
		return s.handleAPIError(err)
	}
	var preview struct {
		Fee        uint64 `json:"fee"`
		FeePerByte uint64 `json:"fee_per_byte"`
		OldFee     uint64 `json:"old_fee"`
		BumpCost   uint64 `json:"bump_cost"`
	}
	if err := json.Unmarshal(raw, &preview); err != nil {
		return fmt.Errorf("parse bump preview: %w", err)
	}
	raised := preview.FeePerByte > fee.rate()
	if raised {
		fee.extra = preview.FeePerByte - fee.base
	}

	fmt.Printf("\n%s\n\n", SectionHead("Speed up", s.noColor))
	fmt.Printf("  Send:     %s\n", txid)
	fmt.Printf("  Old fee:  %s\n", FormatAmount(preview.OldFee))
	fmt.Printf("  New fee:  %s (%d per byte)\n", FormatAmount(preview.Fee), preview.FeePerByte)
	fmt.Printf("  Costs:    %s more\n", FormatAmount(preview.BumpCost))
	if raised {
		fmt.Printf("  The rate was raised to %d per byte, the lowest rate a bump of this send can use.\n", preview.FeePerByte)
	}
	s.printFeeWarning(fee, preview.Fee)
	if !s.confirmFee(fee, preview.Fee) {
		fmt.Println("  Cancelled")
		return nil
	}

	req["dry_run"] = false
	raw, err = s.client.Post(ctx, "/api/wallet/send/bump", req)
	if err != nil {
		return s.handleAPIError(err)
	}
	var result struct {
		TxID string `json:"txid"`
	}
	json.Unmarshal(raw, &result)
	fmt.Printf("  Sped up:  %s\n", result.TxID)
	fmt.Printf("  Explorer: https://explorer.blocknetcrypto.com/tx/%s\n", result.TxID)
	return nil
}
