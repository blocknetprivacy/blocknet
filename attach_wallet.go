package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (s *AttachSession) cmdLoad() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.client.Get(ctx, "/api/wallet/balance")
	if err == nil {
		fmt.Printf("\n%s\n", SectionHead("Wallet", s.noColor))
		fmt.Println("  A wallet is already loaded.")
		return nil
	}
	if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == 409 {
		fmt.Printf("\n%s\n", SectionHead("Wallet", s.noColor))
		fmt.Println("  A wallet is already loaded.")
		return nil
	}

	home, _ := os.UserHomeDir()
	searchDirs := []string{
		WalletsDir(),
		filepath.Join(home, ".config", "blocknet", string(s.network)),
		home,
	}

	cfg, cfgErr := LoadConfig(ConfigFile())
	if cfgErr == nil {
		if cc := cfg.Cores[s.network]; cc != nil {
			dataDir := cc.ResolveDataDir(s.network)
			abs, _ := filepath.Abs(dataDir)
			searchDirs = append(searchDirs, abs)
		}
	}

	cwd, _ := os.Getwd()
	if cwd != "" && cwd != home {
		searchDirs = append(searchDirs, cwd)
	}

	seen := make(map[string]bool)
	var wallets []string
	for _, dir := range searchDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.wallet.dat"))
		for _, m := range matches {
			abs, _ := filepath.Abs(m)
			if !seen[abs] {
				seen[abs] = true
				wallets = append(wallets, abs)
			}
		}
	}

	fmt.Printf("\n%s\n", SectionHead("Load Wallet", s.noColor))

	if len(wallets) > 0 {
		fmt.Println("  Found wallet files:")
		for i, w := range wallets {
			fmt.Printf("  %d) %s\n", i+1, w)
		}
	} else {
		fmt.Println("  No wallet files found.")
	}
	fmt.Printf("  %d) Enter a custom path\n", len(wallets)+1)
	fmt.Printf("  %d) Create a new wallet\n", len(wallets)+2)
	fmt.Print("\n  Choose: ")

	choiceLine, err := s.reader.ReadString('\n')
	if err != nil {
		return err
	}
	choice, err := strconv.Atoi(strings.TrimSpace(choiceLine))
	if err != nil || choice < 1 || choice > len(wallets)+2 {
		return fmt.Errorf("invalid choice")
	}

	var walletPath string
	switch {
	case choice <= len(wallets):
		walletPath = wallets[choice-1]
	case choice == len(wallets)+1:
		fmt.Println("  Enter path to wallet file:")
		fmt.Print("\n> ")
		pathLine, err := s.reader.ReadString('\n')
		if err != nil {
			return err
		}
		walletPath = strings.TrimSpace(pathLine)
		if walletPath == "" {
			return fmt.Errorf("empty path")
		}
		if strings.HasPrefix(walletPath, "~/") {
			walletPath = filepath.Join(home, walletPath[2:])
		}
		abs, err := filepath.Abs(walletPath)
		if err != nil {
			return fmt.Errorf("invalid path: %w", err)
		}
		walletPath = abs
		if _, err := os.Stat(walletPath); err != nil {
			return fmt.Errorf("file not found: %s", walletPath)
		}
	case choice == len(wallets)+2:
		walletPath = ""
	}

	password, err := s.readPassword("  Password: ")
	if err != nil {
		return err
	}
	if len(password) < 3 {
		return fmt.Errorf("password must be at least 3 characters")
	}

	recheckCtx, recheckCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer recheckCancel()
	_, recheckErr := s.client.Get(recheckCtx, "/api/wallet/balance")
	if recheckErr == nil {
		fmt.Printf("\n%s\n", SectionHead("Wallet", s.noColor))
		fmt.Println("  A wallet was loaded in the background (likely from a previous attempt).")
		fmt.Println("  Run 'balance' to check.")
		return nil
	}
	if apiErr, ok := recheckErr.(*APIError); ok && apiErr.StatusCode == 409 {
		fmt.Printf("\n%s\n", SectionHead("Wallet", s.noColor))
		fmt.Println("  A wallet was loaded in the background (likely from a previous attempt).")
		fmt.Println("  Run 'balance' to check.")
		return nil
	}

	loadCtx, loadCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer loadCancel()

	loadReq := map[string]string{
		"password": password,
	}
	if walletPath != "" {
		loadReq["wallet_file"] = walletPath
	}
	raw, err := s.client.Post(loadCtx, "/api/wallet/load", loadReq)
	if err != nil {
		if apiErr, ok := err.(*APIError); ok && strings.Contains(strings.ToLower(apiErr.Message), "already loaded") {
			return fmt.Errorf("the core thinks a wallet is already loaded, but it isn't usable.\n  This can happen after a failed or timed-out load attempt.\n  Restart the core with 'blocknet restart %s' to clear the stale state", s.network)
		}
		return s.handleAPIError(err)
	}

	var resp struct {
		Loaded  bool   `json:"loaded"`
		Address string `json:"address"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("\n  Wallet loaded\n")
	fmt.Printf("  Address: %s\n", resp.Address)

	s.locked = false

	if walletPath != "" {
		backupDir := WalletsDir()
		os.MkdirAll(backupDir, 0755)
		backupPath := filepath.Join(backupDir, filepath.Base(walletPath))
		if _, err := os.Stat(backupPath); err != nil {
			src, err := os.ReadFile(walletPath)
			if err == nil {
				if err := os.WriteFile(backupPath, src, 0600); err == nil {
					fmt.Printf("  Backup: %s\n", backupPath)
				}
			}
		}
	}

	if walletPath != "" && cfgErr == nil {
		fmt.Print("\n  Save wallet path to config for auto-load? [y/N]: ")
		confirmLine, _ := s.reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(confirmLine)) == "y" {
			cc := cfg.Cores[s.network]
			if cc != nil {
				cc.WalletFile = walletPath
				EnsureConfigDir()
				if err := SaveConfig(ConfigFile(), cfg); err != nil {
					fmt.Fprintf(os.Stderr, "  warning: could not save config: %v\n", err)
				} else {
					fmt.Println("  Saved. Next start will use this wallet automatically.")
				}
			}
		}
	}
	return nil
}

func (s *AttachSession) cmdUnload() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.client.Post(ctx, "/api/wallet/unload", nil)
	if err != nil {
		return s.handleAPIError(err)
	}

	s.locked = false
	fmt.Printf("\n%s\n", SectionHead("Unloaded", s.noColor))
	fmt.Println("  Wallet unloaded. Use 'load' to open another.")
	return nil
}

func (s *AttachSession) cmdBalance() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	raw, err := s.client.Get(ctx, "/api/wallet/balance")
	if err != nil {
		return s.handleAPIError(err)
	}

	var bal struct {
		Spendable          uint64 `json:"spendable"`
		Pending            uint64 `json:"pending"`
		PendingUnconfirmed uint64 `json:"pending_unconfirmed"`
		PendingUnconfETA   int64  `json:"pending_unconfirmed_eta"`
		OutputsTotal       int    `json:"outputs_total"`
		OutputsUnspent     int    `json:"outputs_unspent"`
	}
	if err := json.Unmarshal(raw, &bal); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	fmt.Printf("\n%s\n", SectionHead("Balance", s.noColor))
	fmt.Printf("  spendable:  %s\n", FormatAmount(bal.Spendable))
	fmt.Printf("  confirming: %s\n", FormatAmount(bal.Pending))
	if bal.PendingUnconfirmed > 0 {
		eta := time.Duration(bal.PendingUnconfETA) * time.Second
		fmt.Printf("  pending:    %s (est unlock ~%s)\n", FormatAmount(bal.PendingUnconfirmed), eta.Round(time.Minute))
	}
	fmt.Printf("  total:      %s\n", FormatAmount(bal.Spendable+bal.Pending))
	fmt.Printf("  outputs:    %d unspent", bal.OutputsUnspent)
	if bal.OutputsTotal > bal.OutputsUnspent {
		fmt.Printf(", %d spent", bal.OutputsTotal-bal.OutputsUnspent)
	}
	fmt.Println()
	return nil
}

func (s *AttachSession) cmdAddress() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	raw, err := s.client.Get(ctx, "/api/wallet/address")
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		Address string `json:"address"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("\n%s\n\n", SectionHead("Address", s.noColor))
	fmt.Printf("  %s\n\n", resp.Address)

	idURL := "https://blocknet.id"
	if !s.noColor {
		idURL = "\033[4m\033[38;2;170;255;0mhttps://blocknet.id\033[0m"
	}
	fmt.Printf("  Get a short name like @name or $name at %s\n", idURL)
	return nil
}

func (s *AttachSession) cmdSend(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: send <address> <amount> [memo|hex:<memo_hex>]")
	}

	address := SanitizeInput(args[0])
	sendAll := strings.EqualFold(args[1], "all")

	var amount uint64
	var err error
	if !sendAll {
		amount, err = ParseAmount(args[1])
		if err != nil {
			return fmt.Errorf("invalid amount: %w", err)
		}
	}

	var memo string
	if len(args) >= 3 {
		memo = strings.TrimSpace(strings.Join(args[2:], " "))
		if len(memo) >= 2 && ((memo[0] == '"' && memo[len(memo)-1] == '"') || (memo[0] == '\'' && memo[len(memo)-1] == '\'')) {
			memo = memo[1 : len(memo)-1]
		}
	}

	ctx := context.Background()

	if sendAll {
		return s.sendAll(ctx, address, memo)
	}

	recipient := map[string]any{"address": address, "amount": amount}
	if memo != "" {
		recipient["memo"] = memo
	}
	sendReq := map[string]any{
		"recipients": []map[string]any{recipient},
		"dry_run":    true,
	}

	raw, err := s.client.Post(ctx, "/api/wallet/send", sendReq)
	if err != nil {
		return s.handleAPIError(err)
	}

	var preview struct {
		Fee    uint64 `json:"fee"`
		Change uint64 `json:"change"`
	}
	json.Unmarshal(raw, &preview)

	fmt.Printf("\n%s\n", SectionHead("Send", s.noColor))
	fmt.Printf("\n  Send %s to %s?\n", FormatAmount(amount), address)
	fmt.Printf("  Fee:     %s\n", FormatAmount(preview.Fee))
	if preview.Change > 0 {
		fmt.Printf("  Change:  %s\n", FormatAmount(preview.Change))
	}
	if memo != "" {
		fmt.Printf("  Memo:    %s\n", memo)
	}
	fmt.Print("  Confirm [y/N]: ")

	confirm, _ := s.reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		fmt.Println("  Cancelled")
		return nil
	}

	sendReq["dry_run"] = false
	raw, err = s.client.Post(ctx, "/api/wallet/send", sendReq)
	if err != nil {
		return s.handleAPIError(err)
	}

	var result struct {
		TxID string `json:"txid"`
		Fee  uint64 `json:"fee"`
	}
	json.Unmarshal(raw, &result)

	fmt.Printf("  Sent: %s\n", result.TxID)
	fmt.Printf("  Explorer: https://explorer.blocknetcrypto.com/tx/%s\n", result.TxID)
	return nil
}

func (s *AttachSession) sendAll(ctx context.Context, address, memo string) error {
	raw, err := s.client.Get(ctx, "/api/wallet/outputs")
	if err != nil {
		return s.handleAPIError(err)
	}

	var outputsResp struct {
		Outputs []struct {
			TxID        string `json:"txid"`
			OutputIndex int    `json:"output_index"`
			Amount      uint64 `json:"amount"`
			Status      string `json:"status"`
		} `json:"outputs"`
	}
	json.Unmarshal(raw, &outputsResp)

	var inputs []map[string]any
	var total uint64
	for _, out := range outputsResp.Outputs {
		if out.Status == "unspent" {
			inputs = append(inputs, map[string]any{
				"txid":         out.TxID,
				"output_index": out.OutputIndex,
			})
			total += out.Amount
		}
	}
	if len(inputs) == 0 {
		return fmt.Errorf("no spendable outputs")
	}

	recipient := map[string]any{"address": address, "amount": uint64(1)}
	if memo != "" {
		recipient["memo"] = memo
	}
	sendReq := map[string]any{
		"recipients": []map[string]any{recipient},
		"inputs":     inputs,
		"dry_run":    true,
	}

	raw, err = s.client.Post(ctx, "/api/wallet/send/advanced", sendReq)
	if err != nil {
		return s.handleAPIError(err)
	}

	var preview struct {
		Fee uint64 `json:"fee"`
	}
	json.Unmarshal(raw, &preview)

	amount := total - preview.Fee

	fmt.Printf("\n%s\n", SectionHead("Send", s.noColor))
	fmt.Printf("\n  Send %s to %s? (all)\n", FormatAmount(amount), address)
	fmt.Printf("  Fee:    %s\n", FormatAmount(preview.Fee))
	if memo != "" {
		fmt.Printf("  Memo:   %s\n", memo)
	}
	fmt.Print("  Confirm [y/N]: ")

	confirm, _ := s.reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		fmt.Println("  Cancelled")
		return nil
	}

	sendReq["recipients"].([]map[string]any)[0]["amount"] = amount
	sendReq["dry_run"] = false
	raw, err = s.client.Post(ctx, "/api/wallet/send/advanced", sendReq)
	if err != nil {
		return s.handleAPIError(err)
	}

	var result struct {
		TxID string `json:"txid"`
	}
	json.Unmarshal(raw, &result)

	fmt.Printf("  Sent: %s\n", result.TxID)
	fmt.Printf("  Explorer: https://explorer.blocknetcrypto.com/tx/%s\n", result.TxID)
	return nil
}

func (s *AttachSession) cmdSign() error {
	fmt.Printf("\n%s\n", SectionHead("Sign", s.noColor))
	fmt.Println("  Enter the text to sign, press ENTER when you're done.")
	fmt.Print("\n> ")

	line, err := s.reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}
	message := strings.TrimSpace(line)
	if message == "" {
		return fmt.Errorf("message cannot be empty")
	}
	if len(message) > 1024 {
		return fmt.Errorf("message must be <= 1024 bytes")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := s.client.Post(ctx, "/api/wallet/sign", map[string]string{"message": message})
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		Signature string `json:"signature"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("\n  %s\n", resp.Signature)
	return nil
}

func (s *AttachSession) cmdVerifyMsg() error {
	fmt.Printf("\n%s\n", SectionHead("Verify", s.noColor))
	fmt.Println("  Enter the address:")
	fmt.Print("\n> ")
	addrLine, err := s.reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}
	address := strings.TrimSpace(addrLine)
	if address == "" {
		return fmt.Errorf("address cannot be empty")
	}

	fmt.Println("  Enter the message that was signed:")
	fmt.Print("\n> ")
	msgLine, err := s.reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}
	message := strings.TrimSpace(msgLine)
	if message == "" {
		return fmt.Errorf("message cannot be empty")
	}

	fmt.Println("  Enter the signature (hex):")
	fmt.Print("\n> ")
	sigLine, err := s.reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}
	signature := strings.TrimSpace(sigLine)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := s.client.Post(ctx, "/api/verify", map[string]string{
		"address":   address,
		"message":   message,
		"signature": signature,
	})
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		Valid bool `json:"valid"`
	}
	json.Unmarshal(raw, &resp)

	if resp.Valid {
		fmt.Printf("\n  %s\n", SectionHead("Signature is VALID", s.noColor))
	} else {
		fmt.Printf("\n  %s\n", ErrorHead("Signature is INVALID", s.noColor))
	}
	return nil
}

func (s *AttachSession) cmdHistory() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := s.client.Get(ctx, "/api/wallet/history")
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		Count   int `json:"count"`
		Outputs []struct {
			TxID        string `json:"txid"`
			OutputIndex int    `json:"output_index"`
			Amount      uint64 `json:"amount"`
			BlockHeight uint64 `json:"block_height"`
			IsCoinbase  bool   `json:"is_coinbase"`
			Spent       bool   `json:"spent"`
		} `json:"outputs"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("\n%s\n", SectionHead("History", s.noColor))

	if resp.Count == 0 {
		fmt.Println("  No transactions yet")
		return nil
	}

	green := "\033[38;2;170;255;0m"
	reset := "\033[0m"
	if s.noColor {
		green, reset = "", ""
	}

	for _, out := range resp.Outputs {
		outType := "regular"
		if out.IsCoinbase {
			outType = "coinbase"
		}
		spentTag := ""
		if out.Spent {
			spentTag = " (spent)"
		}
		fmt.Printf("  block %-6d %sIN%s  %-16s %s  %s%s\n",
			out.BlockHeight, green, reset, FormatAmount(out.Amount), outType, out.TxID, spentTag)
	}
	return nil
}

func (s *AttachSession) cmdOutputs(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := s.client.Get(ctx, "/api/wallet/outputs")
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		ChainHeight  uint64 `json:"chain_height"`
		SyncedHeight uint64 `json:"synced_height"`
		Outputs      []struct {
			TxID          string `json:"txid"`
			OutputIndex   int    `json:"output_index"`
			Amount        uint64 `json:"amount"`
			Status        string `json:"status"`
			Type          string `json:"type"`
			Confirmations uint64 `json:"confirmations"`
			BlockHeight   uint64 `json:"block_height"`
			SpentHeight   uint64 `json:"spent_height,omitempty"`
			OneTimePub    string `json:"one_time_pub"`
			Commitment    string `json:"commitment"`
		} `json:"outputs"`
	}
	json.Unmarshal(raw, &resp)

	filter := "all"
	detailIndex := -1
	showByTx := false
	var txFilter string
	txIndexFilter := -1

	if len(args) > 0 {
		switch strings.ToLower(args[0]) {
		case "spent", "unspent", "pending":
			filter = strings.ToLower(args[0])
			if len(args) == 2 {
				n, err := strconv.Atoi(args[1])
				if err != nil || n < 1 {
					fmt.Println("  Usage: outputs [spent|unspent|pending] [index]")
					fmt.Println("         outputs tx <txid>")
					return nil
				}
				detailIndex = n
			}
		case "tx":
			if len(args) != 2 {
				fmt.Println("  Usage: outputs tx <txid>")
				fmt.Println("         outputs tx <txid>:<index>")
				return nil
			}
			parts := strings.SplitN(args[1], ":", 2)
			txFilter = strings.TrimSpace(parts[0])
			showByTx = true
			if len(parts) == 2 {
				n, err := strconv.Atoi(parts[1])
				if err != nil || n < 0 {
					fmt.Println("  Invalid tx output index")
					return nil
				}
				txIndexFilter = n
			}
		default:
			n, err := strconv.Atoi(args[0])
			if err != nil || n < 1 || len(args) > 1 {
				fmt.Println("  Usage: outputs [spent|unspent|pending] [index]")
				fmt.Println("         outputs tx <txid>")
				return nil
			}
			detailIndex = n
		}
	}

	statusLabel := func(status string) string {
		if s.noColor {
			return status
		}
		switch status {
		case "unspent":
			return "\033[38;2;170;255;0munspent\033[0m"
		case "spent":
			return "\033[38;2;255;68;68mspent\033[0m"
		case "pending":
			return "\033[38;2;255;170;0mpending\033[0m"
		default:
			return status
		}
	}

	fmt.Printf("\n%s\n", SectionHead("Outputs", s.noColor))

	type entry struct {
		TxID, Status, Type, OneTimePub, Commitment      string
		OutputIndex                                     int
		Amount, Confirmations, BlockHeight, SpentHeight uint64
	}

	var filtered []entry
	for _, o := range resp.Outputs {
		if filter != "all" && o.Status != filter {
			continue
		}
		if showByTx {
			if o.TxID != txFilter {
				continue
			}
			if txIndexFilter >= 0 && o.OutputIndex != txIndexFilter {
				continue
			}
		}
		filtered = append(filtered, entry{
			o.TxID, o.Status, o.Type, o.OneTimePub, o.Commitment,
			o.OutputIndex, o.Amount, o.Confirmations, o.BlockHeight, o.SpentHeight,
		})
	}

	if len(filtered) == 0 {
		if resp.SyncedHeight < resp.ChainHeight {
			fmt.Printf("  No outputs found yet.\n")
			fmt.Printf("  Wallet scan is still catching up (%d/%d).\n", resp.SyncedHeight, resp.ChainHeight)
			fmt.Println("  Try: sync")
		} else if filter != "all" {
			fmt.Printf("  No %s outputs found.\n", filter)
		} else {
			fmt.Println("  No outputs found in this wallet yet.")
			fmt.Println("  Receive funds, then run sync if needed.")
		}
		return nil
	}

	printDetail := func(pos int, o entry) {
		fmt.Printf("  #%d\n", pos)
		fmt.Printf("    status:       %s\n", statusLabel(o.Status))
		fmt.Printf("    amount:       %s\n", FormatAmount(o.Amount))
		fmt.Printf("    type:         %s\n", o.Type)
		fmt.Printf("    confirmations:%d\n", o.Confirmations)
		fmt.Printf("    block:        %d\n", o.BlockHeight)
		fmt.Printf("    tx output:    %s:%d\n", o.TxID, o.OutputIndex)
		fmt.Printf("    one-time pub: %s\n", o.OneTimePub)
		fmt.Printf("    commitment:   %s\n", o.Commitment)
		if o.Status == "spent" && o.SpentHeight > 0 {
			fmt.Printf("    spent block:  %d\n", o.SpentHeight)
		}
	}

	if detailIndex > 0 {
		if detailIndex > len(filtered) {
			fmt.Printf("  Output index %d is out of range (1-%d).\n", detailIndex, len(filtered))
			return nil
		}
		printDetail(detailIndex, filtered[detailIndex-1])
		return nil
	}

	if showByTx {
		for i, o := range filtered {
			if i > 0 {
				fmt.Println()
			}
			printDetail(i+1, o)
		}
		return nil
	}

	for i, o := range filtered {
		fmt.Printf("  #%d  %-12s %-8s conf: %d\n", i+1, statusLabel(o.Status), o.Type, o.Confirmations)
		fmt.Printf("      amount: %s\n", FormatAmount(o.Amount))
		fmt.Printf("      block:  %d  tx: %s:%d\n", o.BlockHeight, o.TxID, o.OutputIndex)
	}
	return nil
}

func (s *AttachSession) cmdSeed() error {
	amber := "\033[38;2;255;170;0m"
	rst := "\033[0m"
	if s.noColor {
		amber, rst = "", ""
	}
	fmt.Printf("\n%s%s%s\n", amber, "# Seed", rst)
	fmt.Printf("  %sWARNING: Your recovery seed controls all funds.%s\n", amber, rst)
	fmt.Printf("  %sAnyone with this seed can steal your coins.%s\n", amber, rst)
	fmt.Printf("  %sNever share it. Never enter it online.%s\n", amber, rst)
	fmt.Print("\n  Show recovery seed? [y/N]: ")

	confirm, _ := s.reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		return nil
	}

	password, err := s.readPassword("  Password: ")
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := s.client.Post(ctx, "/api/wallet/seed", map[string]string{"password": password})
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		Mnemonic string   `json:"mnemonic"`
		Words    []string `json:"words"`
	}
	json.Unmarshal(raw, &resp)

	if resp.Mnemonic == "" {
		fmt.Println("  No recovery seed available (wallet may predate BIP39 support)")
		return nil
	}

	words := resp.Words
	if len(words) == 0 {
		words = strings.Fields(resp.Mnemonic)
	}

	fmt.Println()
	for i := 0; i < len(words); i += 4 {
		end := i + 4
		if end > len(words) {
			end = len(words)
		}
		row := ""
		for j := i; j < end; j++ {
			row += fmt.Sprintf("%2d.%-10s ", j+1, words[j])
		}
		fmt.Printf("  %s\n", strings.TrimRight(row, " "))
	}

	fmt.Println()
	fmt.Println("  Write these words down and store them safely.")
	fmt.Println("  Recover with: import (option 1: recovery seed)")
	return nil
}

func (s *AttachSession) cmdImport() error {
	fmt.Printf("\n%s\n", SectionHead("Import", s.noColor))
	fmt.Println("  1) 12-word recovery seed")
	fmt.Println("  2) spend-key/view-key (hex private keys)")
	fmt.Print("\n  Choose [1/2]: ")

	choiceLine, err := s.reader.ReadString('\n')
	if err != nil {
		return err
	}
	choice := strings.ToLower(strings.TrimSpace(choiceLine))

	switch choice {
	case "1", "seed", "mnemonic", "12":
		return s.importFromMnemonic()
	case "2", "keys", "key", "spend", "view":
		return fmt.Errorf("key import requires direct access — use the core CLI with --cli flag")
	default:
		return fmt.Errorf("invalid import type: choose 1 or 2")
	}
}

func (s *AttachSession) importFromMnemonic() error {
	fmt.Println("  Input the 12 words of your seed:")
	fmt.Print("\n> ")

	line, err := s.reader.ReadString('\n')
	if err != nil {
		return err
	}
	mnemonic := strings.Join(strings.Fields(strings.ReplaceAll(strings.TrimSpace(line), ",", " ")), " ")

	fmt.Println("  Input the name of this wallet:")
	fmt.Print("\n> ")
	nameLine, err := s.reader.ReadString('\n')
	if err != nil {
		return err
	}
	filename := strings.TrimSpace(nameLine)
	if filename == "" {
		return fmt.Errorf("invalid wallet name")
	}
	if !strings.HasSuffix(filename, ".wallet.dat") {
		filename += ".wallet.dat"
	}

	password, err := s.readPassword("  Password: ")
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := s.client.Post(ctx, "/api/wallet/import", map[string]string{
		"mnemonic": mnemonic,
		"password": password,
		"filename": filename,
	})
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		Address  string `json:"address"`
		Filename string `json:"filename"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("\n  name: %s\n", resp.Filename)
	fmt.Printf("  address: %s\n", resp.Address)
	return nil
}

func (s *AttachSession) cmdViewKeys() error {
	fmt.Printf("\n%s\n", SectionHead("View Keys", s.noColor))

	amber := "\033[38;2;255;170;0m"
	rst := "\033[0m"
	if s.noColor {
		amber, rst = "", ""
	}
	fmt.Printf("  %sWARNING: Your view private key lets anyone see all incoming funds.%s\n", amber, rst)
	fmt.Printf("  %sNever share it unless you understand the implications.%s\n", amber, rst)
	fmt.Print("\n  Export view-only keys? [y/N]: ")

	confirm, _ := s.reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		return nil
	}

	password, err := s.readPassword("  Password: ")
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := s.client.Post(ctx, "/api/wallet/viewkeys", map[string]string{"password": password})
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		SpendPub string `json:"spend_pub"`
		ViewPriv string `json:"view_priv"`
		ViewPub  string `json:"view_pub"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("\n  spend public key:  %s\n", resp.SpendPub)
	fmt.Printf("  view private key:  %s\n", resp.ViewPriv)
	fmt.Printf("  view public key:   %s\n", resp.ViewPub)
	fmt.Println()
	fmt.Println("  To create a view-only wallet on another machine, use these keys")
	fmt.Println("  with the import command (option 2: spend-key/view-key).")
	return nil
}

func (s *AttachSession) cmdProve(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: prove <txid>")
	}

	txid := SanitizeInput(args[0])
	if len(txid) != 64 {
		return fmt.Errorf("txid must be 64 hex characters")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := s.client.Post(ctx, "/api/wallet/prove", map[string]string{"txid": txid})
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		TxID  string `json:"txid"`
		TxKey string `json:"tx_key"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("\n%s\n", SectionHead("Prove", s.noColor))
	fmt.Printf("  txid:    %s\n", resp.TxID)
	fmt.Printf("  tx key:  %s\n", resp.TxKey)
	fmt.Println()
	fmt.Println("  Share this tx key with the recipient so they can verify you sent the transaction.")
	return nil
}

func (s *AttachSession) cmdLock() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.client.Post(ctx, "/api/wallet/lock", nil)
	if err != nil {
		return s.handleAPIError(err)
	}

	s.locked = true
	fmt.Printf("\n%s\n", SectionHead("Locked", s.noColor))
	return nil
}

func (s *AttachSession) cmdUnlock() error {
	if !s.locked {
		fmt.Printf("\n%s\n", SectionHead("Unlocked", s.noColor))
		fmt.Println("  Already unlocked")
		return nil
	}

	password, err := s.readPassword("Password: ")
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = s.client.Post(ctx, "/api/wallet/unlock", map[string]string{"password": password})
	if err != nil {
		return s.handleAPIError(err)
	}

	s.locked = false
	fmt.Printf("\n%s\n", SectionHead("Unlocked", s.noColor))
	return nil
}

func (s *AttachSession) cmdAudit() error {
	fmt.Printf("\n%s\n", SectionHead("Audit", s.noColor))
	fmt.Println("  Scanning wallet outputs for duplicate key images...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := s.client.Post(ctx, "/api/wallet/audit", nil)
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		TotalOutputs    int    `json:"total_outputs"`
		UniqueKeyImages int    `json:"unique_key_images"`
		FailedKeyImages int    `json:"failed_key_images"`
		TotalBurned     uint64 `json:"total_burned"`
		BurnedOutputs   int    `json:"burned_outputs"`
		DuplicateGroups []struct {
			KeyImage         string `json:"key_image"`
			BurnedAmount     uint64 `json:"burned_amount"`
			UnspendableCount int    `json:"unspendable_count"`
			Outputs          []struct {
				TxID        string `json:"txid"`
				OutputIndex int    `json:"output_index"`
				Amount      uint64 `json:"amount"`
				Spent       bool   `json:"spent"`
				BlockHeight uint64 `json:"block_height"`
			} `json:"outputs"`
		} `json:"duplicate_groups"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("  Total outputs:      %d\n", resp.TotalOutputs)
	fmt.Printf("  Unique key images:  %d\n", resp.UniqueKeyImages)
	if resp.FailedKeyImages > 0 {
		fmt.Printf("  Failed key images:  %d\n", resp.FailedKeyImages)
	}

	if len(resp.DuplicateGroups) == 0 {
		green := "\033[38;2;170;255;0m"
		rst := "\033[0m"
		if s.noColor {
			green, rst = "", ""
		}
		fmt.Printf("\n  %sNo duplicate key images found. Wallet is clean.%s\n", green, rst)
		return nil
	}

	amber := "\033[38;2;255;170;0m"
	rst := "\033[0m"
	if s.noColor {
		amber, rst = "", ""
	}

	fmt.Printf("\n  %sDuplicate key images found: %d group(s)%s\n", amber, len(resp.DuplicateGroups), rst)
	fmt.Printf("  %sBurned outputs: %d (%s unspendable)%s\n", amber, resp.BurnedOutputs, FormatAmount(resp.TotalBurned), rst)

	for i, group := range resp.DuplicateGroups {
		fmt.Printf("\n  Group %d — key image: %s\n", i+1, group.KeyImage)
		fmt.Printf("    burned: %s across %d duplicate(s)\n", FormatAmount(group.BurnedAmount), group.UnspendableCount)
		for _, out := range group.Outputs {
			spentTag := ""
			if out.Spent {
				spentTag = " (spent)"
			}
			fmt.Printf("    block %-6d  %s  %s:%d%s\n",
				out.BlockHeight, FormatAmount(out.Amount), out.TxID, out.OutputIndex, spentTag)
		}
	}
	return nil
}

func (s *AttachSession) cmdSave() error {
	fmt.Printf("\n%s\n", SectionHead("Saved", s.noColor))
	fmt.Println("  Wallet is saved automatically by the core daemon.")
	return nil
}

func (s *AttachSession) cmdSync() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := s.client.Get(ctx, "/api/wallet/balance")
	if err == nil {
		var bal struct {
			ChainHeight uint64 `json:"chain_height"`
		}
		json.Unmarshal(raw, &bal)

		rawOut, errOut := s.client.Get(ctx, "/api/wallet/outputs")
		if errOut == nil {
			var outs struct {
				SyncedHeight uint64 `json:"synced_height"`
			}
			json.Unmarshal(rawOut, &outs)
			fmt.Printf("\n%s\n", SectionHead("Sync", s.noColor))
			fmt.Printf("  Known blocks:   %d\n", bal.ChainHeight)
			fmt.Printf("  Blocks scanned: %d\n", outs.SyncedHeight)
		}
	}

	_, err = s.client.Post(ctx, "/api/wallet/sync", nil)
	if err != nil {
		return s.handleAPIError(err)
	}

	fmt.Println("  Sync triggered — the core will scan for new outputs.")
	return nil
}
