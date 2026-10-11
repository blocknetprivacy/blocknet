package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// viewOnlyPhrase describes a view-only wallet everywhere attach mentions one.
const viewOnlyPhrase = "view-only (watches incoming funds, cannot spend)"

// maxMemoBytes is the largest memo payload a transaction can carry: the core's
// wallet.MemoSize (128) minus its 4-byte length prefix. Enforced client-side for
// a clean error before the round-trip; the core re-validates authoritatively.
const maxMemoBytes = 124

// parseMemoArg converts the trailing memo arguments into the API's memo
// fields. A "hex:<hex>" prefix is decoded to raw bytes and sent as memo_hex;
// anything else is UTF-8 text sent as memo_text (surrounding quotes stripped).
// display is the human-readable form shown in the send confirmation.
func parseMemoArg(parts []string) (memoText, memoHex, display string, err error) {
	if len(parts) == 0 {
		return "", "", "", nil
	}
	raw := strings.TrimSpace(strings.Join(parts, " "))
	if raw == "" {
		return "", "", "", nil
	}
	if strings.HasPrefix(raw, "hex:") {
		h := strings.ToLower(strings.TrimPrefix(raw, "hex:"))
		decoded, decErr := hex.DecodeString(h)
		if decErr != nil {
			return "", "", "", fmt.Errorf("invalid memo hex")
		}
		if len(decoded) > maxMemoBytes {
			return "", "", "", fmt.Errorf("memo too long: max %d bytes", maxMemoBytes)
		}
		return "", h, MemoDisplay(h), nil
	}
	if len(raw) >= 2 && ((raw[0] == '"' && raw[len(raw)-1] == '"') || (raw[0] == '\'' && raw[len(raw)-1] == '\'')) {
		raw = raw[1 : len(raw)-1]
	}
	if len(raw) > maxMemoBytes {
		return "", "", "", fmt.Errorf("memo too long: max %d bytes", maxMemoBytes)
	}
	return raw, "", raw, nil
}

// resolvedRecipient is the name-resolution info the send API returns per
// recipient when the address was a blocknet.id @name/$name handle.
type resolvedRecipient struct {
	ResolvedHandle   string `json:"resolved_handle"`
	ResolvedAddress  string `json:"resolved_address"`
	ResolverVerified bool   `json:"resolver_verified"`
}

// printResolution prints the "Resolved <input> -> <addr>" line (with a verified
// badge) when the address resolved from a handle, mirroring the core menu.
func (s *AttachSession) printResolution(input string, r resolvedRecipient) {
	if r.ResolvedHandle == "" || r.ResolvedAddress == "" {
		return
	}
	if s.noColor {
		verified := ""
		if r.ResolverVerified {
			verified = " [verified]"
		}
		fmt.Printf("  Resolved %s -> %s%s\n", input, r.ResolvedAddress, verified)
		return
	}
	if r.ResolverVerified {
		green, _, _, _, _, reset := Palette(s.noColor)
		fmt.Printf("  Resolved %s -> %s %s✓%s verified\n", input, r.ResolvedAddress, green, reset)
	} else {
		fmt.Printf("  Resolved %s -> %s\n", input, r.ResolvedAddress)
	}
}

// walletAlreadyLoaded reports whether the core already has a wallet loaded.
func (s *AttachSession) walletAlreadyLoaded() bool {
	ctx, cancel := withPatience(defaultAPITimeout)
	_, err := s.client.Get(ctx, "/api/wallet/balance")
	cancel()
	if err == nil {
		return true
	}
	apiErr, ok := err.(*APIError)
	return ok && (apiErr.StatusCode == 409 || apiErr.StatusCode == 403)
}

func (s *AttachSession) cmdLoad() error {
	if s.walletAlreadyLoaded() {
		fmt.Printf("\n%s\n\n", SectionHead("Wallet", s.noColor))
		fmt.Println("  A wallet is already loaded")
		return nil
	}

	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cc := cfg.Cores[s.network]
	if cc == nil {
		return fmt.Errorf("no config for %s", s.network)
	}

	// The core only loads wallets from the folder of the wallet file it was
	// started with (it keeps the base name of the path it is sent), so only
	// files in that folder are offered.
	coreDir := filepath.Dir(cc.EffectiveWalletFile(s.network))
	wallets, _ := filepath.Glob(filepath.Join(coreDir, "*.wallet.dat"))
	sort.Strings(wallets)

	fmt.Printf("\n%s\n\n", SectionHead("Load Wallet", s.noColor))

	if len(wallets) > 0 {
		fmt.Printf("  Wallet files in %s:\n", coreDir)
		for i, w := range wallets {
			fmt.Printf("  %d) %s\n", i+1, filepath.Base(w))
		}
	} else {
		fmt.Printf("  No wallet files in %s\n", coreDir)
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
	var createFilename string
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
			home, _ := os.UserHomeDir()
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
		if filepath.Dir(walletPath) != coreDir {
			return fmt.Errorf("the core only loads wallets from %s\n  Copy the file there, then run 'load' again", coreDir)
		}
	case choice == len(wallets)+2:
		fmt.Println("  Wallet name (without extension):")
		fmt.Print("\n> ")
		nameLine, err := s.reader.ReadString('\n')
		if err != nil {
			return err
		}
		name := strings.TrimSpace(nameLine)
		if name == "" {
			return fmt.Errorf("empty wallet name")
		}
		if !strings.HasSuffix(name, ".wallet.dat") {
			name += ".wallet.dat"
		}
		createFilename = name
	}

	password, err := s.readPassword("  Password: ")
	if err != nil {
		return err
	}
	if len(password) < 3 {
		return fmt.Errorf("password must be at least 3 characters")
	}
	if createFilename != "" {
		confirmPw, err := s.readPassword("  Confirm password: ")
		if err != nil {
			return err
		}
		if confirmPw != password {
			return fmt.Errorf("passwords do not match")
		}
	}

	if s.walletAlreadyLoaded() {
		fmt.Printf("\n%s\n\n", SectionHead("Wallet", s.noColor))
		fmt.Println("  A wallet was loaded in the background (likely from a previous attempt)")
		fmt.Println("  Run 'balance' to check")
		return nil
	}

	if createFilename != "" {
		createCtx, createCancel := withPatience(60 * time.Second)
		raw, err := s.client.Post(createCtx, "/api/wallet/create", map[string]string{
			"password": password,
			"filename": createFilename,
		})
		createCancel()
		if err != nil {
			if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == 409 {
				return fmt.Errorf("%s\n  Use 'load' and select it to open the existing wallet", apiErr.Message)
			}
			return s.handleAPIError(err)
		}

		var resp struct {
			Created  bool   `json:"created"`
			Address  string `json:"address"`
			Filename string `json:"filename"`
		}
		json.Unmarshal(raw, &resp)

		s.locked = false
		fmt.Printf("\n%s\n\n", SectionHead("Wallet Created", s.noColor))
		fmt.Printf("  Address:  %s\n", resp.Address)
		fmt.Printf("  Filename: %s\n", resp.Filename)

		cc.WalletFile = filepath.Join(coreDir, resp.Filename)
		if err := EnsureConfigDir(); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
		if err := SaveConfig(ConfigFile(), cfg); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
		return nil
	}

	if walletPath != cc.WalletFile {
		cc.WalletFile = walletPath
		if err := EnsureConfigDir(); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
		if err := SaveConfig(ConfigFile(), cfg); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
	}

	loadCtx, loadCancel := withPatience(60 * time.Second)
	raw, err := s.client.Post(loadCtx, "/api/wallet/load", map[string]string{
		"password": password,
		"filepath": filepath.Base(walletPath),
	})
	loadCancel()
	if err != nil {
		if apiErr, ok := err.(*APIError); ok {
			lower := strings.ToLower(apiErr.Message)
			if strings.Contains(lower, "already loaded") {
				return fmt.Errorf("the core thinks a wallet is already loaded, but it isn't usable.\n  This can happen after a failed or timed-out load attempt.\n  Restart the core with 'blocknet restart %s' to clear the stale state", s.network)
			}
			switch apiErr.StatusCode {
			case 401:
				if strings.Contains(lower, "wrong password") {
					return fmt.Errorf("wrong password")
				}
				return fmt.Errorf("unauthorized: check api.cookie")
			case 403:
				return fmt.Errorf("wallet file not readable (check file permissions)")
			case 404:
				return fmt.Errorf("wallet file not found by the core\n  It must be in %s", coreDir)
			case 422:
				return fmt.Errorf("wallet file is corrupted\n  Restore from backup or re-import from seed")
			case 500:
				return fmt.Errorf("the core returned: %s\n  Check the core log: blocknet logs %s", apiErr.Message, s.network)
			}
		}
		return s.handleAPIError(err)
	}

	var resp struct {
		Loaded   bool   `json:"loaded"`
		Address  string `json:"address"`
		Filename string `json:"filename"`
	}
	json.Unmarshal(raw, &resp)

	s.locked = false
	fmt.Printf("\n%s\n\n", SectionHead("Wallet Loaded", s.noColor))
	fmt.Printf("  Address: %s\n", resp.Address)

	{
		backupDir := WalletsDir()
		os.MkdirAll(backupDir, 0755)
		backupPath := filepath.Join(backupDir, filepath.Base(walletPath))
		if _, err := os.Stat(backupPath); err != nil {
			src, err := os.ReadFile(walletPath)
			if err == nil {
				if err := os.WriteFile(backupPath, src, 0600); err == nil {
					fmt.Printf("  Backup:  %s\n", backupPath)
				}
			}
		}
	}

	return nil
}

func (s *AttachSession) cmdUnload() error {
	ctx, cancel := withPatience(defaultAPITimeout)
	defer cancel()

	_, err := s.client.Post(ctx, "/api/wallet/unload", nil)
	if err != nil {
		return s.handleAPIError(err)
	}

	s.locked = false
	fmt.Printf("\n%s\n\n", SectionHead("Unloaded", s.noColor))
	fmt.Println("  Wallet unloaded. Use 'load' to open another")
	return nil
}

func (s *AttachSession) cmdBalance() error {
	ctx, cancel := withPatience(defaultAPITimeout)
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
		Total              uint64 `json:"total"`
		OutputsTotal       int    `json:"outputs_total"`
		OutputsUnspent     int    `json:"outputs_unspent"`
	}
	if err := json.Unmarshal(raw, &bal); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	fmt.Printf("\n%s\n\n", SectionHead("Balance", s.noColor))
	fmt.Printf("  Spendable:   %s\n", FormatAmount(bal.Spendable))
	fmt.Printf("  Pending:     %s\n", FormatAmount(bal.Pending))
	if bal.PendingUnconfirmed > 0 {
		eta := time.Duration(bal.PendingUnconfETA) * time.Second
		fmt.Printf("  Unconfirmed: %s (spendable in about %s)\n", FormatAmount(bal.PendingUnconfirmed), FormatDuration(eta))
	}
	fmt.Printf("  Total:       %s\n", FormatAmount(bal.Total))
	fmt.Printf("  Outputs:     %d unspent", bal.OutputsUnspent)
	if bal.OutputsTotal > bal.OutputsUnspent {
		fmt.Printf(", %d spent", bal.OutputsTotal-bal.OutputsUnspent)
	}
	fmt.Println()
	if behind := s.syncLag(); behind > 0 {
		Warnf("still syncing, %s behind: this may not be your full balance yet", Plural(int(behind), "block"))
	}
	return nil
}

// syncLag returns how many blocks the wallet is behind the network tip when
// that is enough that recently received funds may be missing from the
// balance. It returns 0 when the wallet is caught up (or only routinely
// behind, see syncLagWarnBlocks) and on any error fetching status. The
// warning is best-effort and must never block showing the balance.
func (s *AttachSession) syncLag() uint64 {
	ctx, cancel := withPatience(defaultAPITimeout)
	defer cancel()

	raw, err := s.client.Get(ctx, "/api/status")
	if err != nil {
		return 0
	}

	var st struct {
		ChainHeight uint64 `json:"chain_height"`
		Syncing     bool   `json:"syncing"`
		SyncTarget  uint64 `json:"sync_target"`
		Wallet      *struct {
			SyncedHeight uint64 `json:"synced_height"`
		} `json:"wallet"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return 0
	}

	// The network tip is the chain height, or the sync target while we are
	// still downloading blocks toward it.
	tip := st.ChainHeight
	if st.Syncing && st.SyncTarget > tip {
		tip = st.SyncTarget
	}

	// Compare against what the wallet has actually scanned: spendable balance
	// reflects the wallet's synced height, not the raw chain height, so a wallet
	// that is still catching up its scan can hide funds even on a synced chain.
	scanned := st.ChainHeight
	if st.Wallet != nil {
		scanned = st.Wallet.SyncedHeight
	}

	if tip <= scanned || tip-scanned <= syncLagWarnBlocks {
		return 0
	}
	return tip - scanned
}

func (s *AttachSession) cmdAddress() error {
	ctx, cancel := withPatience(defaultAPITimeout)
	defer cancel()

	raw, err := s.client.Get(ctx, "/api/wallet/address")
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		Address  string `json:"address"`
		ViewOnly bool   `json:"view_only"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("\n%s\n\n", SectionHead("Address", s.noColor))
	fmt.Printf("  %s\n", resp.Address)
	if resp.ViewOnly {
		fmt.Printf("  This wallet is %s\n", viewOnlyPhrase)
	}
	fmt.Println()

	green, _, _, _, _, reset := Palette(s.noColor)
	idURL := green + "https://blocknet.id" + reset
	fmt.Printf("  Get a short name like @name or $name at %s\n", idURL)
	return nil
}

func (s *AttachSession) cmdSend(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: send <address> <amount|all> [memo|hex:<memo_hex>]")
	}

	address := SanitizeInput(args[0])
	sendAll := strings.EqualFold(args[1], "all")

	var amount uint64
	var err error
	if !sendAll {
		amount, err = ParseAmount(args[1])
		if err != nil {
			return err
		}
	}

	// "send <addr> 1 BNT": a unit after the amount belongs to the amount,
	// not to the memo.
	rest := args[2:]
	if len(rest) > 0 && strings.EqualFold(rest[0], "bnt") {
		rest = rest[1:]
	}
	memoText, memoHex, memoDisplay, err := parseMemoArg(rest)
	if err != nil {
		return err
	}

	ctx := context.Background()

	if sendAll {
		return s.sendAll(ctx, address, memoText, memoHex, memoDisplay)
	}

	recipient := map[string]any{"address": address, "amount": amount}
	if memoHex != "" {
		recipient["memo_hex"] = memoHex
	} else if memoText != "" {
		recipient["memo_text"] = memoText
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
		Fee        uint64              `json:"fee"`
		Change     uint64              `json:"change"`
		Recipients []resolvedRecipient `json:"recipients"`
	}
	json.Unmarshal(raw, &preview)

	var resolved resolvedRecipient
	if len(preview.Recipients) > 0 {
		resolved = preview.Recipients[0]
	}

	fmt.Printf("\n%s\n\n", SectionHead("Send", s.noColor))
	if resolved.ResolvedHandle != "" {
		s.printResolution(address, resolved)
		fmt.Println()
	}
	fmt.Printf("  Send %s to %s?\n", FormatAmount(amount), address)
	fmt.Printf("  Fee:      %s\n", FormatAmount(preview.Fee))
	if resolved.ResolvedHandle != "" {
		fmt.Printf("  Address:  %s\n", resolved.ResolvedAddress)
	}
	if preview.Change > 0 {
		fmt.Printf("  Change:   %s\n", FormatAmount(preview.Change))
	}
	if memoDisplay != "" {
		fmt.Printf("  Memo:     %s\n", memoDisplay)
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

	fmt.Printf("  Sent:     %s\n", result.TxID)
	fmt.Printf("  Explorer: https://explorer.blocknetcrypto.com/tx/%s\n", result.TxID)
	return nil
}

func (s *AttachSession) sendAll(ctx context.Context, address, memoText, memoHex, memoDisplay string) error {
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
	if memoHex != "" {
		recipient["memo_hex"] = memoHex
	} else if memoText != "" {
		recipient["memo_text"] = memoText
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
		Fee        uint64              `json:"fee"`
		Recipients []resolvedRecipient `json:"recipients"`
	}
	if err := json.Unmarshal(raw, &preview); err != nil {
		return fmt.Errorf("parse fee preview: %w", err)
	}

	var resolved resolvedRecipient
	if len(preview.Recipients) > 0 {
		resolved = preview.Recipients[0]
	}

	if preview.Fee >= total {
		return fmt.Errorf("balance too small to cover the fee (fee %s)", FormatAmount(preview.Fee))
	}
	amount := total - preview.Fee

	fmt.Printf("\n%s\n\n", SectionHead("Send", s.noColor))
	if resolved.ResolvedHandle != "" {
		s.printResolution(address, resolved)
		fmt.Println()
	}
	fmt.Printf("  Send all (%s) to %s?\n", FormatAmount(amount), address)
	fmt.Printf("  Fee:      %s\n", FormatAmount(preview.Fee))
	if resolved.ResolvedHandle != "" {
		fmt.Printf("  Address:  %s\n", resolved.ResolvedAddress)
	}
	if memoDisplay != "" {
		fmt.Printf("  Memo:     %s\n", memoDisplay)
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

	fmt.Printf("  Sent:     %s\n", result.TxID)
	fmt.Printf("  Explorer: https://explorer.blocknetcrypto.com/tx/%s\n", result.TxID)
	return nil
}

func (s *AttachSession) cmdSign() error {
	fmt.Printf("\n%s\n\n", SectionHead("Sign", s.noColor))
	fmt.Println("  Enter the text to sign, then press Enter")
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
	fmt.Printf("\n%s\n\n", SectionHead("Verify", s.noColor))
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
	if signature == "" {
		return fmt.Errorf("signature cannot be empty")
	}

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
		fmt.Printf("\n%s\n", SectionHead("Signature is VALID", s.noColor))
	} else {
		fmt.Printf("\n%s\n", ErrorHead("Signature is INVALID", s.noColor))
	}
	return nil
}

func (s *AttachSession) cmdHistory() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res := s.fetchAll(ctx, "/api/wallet/history", "/api/wallet/sends?order=asc&limit=500")

	// Incoming: owned outputs.
	rawIn, err := res[0].raw, res[0].err
	if err != nil {
		return s.handleAPIError(err)
	}
	var inResp struct {
		Outputs []struct {
			TxID        string `json:"txid"`
			Amount      uint64 `json:"amount"`
			BlockHeight uint64 `json:"block_height"`
			IsCoinbase  bool   `json:"is_coinbase"`
			Spent       bool   `json:"spent"`
			MemoHex     string `json:"memo_hex"`
		} `json:"outputs"`
	}
	json.Unmarshal(rawIn, &inResp)

	// Outgoing sends are recorded separately from owned outputs; merge them so
	// history shows OUT events too. Best-effort: a sends failure must not hide
	// the incoming history.
	var outResp struct {
		Sends []struct {
			TxID           string `json:"txid"`
			RecordedHeight uint64 `json:"recorded_height"`
			InMempool      bool   `json:"in_mempool"`
			TotalAmount    uint64 `json:"total_amount"`
			Recipients     []struct {
				MemoHex string `json:"memo_hex"`
			} `json:"recipients"`
		} `json:"sends"`
	}
	if res[1].err == nil {
		json.Unmarshal(res[1].raw, &outResp)
	}

	type event struct {
		height    uint64
		pending   bool
		direction string
		amount    uint64
		coinbase  bool
		txid      string
		memoHex   string
		spent     bool
	}

	var events []event
	for _, o := range inResp.Outputs {
		events = append(events, event{
			height: o.BlockHeight, direction: "IN", amount: o.Amount,
			coinbase: o.IsCoinbase, txid: o.TxID, memoHex: o.MemoHex, spent: o.Spent,
		})
	}
	for _, o := range outResp.Sends {
		memo := ""
		if len(o.Recipients) > 0 {
			memo = o.Recipients[0].MemoHex
		}
		events = append(events, event{
			height: o.RecordedHeight, pending: o.InMempool, direction: "OUT",
			amount: o.TotalAmount, txid: o.TxID, memoHex: memo,
		})
	}

	fmt.Printf("\n%s\n\n", SectionHead("History", s.noColor))
	if len(events) == 0 {
		fmt.Println("  No transactions yet")
		return nil
	}

	// Oldest first (block height is monotonic with time); pending (mempool)
	// sends sort to the end.
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].pending != events[j].pending {
			return !events[i].pending
		}
		return events[i].height < events[j].height
	})

	green, _, amber, pink, _, reset := Palette(s.noColor)

	// Column widths come from the rows so long heights and amounts line up.
	whereW, amountW := 0, 0
	where := func(e event) string {
		if e.pending {
			return "mempool"
		}
		return "block " + strconv.FormatUint(e.height, 10)
	}
	for _, e := range events {
		whereW = max(whereW, len(where(e)))
		amountW = max(amountW, len(FormatAmount(e.amount)))
	}

	for _, e := range events {
		color := green
		if e.direction == "OUT" {
			color = pink
			if e.pending {
				color = amber
			}
		}
		extras := ""
		if e.direction == "IN" {
			if e.coinbase {
				extras = "  coinbase"
			}
			if e.spent {
				extras += "  (spent)"
			}
		}
		fmt.Printf("  %s  %s  %s  %s%s\n",
			PadRight(where(e), whereW), PadRight(color+e.direction+reset, 3),
			PadLeft(FormatAmount(e.amount), amountW), e.txid, extras)
		if m := MemoDisplay(e.memoHex); m != "" {
			fmt.Printf("    Memo: %s\n", m)
		}
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
			MemoHex       string `json:"memo_hex,omitempty"`
		} `json:"outputs"`
	}
	json.Unmarshal(raw, &resp)

	filter := "all"
	detailIndex := -1
	showByTx := false
	var txFilter string
	txIndexFilter := -1

	const usage = "outputs [spent|unspent|pending] [index]\n         outputs tx <txid>[:<index>]"
	usageErr := fmt.Errorf("usage: %s", usage)

	if len(args) > 0 {
		switch strings.ToLower(args[0]) {
		case "spent", "unspent", "pending":
			if err := ExtraArgs(args, 2, usage); err != nil {
				return err
			}
			filter = strings.ToLower(args[0])
			if len(args) == 2 {
				n, err := strconv.Atoi(args[1])
				if err != nil || n < 1 {
					return usageErr
				}
				detailIndex = n
			}
		case "tx":
			if len(args) < 2 {
				return usageErr
			}
			if err := ExtraArgs(args, 2, usage); err != nil {
				return err
			}
			parts := strings.SplitN(args[1], ":", 2)
			txFilter = strings.TrimSpace(parts[0])
			if !isHex64(txFilter) {
				return fmt.Errorf("txid must be 64 hex characters")
			}
			txFilter = strings.ToLower(txFilter)
			showByTx = true
			if len(parts) == 2 {
				n, err := strconv.Atoi(parts[1])
				if err != nil || n < 0 {
					return fmt.Errorf("invalid output index %q: use outputs tx <txid>:<index>", parts[1])
				}
				txIndexFilter = n
			}
		default:
			n, err := strconv.Atoi(args[0])
			if err != nil || n < 1 {
				return usageErr
			}
			if err := ExtraArgs(args, 1, usage); err != nil {
				return err
			}
			detailIndex = n
		}
	}

	green, _, amber, _, dim, reset := Palette(s.noColor)
	statusLabel := func(status string) string {
		switch status {
		case "unspent":
			return green + status + reset
		case "spent":
			return dim + status + reset
		case "pending":
			return amber + status + reset
		default:
			return status
		}
	}

	fmt.Printf("\n%s\n\n", SectionHead("Outputs", s.noColor))

	type entry struct {
		TxID, Status, Type, OneTimePub, Commitment, MemoHex string
		OutputIndex                                         int
		Amount, Confirmations, BlockHeight, SpentHeight     uint64
	}

	var filtered []entry
	for _, o := range resp.Outputs {
		if filter != "all" && o.Status != filter {
			continue
		}
		if showByTx {
			if !strings.EqualFold(o.TxID, txFilter) {
				continue
			}
			if txIndexFilter >= 0 && o.OutputIndex != txIndexFilter {
				continue
			}
		}
		filtered = append(filtered, entry{
			o.TxID, o.Status, o.Type, o.OneTimePub, o.Commitment, o.MemoHex,
			o.OutputIndex, o.Amount, o.Confirmations, o.BlockHeight, o.SpentHeight,
		})
	}

	if len(filtered) == 0 {
		if resp.SyncedHeight < resp.ChainHeight {
			fmt.Println("  No outputs found yet")
			fmt.Printf("  Wallet scan is still catching up (%d/%d)\n", resp.SyncedHeight, resp.ChainHeight)
			fmt.Println("  Try: sync")
		} else if showByTx {
			fmt.Println("  No outputs of this wallet in that transaction")
		} else if filter != "all" {
			fmt.Printf("  No %s outputs found\n", filter)
		} else {
			fmt.Println("  No outputs found in this wallet yet")
			fmt.Println("  Receive funds, then run sync if needed")
		}
		return nil
	}

	printDetail := func(pos int, o entry) {
		fmt.Printf("  #%d\n", pos)
		fmt.Printf("    Status:        %s\n", statusLabel(o.Status))
		fmt.Printf("    Amount:        %s\n", FormatAmount(o.Amount))
		fmt.Printf("    Type:          %s\n", o.Type)
		fmt.Printf("    Confirmations: %d\n", o.Confirmations)
		fmt.Printf("    Block:         %d\n", o.BlockHeight)
		fmt.Printf("    Tx Output:     %s:%d\n", o.TxID, o.OutputIndex)
		fmt.Printf("    One-Time Pub:  %s\n", o.OneTimePub)
		fmt.Printf("    Commitment:    %s\n", o.Commitment)
		if o.Status == "spent" && o.SpentHeight > 0 {
			fmt.Printf("    Spent Block:   %d\n", o.SpentHeight)
		}
		if m := MemoDisplay(o.MemoHex); m != "" {
			fmt.Printf("    Memo:          %s\n", m)
		}
	}

	if detailIndex > 0 {
		if detailIndex > len(filtered) {
			return fmt.Errorf("output %d is out of range (1 to %d)", detailIndex, len(filtered))
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

	numW := len(fmt.Sprintf("#%d", len(filtered)))
	typeW := 0
	for _, o := range filtered {
		typeW = max(typeW, len(o.Type))
	}
	indent := strings.Repeat(" ", numW+4)
	for i, o := range filtered {
		fmt.Printf("  %s  %s %s  Confirmations: %d\n", PadRight(fmt.Sprintf("#%d", i+1), numW),
			PadRight(statusLabel(o.Status), 8), PadRight(o.Type, typeW), o.Confirmations)
		fmt.Printf("%sAmount: %s\n", indent, FormatAmount(o.Amount))
		fmt.Printf("%sBlock:  %d  Tx: %s:%d\n", indent, o.BlockHeight, o.TxID, o.OutputIndex)
	}
	return nil
}

func (s *AttachSession) cmdSeed() error {
	_, _, amber, _, _, rst := Palette(s.noColor)
	fmt.Printf("\n%s\n\n", WarnHead("Seed", s.noColor))
	fmt.Printf("  %sWARNING: Your recovery seed controls all funds.%s\n", amber, rst)
	fmt.Printf("  %sAnyone with this seed can steal your coins.%s\n", amber, rst)
	fmt.Printf("  %sNever share it. Never enter it online.%s\n", amber, rst)
	fmt.Print("\n  Show recovery seed? [y/N]: ")

	confirm, _ := s.reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		fmt.Println("  Cancelled")
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
	fmt.Println("  Write these words down and store them safely")
	fmt.Println("  Recover with: import (option 1: recovery seed)")
	return nil
}

func (s *AttachSession) cmdImport() error {
	fmt.Printf("\n%s\n\n", SectionHead("Import", s.noColor))
	fmt.Println("  1) 12-word recovery seed")
	fmt.Println("  2) Spend key and view key (hex private keys)")
	fmt.Println("  3) View-only (spend public key and view private key)")
	fmt.Print("\n  Choose [1/2/3]: ")

	choiceLine, err := s.reader.ReadString('\n')
	if err != nil {
		return err
	}
	choice := strings.ToLower(strings.TrimSpace(choiceLine))

	switch choice {
	case "1", "seed", "mnemonic", "12":
		return s.importFromMnemonic()
	case "2", "keys", "key", "spend":
		return s.importFromKeys()
	case "3", "view", "viewonly", "view-only", "watch":
		return s.importViewOnly()
	default:
		return fmt.Errorf("invalid import type: choose 1, 2 or 3")
	}
}

func (s *AttachSession) readHexKey(prompt string) (string, error) {
	key, err := s.readPassword(prompt)
	if err != nil {
		return "", err
	}
	key = strings.ToLower(strings.TrimSpace(key))
	if b, err := hex.DecodeString(key); err != nil || len(b) != 32 {
		return "", fmt.Errorf("invalid key: expected 64 hex chars")
	}
	return key, nil
}

func (s *AttachSession) importFromKeys() error {
	spendPriv, err := s.readHexKey("  Spend private key (64 hex chars): ")
	if err != nil {
		return err
	}
	viewPriv, err := s.readHexKey("  View private key (64 hex chars): ")
	if err != nil {
		return err
	}
	return s.importWallet(map[string]string{"spend_priv": spendPriv, "view_priv": viewPriv})
}

func (s *AttachSession) importViewOnly() error {
	fmt.Print("  Spend public key (64 hex chars): ")
	line, err := s.reader.ReadString('\n')
	if err != nil {
		return err
	}
	spendPub := strings.ToLower(strings.TrimSpace(line))
	if b, err := hex.DecodeString(spendPub); err != nil || len(b) != 32 {
		return fmt.Errorf("invalid spend public key: expected 64 hex chars")
	}
	viewPriv, err := s.readHexKey("  View private key (64 hex chars): ")
	if err != nil {
		return err
	}
	return s.importWallet(map[string]string{"spend_pub": spendPub, "view_priv": viewPriv})
}

func (s *AttachSession) importFromMnemonic() error {
	fmt.Println("  Input the 12 words of your seed:")
	fmt.Print("\n> ")

	line, err := s.reader.ReadString('\n')
	if err != nil {
		return err
	}
	mnemonic := strings.Join(strings.Fields(strings.ReplaceAll(strings.TrimSpace(line), ",", " ")), " ")
	return s.importWallet(map[string]string{"mnemonic": mnemonic})
}

func (s *AttachSession) importWallet(fields map[string]string) error {
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
	if len(password) < 3 {
		return fmt.Errorf("password must be at least 3 characters")
	}
	confirmPw, err := s.readPassword("  Confirm password: ")
	if err != nil {
		return err
	}
	if confirmPw != password {
		return fmt.Errorf("passwords do not match")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fields["password"] = password
	fields["filename"] = filename
	raw, err := s.client.Post(ctx, "/api/wallet/import", fields)
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		Address  string `json:"address"`
		Filename string `json:"filename"`
		ViewOnly bool   `json:"view_only"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("\n%s\n\n", SectionHead("Wallet Imported", s.noColor))
	fmt.Printf("  Name:    %s\n", resp.Filename)
	fmt.Printf("  Address: %s\n", resp.Address)
	if resp.ViewOnly {
		fmt.Printf("  Type:    %s\n", viewOnlyPhrase)
	}
	return nil
}

func (s *AttachSession) cmdViewKeys() error {
	fmt.Printf("\n%s\n\n", WarnHead("View Keys", s.noColor))

	_, _, amber, _, _, rst := Palette(s.noColor)
	fmt.Printf("  %sWARNING: Your view private key lets anyone see all incoming funds.%s\n", amber, rst)
	fmt.Printf("  %sNever share it unless you understand the implications.%s\n", amber, rst)
	fmt.Println()
	fmt.Println("  This shows your view keys and saves a wallet file that is")
	fmt.Printf("  %s\n", viewOnlyPhrase)
	fmt.Print("\n  Continue? [y/N]: ")

	confirm, _ := s.reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		fmt.Println("  Cancelled")
		return nil
	}

	password, err := s.readPassword("  Wallet password: ")
	if err != nil {
		return err
	}

	filePassword, err := s.readPassword("  New password for the view-only wallet file: ")
	if err != nil {
		return err
	}
	if len(filePassword) < 3 {
		return fmt.Errorf("file password must be at least 3 characters")
	}
	confirmPw, err := s.readPassword("  Confirm password: ")
	if err != nil {
		return err
	}
	if confirmPw != filePassword {
		return fmt.Errorf("passwords do not match")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := s.client.Post(ctx, "/api/wallet/viewkeys", map[string]any{
		"password":      password,
		"create_file":   true,
		"file_password": filePassword,
	})
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		SpendPub string `json:"spend_pub"`
		ViewPriv string `json:"view_priv"`
		ViewPub  string `json:"view_pub"`
		Created  bool   `json:"created"`
		Path     string `json:"path"`
		Address  string `json:"address"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("\n  Spend Public Key: %s\n", resp.SpendPub)
	fmt.Printf("  View Private Key: %s\n", resp.ViewPriv)
	fmt.Printf("  View Public Key:  %s\n", resp.ViewPub)

	if resp.Created {
		fmt.Printf("  Saved To:         %s\n", resp.Path)
		if resp.Address != "" {
			fmt.Printf("  Address:          %s\n", resp.Address)
		}
		fmt.Println()
		fmt.Println("  Copy that file to another machine and 'load' it with the file")
		fmt.Println("  password you just set to watch incoming funds there")
	}
	return nil
}

func (s *AttachSession) cmdProve(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: prove <txid>")
	}

	if err := ExtraArgs(args, 1, "prove <txid>"); err != nil {
		return err
	}
	txid := strings.ToLower(SanitizeInput(args[0]))
	if !isHex64(txid) {
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

	fmt.Printf("\n%s\n\n", SectionHead("Prove", s.noColor))
	fmt.Printf("  TxID:   %s\n", resp.TxID)
	fmt.Printf("  Tx Key: %s\n", resp.TxKey)
	fmt.Println()
	fmt.Println("  Share this tx key with the recipient so they can verify you sent the transaction")
	return nil
}

func (s *AttachSession) cmdLock() error {
	locked, err := s.coreLocked()
	if err != nil {
		return s.handleAPIError(err)
	}
	if locked {
		fmt.Printf("\n%s\n\n", SectionHead("Locked", s.noColor))
		fmt.Println("  Already locked")
		return nil
	}

	ctx, cancel := withPatience(defaultAPITimeout)
	defer cancel()

	if _, err := s.client.Post(ctx, "/api/wallet/lock", nil); err != nil {
		return s.handleAPIError(err)
	}

	s.locked = true
	fmt.Printf("\n%s\n", SectionHead("Locked", s.noColor))
	return nil
}

func (s *AttachSession) cmdUnlock() error {
	// Ask the core rather than trusting s.locked: another client may have
	// locked or unlocked the wallet since this session last looked.
	locked, err := s.coreLocked()
	if err != nil {
		return s.handleAPIError(err)
	}
	if !locked {
		fmt.Printf("\n%s\n\n", SectionHead("Unlocked", s.noColor))
		fmt.Println("  Already unlocked")
		return nil
	}

	password, err := s.readPassword("  Password: ")
	if err != nil {
		return err
	}

	ctx, cancel := withPatience(defaultAPITimeout)
	defer cancel()

	if _, err := s.client.Post(ctx, "/api/wallet/unlock", map[string]string{"password": password}); err != nil {
		return s.handleAPIError(err)
	}

	s.locked = false
	fmt.Printf("\n%s\n", SectionHead("Unlocked", s.noColor))
	return nil
}

func (s *AttachSession) cmdAudit() error {
	fmt.Printf("\n%s\n\n", SectionHead("Audit", s.noColor))
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

	fmt.Printf("  Total Outputs:     %d\n", resp.TotalOutputs)
	fmt.Printf("  Unique Key Images: %d\n", resp.UniqueKeyImages)
	if resp.FailedKeyImages > 0 {
		fmt.Printf("  Failed Key Images: %d\n", resp.FailedKeyImages)
	}

	green, _, amber, _, _, rst := Palette(s.noColor)
	if len(resp.DuplicateGroups) == 0 {
		fmt.Printf("\n  %s✓%s No duplicate key images found. Wallet is clean\n", green, rst)
		return nil
	}

	fmt.Printf("\n  %s!%s Duplicate key images found: %s\n", amber, rst, Plural(len(resp.DuplicateGroups), "group"))
	fmt.Printf("  %s!%s Burned outputs: %d (%s unspendable)\n", amber, rst, resp.BurnedOutputs, FormatAmount(resp.TotalBurned))

	for i, group := range resp.DuplicateGroups {
		fmt.Printf("\n  Group %d (key image %s)\n", i+1, group.KeyImage)
		fmt.Printf("    Burned: %s across %s\n", FormatAmount(group.BurnedAmount), Plural(group.UnspendableCount, "duplicate"))
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

func (s *AttachSession) cmdSync() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("\n%s\n\n", SectionHead("Sync", s.noColor))
	fmt.Println("  Scanning for wallet outputs...")

	raw, err := s.client.Post(ctx, "/api/wallet/sync", nil)
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		Status        string `json:"status"`
		SyncedHeight  uint64 `json:"synced_height"`
		ChainHeight   uint64 `json:"chain_height"`
		BlocksScanned int    `json:"blocks_scanned"`
		OutputsFound  int    `json:"outputs_found"`
		OutputsSpent  int    `json:"outputs_spent"`
	}
	json.Unmarshal(raw, &resp)

	if resp.Status == "already synced" {
		fmt.Printf("  Wallet is up to date at height %d\n", resp.SyncedHeight)
	} else {
		fmt.Printf("  Scanned %s to height %d\n", Plural(resp.BlocksScanned, "block"), resp.SyncedHeight)
		fmt.Printf("  Outputs found: %d\n", resp.OutputsFound)
		if resp.OutputsSpent > 0 {
			fmt.Printf("  Outputs spent: %d\n", resp.OutputsSpent)
		}
	}
	return nil
}
