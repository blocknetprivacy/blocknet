package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func (s *AttachSession) cmdStatus() error {
	ctx, cancel := withPatience(defaultAPITimeout)
	defer cancel()

	raw, err := s.client.Status(ctx)
	if err != nil {
		return s.handleAPIError(err)
	}

	var status struct {
		PeerID      string `json:"peer_id"`
		Peers       int    `json:"peers"`
		ChainHeight uint64 `json:"chain_height"`
		BestHash    string `json:"best_hash"`
		Syncing     bool   `json:"syncing"`
	}
	json.Unmarshal(raw, &status)

	fmt.Printf("\n%s\n", SectionHead("Node", s.noColor))
	fmt.Printf("  Peer ID:     %s\n", status.PeerID)
	fmt.Printf("  Peers:       %d\n", status.Peers)
	fmt.Printf("  Height:      %d\n", status.ChainHeight)
	fmt.Printf("  Best Hash:   %s\n", status.BestHash)
	fmt.Printf("  Syncing:     %v\n", status.Syncing)

	raw, err = s.client.Get(ctx, "/api/wallet/balance")
	if err == nil {
		var bal struct {
			Spendable      uint64 `json:"spendable"`
			Pending        uint64 `json:"pending"`
			OutputsTotal   int    `json:"outputs_total"`
			OutputsUnspent int    `json:"outputs_unspent"`
		}
		json.Unmarshal(raw, &bal)

		raw2, _ := s.client.Get(ctx, "/api/wallet/address")
		var addr struct {
			Address  string `json:"address"`
			ViewOnly bool   `json:"view_only"`
		}
		if raw2 != nil {
			json.Unmarshal(raw2, &addr)
		}

		walletType := "Full"
		if addr.ViewOnly {
			walletType = "View-Only (cannot spend)"
		}

		balStr := FormatAmount(bal.Spendable)
		if bal.Pending > 0 {
			balStr += fmt.Sprintf(" + %s pending", FormatAmount(bal.Pending))
		}

		fmt.Printf("\n%s\n", SectionHead("Wallet", s.noColor))
		fmt.Printf("  Type:        %s\n", walletType)
		fmt.Printf("  Balance:     %s\n", balStr)
		fmt.Printf("  Outputs:     %d unspent / %d total\n", bal.OutputsUnspent, bal.OutputsTotal)
		fmt.Printf("  Address:     %s\n", addr.Address)
	}
	return nil
}

func (s *AttachSession) cmdPeers() error {
	ctx, cancel := withPatience(defaultAPITimeout)
	defer cancel()

	raw, err := s.client.Get(ctx, "/api/peers")
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		Count int `json:"count"`
		Peers []struct {
			PeerID string   `json:"peer_id"`
			Addrs  []string `json:"addrs"`
		} `json:"peers"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("\n%s", SectionHead("Peers", s.noColor))
	if resp.Count == 0 {
		fmt.Println(" (0)")
		fmt.Println("  None connected")
	} else {
		fmt.Printf(" (%d)\n", resp.Count)
		for _, p := range resp.Peers {
			fmt.Printf("  %s\n", p.PeerID)
			for _, addr := range p.Addrs {
				fmt.Printf("    %s\n", addr)
			}
		}
	}

	raw, err = s.client.Get(ctx, "/api/peers/banned")
	if err == nil {
		var banned struct {
			Count int `json:"count"`
		}
		json.Unmarshal(raw, &banned)
		if banned.Count > 0 {
			fmt.Printf("\n  %d banned (use 'banned' to see details)\n", banned.Count)
		}
	}
	return nil
}

func (s *AttachSession) cmdBanned() error {
	ctx, cancel := withPatience(defaultAPITimeout)
	defer cancel()

	raw, err := s.client.Get(ctx, "/api/peers/banned")
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		Count  int `json:"count"`
		Banned []struct {
			PeerID    string   `json:"peer_id"`
			Addrs     []string `json:"addrs"`
			Reason    string   `json:"reason"`
			BanCount  int      `json:"ban_count"`
			Permanent bool     `json:"permanent"`
			ExpiresAt string   `json:"expires_at,omitempty"`
		} `json:"banned"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("\n%s", SectionHead("Banned", s.noColor))
	if resp.Count == 0 {
		fmt.Println(" (0)")
		fmt.Println("  None")
		return nil
	}

	fmt.Printf(" (%d)\n", resp.Count)
	for _, ban := range resp.Banned {
		durStr := "permanent"
		if !ban.Permanent && ban.ExpiresAt != "" {
			if t, err := time.Parse(time.RFC3339, ban.ExpiresAt); err == nil {
				remaining := time.Until(t).Round(time.Minute)
				durStr = fmt.Sprintf("expires in %s", remaining)
			}
		}
		fmt.Printf("  %s\n", ban.PeerID)
		for _, addr := range ban.Addrs {
			fmt.Printf("    addr:   %s\n", addr)
		}
		fmt.Printf("    reason: %s\n    count:  %dx, %s\n", ban.Reason, ban.BanCount, durStr)
	}
	return nil
}

func (s *AttachSession) cmdExportPeer() error {
	ctx, cancel := withPatience(defaultAPITimeout)
	defer cancel()

	raw, err := s.client.Get(ctx, "/api/peers")
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		Peers []struct {
			PeerID string   `json:"peer_id"`
			Addrs  []string `json:"addrs"`
		} `json:"peers"`
	}
	json.Unmarshal(raw, &resp)

	var lines []string
	for _, p := range resp.Peers {
		for _, addr := range p.Addrs {
			lines = append(lines, addr+"/p2p/"+p.PeerID)
		}
	}
	if len(lines) == 0 {
		return fmt.Errorf("no peers to export")
	}

	if err := os.WriteFile("peer.txt", []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		return fmt.Errorf("write peer.txt: %w", err)
	}

	fmt.Printf("\n%s\n", SectionHead("Export", s.noColor))
	fmt.Printf("  %d peer addresses written to peer.txt\n", len(lines))
	fmt.Println("  Share this file or its contents with other nodes.")
	return nil
}

func (s *AttachSession) cmdMining(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if len(args) == 0 {
		raw, err := s.client.Get(ctx, "/api/mining")
		if err != nil {
			return s.handleAPIError(err)
		}

		var resp struct {
			Running   bool    `json:"running"`
			Threads   int     `json:"threads"`
			Hashrate  float64 `json:"hashrate,omitempty"`
			HashCount uint64  `json:"hash_count,omitempty"`
			StartedAt string  `json:"started_at,omitempty"`
		}
		json.Unmarshal(raw, &resp)

		if resp.Running {
			elapsed := ""
			if resp.StartedAt != "" {
				if t, err := time.Parse(time.RFC3339, resp.StartedAt); err == nil {
					elapsed = time.Since(t).Round(time.Second).String()
				}
			}
			fmt.Printf("\n%s — active", SectionHead("Mining", s.noColor))
			if elapsed != "" {
				fmt.Printf(" (%s)", elapsed)
			}
			fmt.Println()
			fmt.Printf("  Hashrate:     %.2f H/s\n", resp.Hashrate)
			fmt.Printf("  Total hashes: %d\n", resp.HashCount)
		} else {
			fmt.Printf("\n%s — stopped\n", SectionHead("Mining", s.noColor))
		}
		return nil
	}

	switch args[0] {
	case "start":
		fmt.Printf("\n%s\n", SectionHead("Mining", s.noColor))
		_, err := s.client.Post(ctx, "/api/mining/start", nil)
		if err != nil {
			if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == 409 {
				fmt.Println("  Already running")
				return nil
			}
			return s.handleAPIError(err)
		}
		fmt.Println("  Started")

	case "stop":
		fmt.Printf("\n%s\n", SectionHead("Mining", s.noColor))
		_, err := s.client.Post(ctx, "/api/mining/stop", nil)
		if err != nil {
			if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == 409 {
				fmt.Println("  Not running")
				return nil
			}
			return s.handleAPIError(err)
		}
		fmt.Println("  Stopped")

	case "threads", "thread", "t", "thrads", "thrad":
		fmt.Printf("\n%s\n", SectionHead("Mining", s.noColor))
		if len(args) < 2 {
			raw, err := s.client.Get(ctx, "/api/mining")
			if err != nil {
				return s.handleAPIError(err)
			}
			var resp struct {
				Threads int `json:"threads"`
			}
			json.Unmarshal(raw, &resp)
			fmt.Printf("  Threads: %d\n", resp.Threads)
			return nil
		}
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 1 {
			return fmt.Errorf("usage: mining threads <N> (N >= 1)")
		}
		_, err = s.client.Post(ctx, "/api/mining/threads", map[string]int{"threads": n})
		if err != nil {
			return s.handleAPIError(err)
		}
		fmt.Printf("  Threads set to %d (~%dGB RAM)\n", n, n*2)

	default:
		return fmt.Errorf("usage: mining [start|stop|threads <N>]")
	}
	return nil
}

func (s *AttachSession) cmdCertify() error {
	fmt.Printf("\n%s\n", SectionHead("Certify", s.noColor))
	fmt.Println("  Verifying chain integrity (difficulty, timestamps, linkage)...")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	raw, err := s.client.Get(ctx, "/api/certify")
	if err != nil {
		return s.handleAPIError(err)
	}

	var resp struct {
		Height     uint64 `json:"height"`
		Clean      bool   `json:"clean"`
		Violations []struct {
			Height  uint64 `json:"height"`
			Message string `json:"message"`
		} `json:"violations"`
	}
	json.Unmarshal(raw, &resp)

	fmt.Printf("  Chain height: %d\n", resp.Height)

	if resp.Clean {
		green := "\033[38;2;170;255;0m"
		rst := "\033[0m"
		if s.noColor {
			green, rst = "", ""
		}
		fmt.Printf("  %sChain is clean. No violations found.%s\n", green, rst)
		return nil
	}

	amber := "\033[38;2;255;170;0m"
	rst := "\033[0m"
	if s.noColor {
		amber, rst = "", ""
	}

	fmt.Printf("\n  %s%d violation(s) found:%s\n", amber, len(resp.Violations), rst)
	for _, v := range resp.Violations {
		fmt.Printf("    block %-8d %s\n", v.Height, v.Message)
	}
	return nil
}

func (s *AttachSession) cmdPurge() error {
	fmt.Printf("\n%s\n", ErrorHead("Purge", s.noColor))
	fmt.Println("  This will delete all blockchain data.")
	fmt.Println("  Your wallet will NOT be deleted.")
	fmt.Println("  This action CANNOT be undone.")
	fmt.Print("\n  Confirm purge? [y/N]: ")

	confirm, _ := s.reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		fmt.Println("  Cancelled")
		return nil
	}

	password, err := s.readPassword("  Password: ")
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = s.client.Post(ctx, "/api/purge", map[string]any{
		"password": password,
		"confirm":  true,
	})
	if err != nil {
		return s.handleAPIError(err)
	}

	fmt.Println("  Blockchain data purged. Core will shut down.")
	return fmt.Errorf("quit")
}

func (s *AttachSession) cmdVersion() {
	fmt.Printf("\n%s\n", SectionHead("Version "+Version, s.noColor))
}

func (s *AttachSession) cmdAbout() {
	fmt.Printf("\n%s\n", SectionHead("About", s.noColor))
	fmt.Printf("  Blocknet v%s\n", Version)
	fmt.Println("  Zero-knowledge money. Made in USA.")
	fmt.Println()
	fmt.Println("  BSD 3-Clause License")
	fmt.Println("  Copyright (c) 2026, Blocknet Privacy")
	fmt.Println()
	fmt.Println("  https://blocknetcrypto.com")
	fmt.Println("  https://explorer.blocknetcrypto.com")
	fmt.Println("  https://github.com/blocknetprivacy")
}

func (s *AttachSession) cmdLicense() {
	fmt.Printf("\n%s\n", SectionHead("License", s.noColor))
	fmt.Println("  BSD 3-Clause License")
	fmt.Println()
	fmt.Println("  Copyright (c) 2026, Blocknet")
	fmt.Println("  All rights reserved.")
	fmt.Println()
	fmt.Println("  Redistribution and use in source and binary forms, with or without")
	fmt.Println("  modification, are permitted provided that the following conditions are met:")
	fmt.Println()
	fmt.Println("  1. Redistributions of source code must retain the above copyright notice,")
	fmt.Println("     this list of conditions and the following disclaimer.")
	fmt.Println()
	fmt.Println("  2. Redistributions in binary form must reproduce the above copyright notice,")
	fmt.Println("     this list of conditions and the following disclaimer in the documentation")
	fmt.Println("     and/or other materials provided with the distribution.")
	fmt.Println()
	fmt.Println("  3. Neither the name of the copyright holder nor the names of its contributors")
	fmt.Println("     may be used to endorse or promote products derived from this software")
	fmt.Println("     without specific prior written permission.")
	fmt.Println()
	fmt.Println("  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"")
	fmt.Println("  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE")
	fmt.Println("  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE")
	fmt.Println("  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE")
	fmt.Println("  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL")
	fmt.Println("  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR")
	fmt.Println("  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER")
	fmt.Println("  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,")
	fmt.Println("  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE")
	fmt.Println("  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.")
}

func (s *AttachSession) cmdExplore(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: explore <height|hash|mempool>")
	}

	target := args[0]

	if strings.ToLower(target) == "mempool" {
		return s.exploreMempool()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := strconv.ParseUint(target, 10, 64); err == nil {
		return s.exploreBlock(ctx, target)
	}

	if isHex64(target) {
		raw, err := s.client.Get(ctx, "/api/block/"+target)
		if err == nil {
			return s.printBlock(raw)
		}
		if apiErr, ok := err.(*APIError); !ok || apiErr.StatusCode != 404 {
			return s.handleAPIError(err)
		}

		raw, err = s.client.Get(ctx, "/api/tx/"+target)
		if err == nil {
			return s.printTx(target, raw)
		}
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == 404 {
			return fmt.Errorf("no block or transaction found for %s", target)
		}
		return s.handleAPIError(err)
	}

	return fmt.Errorf("expected a block height, 64-char hex hash, or 'mempool'")
}

func (s *AttachSession) exploreBlock(ctx context.Context, id string) error {
	raw, err := s.client.Get(ctx, "/api/block/"+id)
	if err != nil {
		return s.handleAPIError(err)
	}
	return s.printBlock(raw)
}

func (s *AttachSession) printBlock(raw json.RawMessage) error {
	var block struct {
		Height       uint64 `json:"height"`
		Hash         string `json:"hash"`
		PrevHash     string `json:"prev_hash"`
		MerkleRoot   string `json:"merkle_root"`
		Timestamp    int64  `json:"timestamp"`
		Difficulty   uint64 `json:"difficulty"`
		Nonce        uint64 `json:"nonce"`
		TxCount      int    `json:"tx_count"`
		Transactions []struct {
			Hash       string `json:"hash"`
			IsCoinbase bool   `json:"is_coinbase"`
			Inputs     int    `json:"inputs"`
			Outputs    int    `json:"outputs"`
			Fee        uint64 `json:"fee"`
		} `json:"transactions"`
		Confirmations uint64 `json:"confirmations"`
		Reward        uint64 `json:"reward"`
	}
	if err := json.Unmarshal(raw, &block); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	green := "\033[38;2;170;255;0m"
	dim := "\033[2m"
	reset := "\033[0m"
	if s.noColor {
		green, dim, reset = "", "", ""
	}

	fmt.Printf("\n%s\n", SectionHead(fmt.Sprintf("Block %d", block.Height), s.noColor))
	fmt.Printf("  Hash:          %s\n", block.Hash)
	fmt.Printf("  Previous:      %s\n", block.PrevHash)
	fmt.Printf("  Merkle Root:   %s\n", block.MerkleRoot)
	fmt.Printf("  Time:          %s\n", time.Unix(block.Timestamp, 0).UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  Difficulty:    %d\n", block.Difficulty)
	fmt.Printf("  Nonce:         %d\n", block.Nonce)
	fmt.Printf("  Reward:        %s\n", FormatAmount(block.Reward))
	fmt.Printf("  Confirmations: %d\n", block.Confirmations)

	if len(block.Transactions) > 0 {
		fmt.Printf("\n  Transactions (%d):\n", block.TxCount)
		for _, tx := range block.Transactions {
			tag := "  "
			if tx.IsCoinbase {
				tag = green + "cb" + reset
			}
			feeStr := FormatAmount(tx.Fee)
			if tx.Fee == 0 {
				feeStr = dim + "—" + reset
			}
			fmt.Printf("    %s  %s  %d in → %d out  fee: %s\n",
				tag, tx.Hash, tx.Inputs, tx.Outputs, feeStr)
		}
	}

	fmt.Printf("\n  https://explorer.blocknetcrypto.com/block/%d\n", block.Height)
	return nil
}

func (s *AttachSession) printTx(hash string, raw json.RawMessage) error {
	var resp struct {
		Tx struct {
			Inputs  []json.RawMessage `json:"inputs"`
			Outputs []json.RawMessage `json:"outputs"`
			Fee     uint64            `json:"fee"`
		} `json:"tx"`
		BlockHeight   uint64 `json:"block_height"`
		Confirmations uint64 `json:"confirmations"`
		InMempool     bool   `json:"in_mempool"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	green := "\033[38;2;170;255;0m"
	amber := "\033[38;2;255;170;0m"
	reset := "\033[0m"
	if s.noColor {
		green, amber, reset = "", "", ""
	}

	fmt.Printf("\n%s\n", SectionHead("Transaction", s.noColor))
	fmt.Printf("  Hash:          %s\n", hash)

	if resp.InMempool {
		fmt.Printf("  Status:        %sunconfirmed%s (in mempool)\n", amber, reset)
	} else {
		fmt.Printf("  Status:        %sconfirmed%s (block %d)\n", green, reset, resp.BlockHeight)
	}

	fmt.Printf("  Confirmations: %d\n", resp.Confirmations)
	fmt.Printf("  Fee:           %s\n", FormatAmount(resp.Tx.Fee))
	fmt.Printf("  Inputs:        %d\n", len(resp.Tx.Inputs))
	fmt.Printf("  Outputs:       %d\n", len(resp.Tx.Outputs))

	if !resp.InMempool {
		fmt.Printf("\n  https://explorer.blocknetcrypto.com/tx/%s\n", hash)
	}
	return nil
}

func (s *AttachSession) exploreMempool() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := s.client.Get(ctx, "/api/mempool")
	if err != nil {
		return s.handleAPIError(err)
	}

	var stats struct {
		Count     int     `json:"count"`
		SizeBytes int64   `json:"size_bytes"`
		MinFee    uint64  `json:"min_fee"`
		MaxFee    uint64  `json:"max_fee"`
		AvgFee    float64 `json:"avg_fee"`
	}
	if err := json.Unmarshal(raw, &stats); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	fmt.Printf("\n%s\n", SectionHead("Mempool", s.noColor))

	if stats.Count == 0 {
		fmt.Println("  Empty — no pending transactions")
		return nil
	}

	fmt.Printf("  Transactions: %d\n", stats.Count)
	fmt.Printf("  Size:         %s\n", formatBytes(stats.SizeBytes))
	fmt.Printf("  Fee (min):    %s\n", FormatAmount(stats.MinFee))
	fmt.Printf("  Fee (max):    %s\n", FormatAmount(stats.MaxFee))
	fmt.Printf("  Fee (avg):    %s\n", FormatAmount(uint64(stats.AvgFee)))

	rawTxs, err := s.client.Get(ctx, "/api/mempool/txs")
	if err != nil {
		return nil
	}

	var txs []struct {
		Inputs  []json.RawMessage `json:"inputs"`
		Outputs []json.RawMessage `json:"outputs"`
		Fee     uint64            `json:"fee"`
	}
	if err := json.Unmarshal(rawTxs, &txs); err != nil || len(txs) == 0 {
		return nil
	}

	fmt.Printf("\n  Pending:\n")
	limit := len(txs)
	if limit > 25 {
		limit = 25
	}
	for i := 0; i < limit; i++ {
		tx := txs[i]
		fmt.Printf("    %d)  %d in → %d out  fee: %s\n",
			i+1, len(tx.Inputs), len(tx.Outputs), FormatAmount(tx.Fee))
	}
	if len(txs) > 25 {
		fmt.Printf("    ... and %d more\n", len(txs)-25)
	}
	return nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

