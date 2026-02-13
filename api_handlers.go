package main

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"blocknet/wallet"
)

// ============================================================================
// Public handlers (no wallet needed)
// ============================================================================

// handleStatus returns daemon stats.
func (s *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.daemon.Stats())
}

// handleBlock returns a block by hash (hex) or height (integer).
// GET /api/block/{id}
func (s *APIServer) handleBlock(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing block id")
		return
	}

	chain := s.daemon.Chain()
	var block *Block

	// Try as height first
	if height, err := strconv.ParseUint(id, 10, 64); err == nil {
		block = chain.GetBlockByHeight(height)
	} else if len(id) == 64 {
		// Try as hex hash
		hashBytes, err := hex.DecodeString(id)
		if err != nil || len(hashBytes) != 32 {
			writeError(w, http.StatusBadRequest, "invalid block hash")
			return
		}
		var hash [32]byte
		copy(hash[:], hashBytes)
		block = chain.GetBlock(hash)
	} else {
		writeError(w, http.StatusBadRequest, "id must be a height or 64-char hex hash")
		return
	}

	if block == nil {
		writeError(w, http.StatusNotFound, "block not found")
		return
	}

	writeJSON(w, http.StatusOK, blockToJSON(block, chain.Height()))
}

// handleTx returns a transaction by hash (searches chain then mempool).
// GET /api/tx/{hash}
func (s *APIServer) handleTx(w http.ResponseWriter, r *http.Request) {
	hashStr := r.PathValue("hash")
	if len(hashStr) != 64 {
		writeError(w, http.StatusBadRequest, "hash must be 64 hex characters")
		return
	}

	hashBytes, err := hex.DecodeString(hashStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid hex hash")
		return
	}
	var txID [32]byte
	copy(txID[:], hashBytes)

	// Check mempool first (fast)
	if tx, ok := s.daemon.Mempool().GetTransaction(txID); ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"tx":            tx,
			"confirmations": 0,
			"in_mempool":    true,
		})
		return
	}

	// Search chain (slow — scans blocks from tip backwards)
	tx, blockHeight, found := s.findChainTx(hashStr)
	if !found {
		writeError(w, http.StatusNotFound, "transaction not found")
		return
	}

	confirmations := s.daemon.Chain().Height() - blockHeight + 1
	writeJSON(w, http.StatusOK, map[string]any{
		"tx":            tx,
		"block_height":  blockHeight,
		"confirmations": confirmations,
		"in_mempool":    false,
	})
}

// handleMempool returns mempool stats.
// GET /api/mempool
func (s *APIServer) handleMempool(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.daemon.Mempool().Stats())
}

// handlePeers returns connected peers.
// GET /api/peers
func (s *APIServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	peers := s.daemon.Node().Peers()
	ids := make([]string, len(peers))
	for i, p := range peers {
		ids[i] = p.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(peers),
		"peers": ids,
	})
}

// handleBannedPeers returns banned peers.
// GET /api/peers/banned
func (s *APIServer) handleBannedPeers(w http.ResponseWriter, r *http.Request) {
	bans := s.daemon.Node().GetBannedPeers()

	type banEntry struct {
		PeerID    string `json:"peer_id"`
		Reason    string `json:"reason"`
		BanCount  int    `json:"ban_count"`
		Permanent bool   `json:"permanent"`
		ExpiresAt string `json:"expires_at,omitempty"`
	}

	entries := make([]banEntry, len(bans))
	for i, b := range bans {
		entry := banEntry{
			PeerID:    b.PeerID.String(),
			Reason:    b.Reason,
			BanCount:  b.BanCount,
			Permanent: b.Permanent,
		}
		if !b.Permanent {
			entry.ExpiresAt = b.ExpiresAt.Format(time.RFC3339)
		}
		entries[i] = entry
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(entries),
		"banned": entries,
	})
}

// ============================================================================
// Wallet handlers (require loaded + unlocked wallet)
// ============================================================================

// handleBalance returns wallet balance breakdown.
// GET /api/wallet/balance
func (s *APIServer) handleBalance(w http.ResponseWriter, r *http.Request) {
	if !s.requireWallet(w, r) {
		return
	}

	height := s.daemon.Chain().Height()
	total, unspent := s.wallet.OutputCount()

	writeJSON(w, http.StatusOK, map[string]any{
		"spendable":       s.wallet.SpendableBalance(height),
		"pending":         s.wallet.PendingBalance(height),
		"total":           s.wallet.Balance(),
		"outputs_total":   total,
		"outputs_unspent": unspent,
		"chain_height":    height,
	})
}

// handleAddress returns the wallet's stealth address.
// GET /api/wallet/address
func (s *APIServer) handleAddress(w http.ResponseWriter, r *http.Request) {
	if !s.requireWallet(w, r) {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"address":   s.wallet.Address(),
		"view_only": s.wallet.IsViewOnly(),
	})
}

// handleHistory returns wallet output history.
// GET /api/wallet/history
func (s *APIServer) handleHistory(w http.ResponseWriter, r *http.Request) {
	if !s.requireWallet(w, r) {
		return
	}

	outputs := s.wallet.AllOutputs()

	type outputEntry struct {
		TxID        string `json:"txid"`
		OutputIndex int    `json:"output_index"`
		Amount      uint64 `json:"amount"`
		BlockHeight uint64 `json:"block_height"`
		IsCoinbase  bool   `json:"is_coinbase"`
		Spent       bool   `json:"spent"`
		SpentHeight uint64 `json:"spent_height,omitempty"`
		MemoHex     string `json:"memo_hex,omitempty"`
	}

	entries := make([]outputEntry, len(outputs))
	for i, out := range outputs {
		entries[i] = outputEntry{
			TxID:        fmt.Sprintf("%x", out.TxID),
			OutputIndex: out.OutputIndex,
			Amount:      out.Amount,
			BlockHeight: out.BlockHeight,
			IsCoinbase:  out.IsCoinbase,
			Spent:       out.Spent,
			SpentHeight: out.SpentHeight,
		}
		if len(out.Memo) > 0 {
			entries[i].MemoHex = hex.EncodeToString(out.Memo)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(entries),
		"outputs": entries,
	})
}

// handleSend builds and broadcasts a transaction.
// POST /api/wallet/send
func (s *APIServer) handleSend(w http.ResponseWriter, r *http.Request) {
	if !s.requireWallet(w, r) {
		return
	}
	if s.wallet.IsViewOnly() {
		writeError(w, http.StatusForbidden, "view-only wallet cannot send")
		return
	}

	var req struct {
		Address  string `json:"address"`
		Amount   uint64 `json:"amount"` // atomic units
		MemoText string `json:"memo_text"`
		MemoHex  string `json:"memo_hex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate address
	addr := sanitizeInput(req.Address)
	spendPub, viewPub, err := wallet.ParseAddress(addr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid address: "+err.Error())
		return
	}

	// Validate amount
	if req.Amount == 0 {
		writeError(w, http.StatusBadRequest, "amount must be greater than 0")
		return
	}

	// Check spendable balance
	height := s.daemon.Chain().Height()
	spendable := s.wallet.SpendableBalance(height)
	if spendable < req.Amount {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("insufficient spendable balance: have %d, need %d", spendable, req.Amount))
		return
	}

	// Build transaction
	recipient := wallet.Recipient{
		SpendPubKey: spendPub,
		ViewPubKey:  viewPub,
		Amount:      req.Amount,
	}

	var memo []byte
	if req.MemoText != "" && req.MemoHex != "" {
		writeError(w, http.StatusBadRequest, "provide either memo_text or memo_hex, not both")
		return
	}
	if req.MemoHex != "" {
		decoded, err := hex.DecodeString(req.MemoHex)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid memo_hex")
			return
		}
		memo = decoded
	} else if req.MemoText != "" {
		memo = []byte(req.MemoText)
	}
	if len(memo) > wallet.MemoSize-4 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("memo too long: max %d bytes", wallet.MemoSize-4))
		return
	}
	recipient.Memo = memo

	builder := s.createTxBuilder()
	result, err := builder.Transfer([]wallet.Recipient{recipient}, 1000, height)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build transaction: "+err.Error())
		return
	}

	// Submit via Dandelion++
	if err := s.daemon.SubmitTransaction(result.TxData); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to submit transaction: "+err.Error())
		return
	}

	// Mark outputs as spent
	for _, spent := range result.SpentOutputs {
		s.wallet.MarkSpent(spent.OneTimePubKey, height)
	}

	// Record send for history
	s.wallet.RecordSend(&wallet.SendRecord{
		TxID:        result.TxID,
		Timestamp:   time.Now().Unix(),
		Recipient:   addr,
		Amount:      req.Amount,
		Fee:         result.Fee,
		BlockHeight: height,
		Memo:        memo,
	})
	if err := s.wallet.Save(); err != nil {
		log.Printf("Warning: wallet persistence failed after send %x: %v", result.TxID, err)
	}

	resp := map[string]any{
		"txid":   fmt.Sprintf("%x", result.TxID),
		"fee":    result.Fee,
		"change": result.Change,
	}
	if len(memo) > 0 {
		resp["memo_hex"] = hex.EncodeToString(memo)
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleLock locks the wallet.
// POST /api/wallet/lock
func (s *APIServer) handleLock(w http.ResponseWriter, r *http.Request) {
	if s.wallet == nil {
		writeError(w, http.StatusServiceUnavailable, "no wallet loaded")
		return
	}

	s.mu.Lock()
	s.locked = true
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"locked": true})
}

// handleUnlock unlocks the wallet.
// POST /api/wallet/unlock
func (s *APIServer) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if s.wallet == nil {
		writeError(w, http.StatusServiceUnavailable, "no wallet loaded")
		return
	}

	ip := clientIP(r)
	if wait, lockedUntil := s.unlockAttempts.precheck(ip); !lockedUntil.IsZero() {
		retryAfter := int(time.Until(lockedUntil).Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeError(w, http.StatusTooManyRequests, "too many unlock attempts; try again later")
		return
	} else if wait > 0 {
		retryAfter := int(wait.Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeError(w, http.StatusTooManyRequests, "unlock backoff active; retry later")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.Password), s.password) != 1 {
		delay, lockedUntil := s.unlockAttempts.recordFailure(ip)
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
			}
		}
		if !lockedUntil.IsZero() {
			retryAfter := int(time.Until(lockedUntil).Seconds())
			if retryAfter < 1 {
				retryAfter = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeError(w, http.StatusTooManyRequests, "too many unlock attempts; try again later")
			return
		}
		writeError(w, http.StatusUnauthorized, "incorrect password")
		return
	}

	s.unlockAttempts.recordSuccess(ip)

	s.mu.Lock()
	s.locked = false
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"locked": false})
}

// handleLoadWallet loads (or creates) a wallet at runtime.
// Used in daemon mode where the app starts without a wallet.
// POST /api/wallet/load
func (s *APIServer) handleLoadWallet(w http.ResponseWriter, r *http.Request) {
	if s.wallet != nil {
		writeError(w, http.StatusConflict, "wallet already loaded")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Password) < 3 {
		writeError(w, http.StatusBadRequest, "password must be at least 3 characters")
		return
	}

	password := []byte(req.Password)
	wl, err := wallet.LoadOrCreateWallet(s.cli.walletFile, password, defaultWalletConfig())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load wallet: "+err.Error())
		return
	}

	scanner := wallet.NewScanner(wl, defaultScannerConfig())

	// Point miner rewards at this wallet
	s.daemon.Miner().SetRewardKeys(wl.Keys().SpendPubKey, wl.Keys().ViewPubKey)

	// Handle chain-ahead-of-wallet (chain was reset while wallet was offline)
	chainHeight := s.daemon.Chain().Height()
	walletHeight := wl.SyncedHeight()
	if walletHeight > chainHeight {
		if removed := wl.RewindToHeight(chainHeight); removed > 0 {
			if err := wl.Save(); err != nil {
				writeError(w, http.StatusInternalServerError, "wallet rewind persistence failed: "+err.Error())
				return
			}
		}
	}

	// Catch up on blocks that arrived before the wallet was loaded
	if walletHeight < chainHeight {
		for h := walletHeight + 1; h <= chainHeight; h++ {
			block := s.daemon.Chain().GetBlockByHeight(h)
			if block == nil {
				break
			}
			scanner.ScanBlock(blockToScanData(block))
		}
		wl.SetSyncedHeight(chainHeight)
		if err := wl.Save(); err != nil {
			writeError(w, http.StatusInternalServerError, "wallet sync persistence failed: "+err.Error())
			return
		}
	}

	// Publish to API server
	s.wallet = wl
	s.scanner = scanner
	s.password = password

	// Publish to CLI (for autoScanBlocks / shutdown)
	s.cli.mu.Lock()
	s.cli.wallet = wl
	s.cli.scanner = scanner
	s.cli.password = password
	s.cli.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"loaded":  true,
		"address": wl.Address(),
	})
}

// handleImportWallet creates a new wallet from a BIP39 recovery seed.
// POST /api/wallet/import
func (s *APIServer) handleImportWallet(w http.ResponseWriter, r *http.Request) {
	if s.wallet != nil {
		writeError(w, http.StatusConflict, "wallet already loaded")
		return
	}

	var req struct {
		Mnemonic string `json:"mnemonic"`
		Password string `json:"password"`
		Filename string `json:"filename"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Mnemonic == "" {
		writeError(w, http.StatusBadRequest, "mnemonic is required")
		return
	}
	if len(req.Password) < 3 {
		writeError(w, http.StatusBadRequest, "password must be at least 3 characters")
		return
	}
	if !wallet.ValidateMnemonic(req.Mnemonic) {
		writeError(w, http.StatusBadRequest, "invalid mnemonic phrase")
		return
	}

	// Resolve wallet path: basename only, same directory as configured --wallet path
	walletPath := s.cli.walletFile
	if req.Filename != "" {
		base := filepath.Base(req.Filename)
		if base == "." || base == "/" {
			writeError(w, http.StatusBadRequest, "invalid filename")
			return
		}
		walletPath = filepath.Join(filepath.Dir(s.cli.walletFile), base)
	}

	// Don't overwrite an existing file
	if _, err := os.Stat(walletPath); err == nil {
		writeError(w, http.StatusConflict, "wallet file already exists: "+filepath.Base(walletPath))
		return
	}

	password := []byte(req.Password)
	wl, err := wallet.NewWalletFromMnemonic(walletPath, password, req.Mnemonic, defaultWalletConfig())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create wallet: "+err.Error())
		return
	}

	scanner := wallet.NewScanner(wl, defaultScannerConfig())

	// Point miner rewards at this wallet
	s.daemon.Miner().SetRewardKeys(wl.Keys().SpendPubKey, wl.Keys().ViewPubKey)

	// Scan the entire chain to find outputs belonging to this seed
	chainHeight := s.daemon.Chain().Height()
	if chainHeight > 0 {
		for h := uint64(1); h <= chainHeight; h++ {
			block := s.daemon.Chain().GetBlockByHeight(h)
			if block == nil {
				break
			}
			scanner.ScanBlock(blockToScanData(block))
		}
		wl.SetSyncedHeight(chainHeight)
		if err := wl.Save(); err != nil {
			writeError(w, http.StatusInternalServerError, "wallet import persistence failed: "+err.Error())
			return
		}
	}

	// Publish to API server
	s.wallet = wl
	s.scanner = scanner
	s.password = password

	// Publish to CLI (for autoScanBlocks / shutdown)
	s.cli.mu.Lock()
	s.cli.wallet = wl
	s.cli.scanner = scanner
	s.cli.password = password
	s.cli.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"imported": true,
		"address":  wl.Address(),
		"filename": filepath.Base(walletPath),
	})
}

// handleSeed returns the wallet recovery seed (BIP39 mnemonic).
// POST /api/wallet/seed
func (s *APIServer) handleSeed(w http.ResponseWriter, r *http.Request) {
	if !s.requireWallet(w, r) {
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.Password), s.password) != 1 {
		writeError(w, http.StatusUnauthorized, "incorrect password")
		return
	}

	mnemonic := s.wallet.Mnemonic()
	if mnemonic == "" {
		writeError(w, http.StatusNotFound, "no recovery seed available")
		return
	}

	// Sensitive response: discourage caching.
	w.Header().Set("Cache-Control", "no-store")

	writeJSON(w, http.StatusOK, map[string]any{
		"mnemonic": mnemonic,
		"words":    strings.Fields(mnemonic),
	})
}

// handleWalletSync triggers a blockchain sync check.
// POST /api/wallet/sync
func (s *APIServer) handleWalletSync(w http.ResponseWriter, r *http.Request) {
	if !s.requireWallet(w, r) {
		return
	}

	s.daemon.TriggerSync()
	writeJSON(w, http.StatusOK, map[string]any{"status": "sync triggered"})
}

// ============================================================================
// Mining handlers
// ============================================================================

// handleMiningStatus returns mining status and stats.
// GET /api/mining
func (s *APIServer) handleMiningStatus(w http.ResponseWriter, r *http.Request) {
	running := s.daemon.IsMining()

	resp := map[string]any{
		"running": running,
		"threads": s.daemon.Miner().Threads(),
	}

	if running {
		stats := s.daemon.MinerStats()
		resp["hashrate"] = s.daemon.Miner().HashRate()
		resp["hash_count"] = stats.HashCount
		resp["blocks_found"] = stats.BlocksFound
		resp["started_at"] = stats.StartTime.Format(time.RFC3339)
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleMiningStart starts the miner.
// POST /api/mining/start
func (s *APIServer) handleMiningStart(w http.ResponseWriter, r *http.Request) {
	if s.daemon.IsMining() {
		writeError(w, http.StatusConflict, "mining already running")
		return
	}
	s.daemon.StartMining()
	writeJSON(w, http.StatusOK, map[string]any{"running": true})
}

// handleMiningStop stops the miner.
// POST /api/mining/stop
func (s *APIServer) handleMiningStop(w http.ResponseWriter, r *http.Request) {
	if !s.daemon.IsMining() {
		writeError(w, http.StatusConflict, "mining not running")
		return
	}
	s.daemon.StopMining()
	writeJSON(w, http.StatusOK, map[string]any{"running": false})
}

// handleBlockTemplate returns a block template for pool mining.
// The template includes a pre-built coinbase (using the wallet's keys),
// all selected mempool transactions, and the computed merkle root.
// Pool software distributes the header to miners; they find a valid nonce
// and submit back via POST /api/mining/submitblock.
// GET /api/mining/blocktemplate
func (s *APIServer) handleBlockTemplate(w http.ResponseWriter, r *http.Request) {
	if s.wallet == nil {
		writeError(w, http.StatusServiceUnavailable, "no wallet loaded")
		return
	}

	chain := s.daemon.Chain()
	height := chain.Height() + 1
	reward := GetBlockReward(height)

	// Create coinbase paying to the loaded wallet
	coinbase, err := CreateCoinbase(s.wallet.SpendPubKey(), s.wallet.ViewPubKey(), reward, height)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create coinbase: "+err.Error())
		return
	}

	// Get mempool transactions sorted by fee rate
	txs := s.daemon.Mempool().GetTransactionsForBlock(MaxBlockSize-1000, 1000)

	// Build transaction list (coinbase first)
	allTxs := make([]*Transaction, 0, len(txs)+1)
	allTxs = append(allTxs, coinbase.Tx)
	allTxs = append(allTxs, txs...)

	// Build block template (nonce = 0, to be solved by pool miners)
	block := &Block{
		Header: BlockHeader{
			Version:    1,
			Height:     height,
			PrevHash:   chain.BestHash(),
			Timestamp:  time.Now().Unix(),
			Difficulty: chain.NextDifficulty(),
			Nonce:      0,
		},
		Transactions: allTxs,
	}

	// Compute merkle root
	merkleRoot, err := block.ComputeMerkleRoot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to compute merkle root: "+err.Error())
		return
	}
	block.Header.MerkleRoot = merkleRoot

	// Compute target for PoW validation
	target := DifficultyToTarget(block.Header.Difficulty)

	writeJSON(w, http.StatusOK, map[string]any{
		"block":       block,
		"target":      fmt.Sprintf("%x", target),
		"header_base": fmt.Sprintf("%x", block.Header.SerializeForPoW()),
	})
}

// handleSubmitBlock accepts a solved block from pool mining and adds it to the chain.
// POST /api/mining/submitblock
func (s *APIServer) handleSubmitBlock(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.submitBlockLimiter.allow(ip) {
		writeError(w, http.StatusTooManyRequests, "submitblock rate limit exceeded")
		return
	}

	select {
	case s.submitBlockSem <- struct{}{}:
		defer func() { <-s.submitBlockSem }()
	default:
		writeError(w, http.StatusTooManyRequests, "submitblock busy, retry later")
		return
	}

	var block Block
	if err := json.NewDecoder(r.Body).Decode(&block); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if err := s.daemon.SubmitBlock(&block); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	hash := block.Hash()
	writeJSON(w, http.StatusOK, map[string]any{
		"accepted": true,
		"hash":     fmt.Sprintf("%x", hash),
		"height":   block.Header.Height,
	})
}

// handleMiningThreads sets the mining thread count.
// POST /api/mining/threads
func (s *APIServer) handleMiningThreads(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Threads int `json:"threads"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Threads < 1 {
		writeError(w, http.StatusBadRequest, "threads must be >= 1")
		return
	}

	s.daemon.Miner().SetThreads(req.Threads)
	writeJSON(w, http.StatusOK, map[string]any{"threads": s.daemon.Miner().Threads()})
}

// ============================================================================
// Dangerous operations
// ============================================================================

// handlePurgeData deletes all blockchain data from disk.
// POST /api/purge
func (s *APIServer) handlePurgeData(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
		Confirm  bool   `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Fail closed if destructive auth state is not initialized.
	if s.wallet == nil {
		writeError(w, http.StatusServiceUnavailable, "purge unavailable: no wallet loaded")
		return
	}
	if len(s.password) == 0 {
		writeError(w, http.StatusServiceUnavailable, "purge unavailable: password state not initialized")
		return
	}

	// Require password verification
	if subtle.ConstantTimeCompare([]byte(req.Password), s.password) != 1 {
		writeError(w, http.StatusUnauthorized, "incorrect password")
		return
	}

	// Require explicit confirmation
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, "confirmation required (set confirm: true)")
		return
	}

	// Stop daemon first to release database locks
	if err := s.daemon.Stop(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to stop daemon before purge: "+err.Error())
		return
	}

	// Remove data directory
	if err := os.RemoveAll(s.dataDir); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to purge blockchain data: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "blockchain data purged successfully, restart required",
	})

	// Shut down the API server since daemon is stopped
	go func() {
		time.Sleep(100 * time.Millisecond)
		s.Stop()
	}()
}

// ============================================================================
// Helpers
// ============================================================================

// writeJSON encodes v as JSON and writes it with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Warning: failed to write JSON response: %v", err)
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// blockToJSON builds a JSON-friendly block representation.
func blockToJSON(block *Block, chainHeight uint64) map[string]any {
	hash := block.Hash()

	txs := make([]map[string]any, len(block.Transactions))
	for i, tx := range block.Transactions {
		txHash, _ := tx.TxID()
		txs[i] = map[string]any{
			"hash":        fmt.Sprintf("%x", txHash),
			"is_coinbase": i == 0 && block.Header.Height > 0,
			"inputs":      len(tx.Inputs),
			"outputs":     len(tx.Outputs),
			"fee":         tx.Fee,
		}
	}

	confirmations := uint64(0)
	if chainHeight >= block.Header.Height {
		confirmations = chainHeight - block.Header.Height + 1
	}

	return map[string]any{
		"height":        block.Header.Height,
		"hash":          fmt.Sprintf("%x", hash),
		"prev_hash":     fmt.Sprintf("%x", block.Header.PrevHash),
		"merkle_root":   fmt.Sprintf("%x", block.Header.MerkleRoot),
		"timestamp":     block.Header.Timestamp,
		"difficulty":    block.Header.Difficulty,
		"nonce":         block.Header.Nonce,
		"tx_count":      len(block.Transactions),
		"transactions":  txs,
		"confirmations": confirmations,
		"reward":        GetBlockReward(block.Header.Height),
	}
}

// findChainTx searches for a tx by hash string in the blockchain (tip backwards).
func (s *APIServer) findChainTx(hashStr string) (*Transaction, uint64, bool) {
	return s.daemon.Chain().FindTxByHashStr(hashStr)
}

// createTxBuilder creates a transaction builder wired to the daemon (same as CLI).
func (s *APIServer) createTxBuilder() *wallet.Builder {
	cfg := wallet.TransferConfig{
		SelectRingMembers: func(realPubKey, realCommitment [32]byte) (keys, commitments [][32]byte, secretIndex int, err error) {
			ringData, err := s.daemon.Chain().SelectRingMembersWithCommitments(realPubKey, realCommitment)
			if err != nil {
				return nil, nil, 0, err
			}
			return ringData.Keys, ringData.Commitments, ringData.SecretIndex, nil
		},
		CreateCommitment: func(amount uint64, blinding [32]byte) [32]byte {
			commitment, _ := CreatePedersenCommitmentWithBlinding(amount, blinding)
			return commitment
		},
		CreateRangeProof: func(amount uint64, blinding [32]byte) ([]byte, error) {
			proof, err := CreateRangeProof(amount, blinding)
			if err != nil {
				return nil, err
			}
			return proof.Proof, nil
		},
		SignRingCT: func(ringKeys, ringCommitments [][32]byte, secretIndex int, privateKey, realBlinding, pseudoCommitment, pseudoBlinding [32]byte, message []byte) ([]byte, [32]byte, error) {
			sig, err := SignRingCT(ringKeys, ringCommitments, secretIndex, privateKey, realBlinding, pseudoCommitment, pseudoBlinding, message)
			if err != nil {
				return nil, [32]byte{}, err
			}
			return sig.Signature, sig.KeyImage, nil
		},
		GenerateBlinding: func() [32]byte {
			blinding, _ := GenerateBlinding()
			return blinding
		},
		ComputeTxID: func(txData []byte) ([32]byte, error) {
			tx, err := DeserializeTx(txData)
			if err != nil {
				return [32]byte{}, err
			}
			return tx.TxID()
		},
		DeriveStealthAddress: func(spendPub, viewPub [32]byte) (txPriv, txPub, oneTimePub [32]byte, err error) {
			output, err := DeriveStealthAddress(spendPub, viewPub)
			if err != nil {
				return txPriv, txPub, oneTimePub, err
			}
			return output.TxPrivKey, output.TxPubKey, output.OnetimePubKey, nil
		},
		DeriveSharedSecret: DeriveStealthSecretSender,
		ScalarToPoint:      ScalarToPubKey,
		PointAdd: func(p1, p2 [32]byte) ([32]byte, error) {
			return CommitmentAdd(p1, p2)
		},
		BlindingAdd: BlindingAdd,
		BlindingSub: BlindingSub,
		RingSize:    RingSize,
		MinFee:      10000, // 0.0001 BNT minimum
		FeePerByte:  100,   // 0.000001 BNT per byte
	}

	return wallet.NewBuilder(s.wallet, cfg)
}
