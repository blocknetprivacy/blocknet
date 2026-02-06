package main

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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
		"spendable":     s.wallet.SpendableBalance(height),
		"pending":       s.wallet.PendingBalance(height),
		"total":         s.wallet.Balance(),
		"outputs_total": total,
		"outputs_unspent": unspent,
		"chain_height":  height,
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

	outputs := s.wallet.SpendableOutputs()

	type outputEntry struct {
		TxID        string `json:"txid"`
		OutputIndex int    `json:"output_index"`
		Amount      uint64 `json:"amount"`
		BlockHeight uint64 `json:"block_height"`
		IsCoinbase  bool   `json:"is_coinbase"`
		Spent       bool   `json:"spent"`
		SpentHeight uint64 `json:"spent_height,omitempty"`
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
		Address string `json:"address"`
		Amount  uint64 `json:"amount"` // atomic units
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
	s.wallet.Save()

	writeJSON(w, http.StatusOK, map[string]any{
		"txid":   fmt.Sprintf("%x", result.TxID),
		"fee":    result.Fee,
		"change": result.Change,
	})
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

	s.mu.Lock()
	s.locked = false
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"locked": false})
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
// Helpers
// ============================================================================

// writeJSON encodes v as JSON and writes it with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
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
		txData, _ := json.Marshal(tx)
		txHash := ComputeTxHash(txData)
		txs[i] = map[string]any{
			"hash":       fmt.Sprintf("%x", txHash),
			"is_coinbase": i == 0 && block.Header.Height > 0,
			"inputs":     len(tx.Inputs),
			"outputs":    len(tx.Outputs),
			"fee":        tx.Fee,
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
		ComputeTxID: func(txData []byte) [32]byte {
			return ComputeTxHash(txData)
		},
		DeriveStealthAddress: func(spendPub, viewPub [32]byte) (txPriv, txPub, oneTimePub [32]byte, err error) {
			output, err := DeriveStealthAddress(spendPub, viewPub)
			if err != nil {
				return txPriv, txPub, oneTimePub, err
			}
			return output.TxPrivKey, output.TxPubKey, output.OnetimePubKey, nil
		},
		BlindingAdd: BlindingAdd,
		BlindingSub: BlindingSub,
		RingSize:    RingSize,
		MinFee:      10000, // 0.0001 BNT minimum
		FeePerByte:  100,   // 0.000001 BNT per byte
	}

	return wallet.NewBuilder(s.wallet, cfg)
}
