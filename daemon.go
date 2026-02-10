package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"blocknet/p2p"

	"github.com/libp2p/go-libp2p/core/peer"
)

type Daemon struct {
	mu sync.RWMutex

	// Core components
	chain   *Chain
	mempool *Mempool
	miner   *Miner

	// P2P layer
	node      *p2p.Node
	syncMgr   *p2p.SyncManager
	dandelion *p2p.DandelionRouter

	// Identity
	stealthKeys *StealthKeys

	// Block notifications for wallet auto-sync
	blockSubs   []chan *Block
	blockSubsMu sync.Mutex

	// Mined block notifications (blocks we mined)
	minedSubs   []chan *Block
	minedSubsMu sync.Mutex

	// Explorer
	explorerAddr string

	// State
	ctx    context.Context
	cancel context.CancelFunc
}

// DaemonConfig configures the daemon
type DaemonConfig struct {
	// P2P settings
	ListenAddrs []string
	SeedNodes   []string

	// Mining
	EnableMining bool

	// Data directory
	DataDir string

	// ExplorerAddr is the HTTP address for the block explorer (empty = disabled)
	ExplorerAddr string
}

// DefaultSeedNodes are the hardcoded bootstrap nodes
var DefaultSeedNodes = []string{
	"/ip4/46.62.203.242/tcp/28080/p2p/12D3KooWB4FY5fLRpwMsYXoVSYb3hWmiDCSJLysVSX3Z38mnkpX6",
	"/ip4/46.62.243.192/tcp/28080/p2p/12D3KooWSc7bV4H7V8pUeKphJ9G2c67rLbiHUuzYj3HHV5Wtf3NS",
	"/ip4/46.62.252.254/tcp/28080/p2p/12D3KooWHXC9xcREsVpcukZdqXyL83k2vKrdNdfsBpuZ7P9Hpmqd",
	"/ip4/46.62.202.165/tcp/28080/p2p/12D3KooWPaMpej16rnr8CC1ALydc4ECkDmwzAcNddS2XDRV8JYNr",
	"/ip4/46.62.249.240/tcp/28080/p2p/12D3KooWSC4Gezy61GViYAAAMrz4Vv2id4YFsUtFR4qZrb5QtL6F",
	"/ip4/46.62.201.220/tcp/28080/p2p/12D3KooWPjygAsXysJgr4kdmHGdUmwwPX6jbrdszGBhjRZv2g5w8",
}

// DefaultDaemonConfig returns sensible defaults
func DefaultDaemonConfig() DaemonConfig {
	return DaemonConfig{
		ListenAddrs:  []string{"/ip4/0.0.0.0/tcp/28080"},
		SeedNodes:    DefaultSeedNodes,
		EnableMining: false,
		DataDir:      "./data",
	}
}

// NewDaemon creates a new blockchain daemon
// If stealthKeys is nil, new keys are generated
func NewDaemon(cfg DaemonConfig, stealthKeys *StealthKeys) (*Daemon, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Use provided keys or generate new ones
	if stealthKeys == nil {
		var err error
		stealthKeys, err = GenerateStealthKeys()
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to generate stealth keys: %w", err)
		}
	}

	// Create chain with persistent storage
	chain, err := NewChain(cfg.DataDir)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create chain: %w", err)
	}

	// Create genesis block if chain is empty (no blocks exist)
	if !chain.HasGenesis() {
		genesis, err := GetGenesisBlock()
		if err != nil {
			chain.Close()
			cancel()
			return nil, fmt.Errorf("failed to create genesis: %w", err)
		}
		if err := chain.AddBlock(genesis); err != nil {
			chain.Close()
			cancel()
			return nil, fmt.Errorf("failed to add genesis: %w", err)
		}
	}

	// Create mempool (uses chain's key image checker)
	mempool := NewMempool(DefaultMempoolConfig(), chain.IsKeyImageSpent)

	// Create miner (peer count wired up after node creation)
	minerCfg := MinerConfig{
		MinerSpendPub: stealthKeys.SpendPubKey,
		MinerViewPub:  stealthKeys.ViewPubKey,
	}
	miner := NewMiner(chain, mempool, minerCfg)

	// Create P2P node
	nodeCfg := p2p.DefaultNodeConfig()
	nodeCfg.ListenAddrs = cfg.ListenAddrs
	nodeCfg.SeedNodes = cfg.SeedNodes
	nodeCfg.UserAgent = "blocknet/" + Version

	node, err := p2p.NewNode(nodeCfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create P2P node: %w", err)
	}

	// Wire up peer count for miner (skip mining when no peers)
	miner.config.PeerCount = func() int { return len(node.Peers()) }

	d := &Daemon{
		chain:       chain,
		mempool:     mempool,
		miner:       miner,
		node:        node,
		stealthKeys: stealthKeys,
		ctx:         ctx,
		cancel:      cancel,
	}

	// Create sync manager with callbacks
	syncCfg := p2p.SyncConfig{
		GetStatus:         d.getChainStatus,
		GetHeaders:        d.getHeaders,
		GetBlocks:         d.getBlocks,
		GetBlocksByHeight: d.getBlocksByHeight,
		ProcessBlock:      d.processBlockData,
		ProcessHeader:     nil, // Full-block sync, no header processing
		GetMempool:        d.getMempoolTxs,
		ProcessTx:         d.processTxData,
		IsOrphanError: func(err error) bool {
			return errors.Is(err, ErrOrphanBlock)
		},
		GetBlockMeta: func(data []byte) (uint64, [32]byte, error) {
			var block Block
			if err := json.Unmarshal(data, &block); err != nil {
				return 0, [32]byte{}, err
			}
			return block.Header.Height, block.Header.PrevHash, nil
		},
		GetBlockHash: func(data []byte) ([32]byte, error) {
			var block Block
			if err := json.Unmarshal(data, &block); err != nil {
				return [32]byte{}, err
			}
			return block.Hash(), nil
		},
		OnBlockAccepted: func(data []byte) {
			d.miner.NotifyNewBlock()
			var block Block
			if err := json.Unmarshal(data, &block); err == nil {
				d.notifyBlock(&block)
			}
		},
	}
	d.syncMgr = p2p.NewSyncManager(node, syncCfg)

	// Set up P2P handlers
	node.SetBlockHandler(d.handleBlock)
	node.SetTxHandler(d.handleTx)

	// Store explorer config
	d.explorerAddr = cfg.ExplorerAddr

	return d, nil
}

// SubscribeBlocks returns a channel that receives new blocks
func (d *Daemon) SubscribeBlocks() chan *Block {
	d.blockSubsMu.Lock()
	defer d.blockSubsMu.Unlock()
	ch := make(chan *Block, 10)
	d.blockSubs = append(d.blockSubs, ch)
	return ch
}

// notifyBlock sends block to all subscribers
func (d *Daemon) notifyBlock(block *Block) {
	d.blockSubsMu.Lock()
	defer d.blockSubsMu.Unlock()
	for _, ch := range d.blockSubs {
		select {
		case ch <- block:
		default: // Don't block if subscriber is slow
		}
	}
}

// SubscribeMinedBlocks returns a channel that receives blocks we mined
func (d *Daemon) SubscribeMinedBlocks() chan *Block {
	d.minedSubsMu.Lock()
	defer d.minedSubsMu.Unlock()
	ch := make(chan *Block, 10)
	d.minedSubs = append(d.minedSubs, ch)
	return ch
}

// notifyMinedBlock sends mined block to all subscribers
func (d *Daemon) notifyMinedBlock(block *Block) {
	d.minedSubsMu.Lock()
	defer d.minedSubsMu.Unlock()
	for _, ch := range d.minedSubs {
		select {
		case ch <- block:
		default:
		}
	}
}

// Start begins daemon operations
func (d *Daemon) Start() error {
	// Start P2P node
	if err := d.node.Start(); err != nil {
		return fmt.Errorf("failed to start P2P: %w", err)
	}

	// Start sync manager
	d.syncMgr.Start(d.ctx)

	// Start explorer if configured
	if d.explorerAddr != "" {
		explorer := NewExplorer(d)
		go func() {
			log.Printf("Explorer listening on %s", d.explorerAddr)
			if err := explorer.Start(d.explorerAddr); err != nil {
				log.Printf("Explorer error: %v", err)
			}
		}()
	}

	log.Printf("Daemon started")
	log.Printf("  Peer ID: %s", d.node.PeerID())
	log.Printf("  Listening: %v", d.node.Addrs())
	log.Printf("  Chain height: %d", d.chain.Height())

	return nil
}

// Stop gracefully shuts down the daemon
func (d *Daemon) Stop() error {
	log.Println("Shutting down daemon...")

	d.cancel()

	// Stop miner
	d.miner.Stop()

	// Stop sync
	d.syncMgr.Stop()

	// Stop P2P
	if err := d.node.Stop(); err != nil {
		return err
	}

	// Close chain storage
	if err := d.chain.Close(); err != nil {
		return err
	}

	log.Println("Daemon stopped")
	return nil
}

// StartMining begins mining blocks
func (d *Daemon) StartMining() {
	blockChan := make(chan *Block, 10)

	go func() {
		for {
			select {
			case <-d.ctx.Done():
				return
			case block := <-blockChan:
				d.handleMinedBlock(block)
			}
		}
	}()

	d.miner.Start(d.ctx, blockChan)
	log.Println("Mining started")
}

// handleMinedBlock processes a block we mined
func (d *Daemon) handleMinedBlock(block *Block) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Add to our chain
	prevBest := d.chain.BestHash()
	accepted, isMainChain, err := d.chain.ProcessBlock(block)
	if err != nil || !accepted {
		log.Printf("Failed to add mined block: %v", err)
		return
	}

	if !isMainChain {
		// Lost race to a peer block at the same height.
		// Do NOT touch the mempool -- our transactions are still valid
		// and should be included in the next block attempt.
		return
	}

	// Update mempool for all blocks that became main-chain.
	d.updateMempoolForAcceptedMainChain(block, prevBest)

	// Broadcast to peers
	blockData, err := json.Marshal(block)
	if err != nil {
		log.Printf("Failed to marshal block: %v", err)
		return
	}

	d.syncMgr.BroadcastBlock(blockData)

	// Notify wallet subscribers
	d.notifyBlock(block)
	d.notifyMinedBlock(block)
}

// handleBlock processes a block from a peer
func (d *Daemon) handleBlock(from peer.ID, data []byte) {
	var block Block
	if err := json.Unmarshal(data, &block); err != nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	prevBest := d.chain.BestHash()
	accepted, isMainChain, err := d.chain.ProcessBlock(&block)
	if err != nil || !accepted {
		// May be orphan or invalid, ignore silently
		return
	}

	if !isMainChain {
		// Fork block -- don't touch mempool or relay
		return
	}

	d.updateMempoolForAcceptedMainChain(&block, prevBest)
	log.Printf("Received and accepted block at height %d from %s", block.Header.Height, from.String()[:8])

	// Relay to other peers (exclude sender)
	d.node.RelayBlock(from, data)

	// Notify wallet subscribers
	d.notifyBlock(&block)

	// Signal miner to restart with new tip
	d.miner.NotifyNewBlock()
}

// handleTx processes a transaction from a peer (fluff phase)
func (d *Daemon) handleTx(from peer.ID, data []byte) {
	txData, aux := DecodeTxWithAux(data)

	tx, err := DeserializeTx(txData)
	if err != nil {
		return
	}

	if err := d.mempool.AddTransaction(tx, txData, aux); err != nil {
		// Invalid or duplicate, ignore
		return
	}
}

// Chain status callbacks for sync manager

func (d *Daemon) getChainStatus() p2p.ChainStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return p2p.ChainStatus{
		BestHash:  d.chain.BestHash(),
		Height:    d.chain.Height(),
		TotalWork: d.chain.TotalWork(),
		Version:   1,
	}
}

func (d *Daemon) getHeaders(startHeight uint64, max int) ([][]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var headers [][]byte
	for h := startHeight; h <= d.chain.Height() && len(headers) < max; h++ {
		block := d.chain.GetBlockByHeight(h)
		if block == nil {
			break
		}

		headerData, err := json.Marshal(block.Header)
		if err != nil {
			continue
		}
		headers = append(headers, headerData)
	}

	return headers, nil
}

func (d *Daemon) getBlocks(hashes [][32]byte) ([][]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var blocks [][]byte
	for _, hash := range hashes {
		block := d.chain.GetBlock(hash)
		if block == nil {
			continue
		}

		blockData, err := json.Marshal(block)
		if err != nil {
			continue
		}
		blocks = append(blocks, blockData)
	}

	return blocks, nil
}

func (d *Daemon) processBlockData(data []byte) error {
	var block Block
	if err := json.Unmarshal(data, &block); err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	prevBest := d.chain.BestHash()
	accepted, isMainChain, err := d.chain.ProcessBlock(&block)
	if err != nil {
		return err
	}
	if !accepted {
		// Duplicate block we already have — harmless during sync
		return nil
	}

	if isMainChain {
		d.updateMempoolForAcceptedMainChain(&block, prevBest)
	}
	return nil
}

// updateMempoolForAcceptedMainChain updates mempool contents for a newly
// accepted main-chain block. During reorg, this applies both sides:
//   - disconnected old-main-chain blocks are re-queued (if still valid)
//   - connected new-main-chain blocks are removed as confirmed
func (d *Daemon) updateMempoolForAcceptedMainChain(block *Block, previousBest [32]byte) {
	if d.mempool == nil {
		return
	}

	// Fast path: direct extension with a single new main-chain block.
	if block.Header.PrevHash == previousBest {
		d.mempool.OnBlockConnected(block)
		return
	}

	newBest := d.chain.BestHash()
	disconnected, connected := d.collectReorgDiffBlocks(previousBest, newBest)
	if len(connected) == 0 {
		// Fallback to the accepted block if chain traversal failed unexpectedly.
		log.Printf("[reorg] mempool fallback: could not walk reorg diff (prevBest=%x newBest=%x), only connecting tip block", previousBest[:8], newBest[:8])
		d.mempool.OnBlockConnected(block)
		return
	}

	// Disconnect first so old-chain transactions are visible to conflict removal
	// when new-chain blocks are connected.
	for _, b := range disconnected {
		d.mempool.OnBlockDisconnected(b, d.txDataMapForBlock(b))
	}

	for _, b := range connected {
		d.mempool.OnBlockConnected(b)
	}
}

func (d *Daemon) collectReorgDiffBlocks(oldTip, newTip [32]byte) (disconnected []*Block, connected []*Block) {
	const maxReorgDepth = 1000

	// Walk both chains in lockstep-bounded fashion rather than loading the
	// entire old chain into memory.  We walk the new chain first (up to
	// maxReorgDepth) collecting blocks, then walk the old chain looking for
	// the common ancestor among those plus the new-chain set.

	// Step 1: walk new chain collecting blocks until we find one that is on
	// the old chain or we exhaust the depth budget.
	reversed := make([]*Block, 0, 8)
	newChainSet := make(map[[32]byte]struct{}, 64)
	for hash := newTip; ; {
		newChainSet[hash] = struct{}{}
		if hash == oldTip {
			// newTip extends oldTip (shouldn't reach here due to fast-path,
			// but handle gracefully).
			break
		}
		block := d.chain.GetBlock(hash)
		if block == nil {
			log.Printf("[reorg] failed to load new-chain block %x during reorg diff", hash[:8])
			return nil, nil
		}
		reversed = append(reversed, block)
		if block.Header.Height == 0 || len(reversed) >= maxReorgDepth {
			break
		}
		hash = block.Header.PrevHash
	}

	// Step 2: walk old chain looking for common ancestor.
	var commonAncestor [32]byte
	foundCommon := false
	oldAncestors := make(map[[32]byte]*Block, len(reversed))
	for hash := oldTip; ; {
		if _, ok := newChainSet[hash]; ok {
			commonAncestor = hash
			foundCommon = true
			break
		}
		block := d.chain.GetBlock(hash)
		if block == nil {
			log.Printf("[reorg] failed to load old-chain block %x during reorg diff", hash[:8])
			return nil, nil
		}
		oldAncestors[hash] = block
		if block.Header.Height == 0 || len(oldAncestors) >= maxReorgDepth {
			log.Printf("[reorg] no common ancestor found within %d blocks", maxReorgDepth)
			return nil, nil
		}
		hash = block.Header.PrevHash
	}
	if !foundCommon {
		return nil, nil
	}

	// Filter reversed to only blocks after the common ancestor.
	// reversed is newest-first; trim any entries at/before the ancestor.
	trimmed := reversed[:0]
	for _, b := range reversed {
		if b.Hash() == commonAncestor {
			break
		}
		trimmed = append(trimmed, b)
	}
	reversed = trimmed

	for hash := oldTip; hash != commonAncestor; {
		block, ok := oldAncestors[hash]
		if !ok || block == nil {
			log.Printf("[reorg] old-chain block %x missing from ancestors map", hash[:8])
			return nil, nil
		}
		disconnected = append(disconnected, block)
		hash = block.Header.PrevHash
	}

	connected = make([]*Block, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		connected = append(connected, reversed[i])
	}
	return disconnected, connected
}

// txDataMapForBlock builds serialized tx payloads for a block, including
// optional aux trailers reconstructed from block-level aux metadata.
func (d *Daemon) txDataMapForBlock(block *Block) map[[32]byte][]byte {
	if block == nil || len(block.Transactions) == 0 {
		return nil
	}

	// Group payment IDs by transaction index.
	auxByTxIndex := make(map[int]map[int][8]byte)
	if block.AuxData != nil && len(block.AuxData.PaymentIDs) > 0 {
		for key, pid := range block.AuxData.PaymentIDs {
			var txIdx, outIdx int
			if _, err := fmt.Sscanf(key, "%d:%d", &txIdx, &outIdx); err != nil {
				continue
			}
			if txIdx < 0 || txIdx >= len(block.Transactions) || outIdx < 0 {
				continue
			}
			if auxByTxIndex[txIdx] == nil {
				auxByTxIndex[txIdx] = make(map[int][8]byte)
			}
			auxByTxIndex[txIdx][outIdx] = pid
		}
	}

	txDataMap := make(map[[32]byte][]byte, len(block.Transactions))
	for txIdx, tx := range block.Transactions {
		txID, err := tx.TxID()
		if err != nil {
			continue
		}

		txData := tx.Serialize()
		if paymentIDs := auxByTxIndex[txIdx]; len(paymentIDs) > 0 {
			txData = EncodeTxWithAux(txData, &TxAuxData{PaymentIDs: paymentIDs})
		}
		txDataMap[txID] = txData
	}

	return txDataMap
}

// getBlocksByHeight returns blocks in a height range for sync requests
func (d *Daemon) getBlocksByHeight(startHeight uint64, max int) ([][]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var blocks [][]byte
	for i := 0; i < max; i++ {
		height := startHeight + uint64(i)
		block := d.chain.GetBlockByHeight(height)
		if block == nil {
			break // Reached end of chain
		}

		blockData, err := json.Marshal(block)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, blockData)
	}

	return blocks, nil
}

// getMempoolTxs returns all serialized transactions in the mempool (with aux data)
func (d *Daemon) getMempoolTxs() [][]byte {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.mempool.GetAllTransactionDataWithAux()
}

// processTxData handles an incoming transaction from a peer
func (d *Daemon) processTxData(data []byte) error {
	txData, aux := DecodeTxWithAux(data)

	tx, err := DeserializeTx(txData)
	if err != nil {
		return fmt.Errorf("invalid transaction: %w", err)
	}

	// Add to mempool (validates the transaction)
	if err := d.mempool.AddTransaction(tx, txData, aux); err != nil {
		// Not necessarily an error - might be duplicate or already spent
		return nil
	}

	return nil
}

// Stats returns daemon statistics
type DaemonStats struct {
	PeerID       string `json:"peer_id"`
	Peers        int    `json:"peers"`
	ChainHeight  uint64 `json:"chain_height"`
	BestHash     string `json:"best_hash"`
	TotalWork    uint64 `json:"total_work"`
	MempoolSize  int    `json:"mempool_size"`
	MempoolBytes int    `json:"mempool_bytes"`
	Syncing      bool   `json:"syncing"`
	SyncProgress uint64 `json:"sync_progress,omitempty"`
	SyncTarget   uint64 `json:"sync_target,omitempty"`
	SyncPercent  string `json:"sync_percent,omitempty"`
	IdentityAge  string `json:"identity_age"`
}

func (d *Daemon) Stats() DaemonStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	bestHash := d.chain.BestHash()

	stats := DaemonStats{
		PeerID:       d.node.PeerID().String(),
		Peers:        len(d.node.Peers()),
		ChainHeight:  d.chain.Height(),
		BestHash:     fmt.Sprintf("%x", bestHash[:8]),
		TotalWork:    d.chain.TotalWork(),
		MempoolSize:  d.mempool.Size(),
		MempoolBytes: d.mempool.SizeBytes(),
		Syncing:      d.syncMgr.IsSyncing(),
		IdentityAge:  d.node.IdentityAge().Round(time.Second).String(),
	}

	// Add sync progress if syncing
	if stats.Syncing {
		progress, target, _ := d.syncMgr.SyncProgress()
		stats.SyncProgress = progress
		stats.SyncTarget = target
		if target > 0 {
			pct := float64(progress) / float64(target) * 100
			stats.SyncPercent = fmt.Sprintf("%.1f%%", pct)
		}
	}

	return stats
}

// Getters for components
func (d *Daemon) Chain() *Chain     { return d.chain }
func (d *Daemon) Mempool() *Mempool { return d.mempool }
func (d *Daemon) Node() *p2p.Node   { return d.node }
func (d *Daemon) Miner() *Miner     { return d.miner }
func (d *Daemon) TriggerSync()      { d.syncMgr.TriggerSync() }

// IsMining returns whether the miner is running
func (d *Daemon) IsMining() bool {
	return d.miner.IsRunning()
}

// StopMining stops the miner
func (d *Daemon) StopMining() {
	d.miner.Stop()
}

// MinerStats returns current mining statistics
func (d *Daemon) MinerStats() MinerStats {
	return d.miner.Stats()
}

// SubmitTransaction adds a transaction to mempool and broadcasts to peers.
// aux is optional auxiliary data (e.g. encrypted payment IDs).
func (d *Daemon) SubmitTransaction(txData []byte, aux ...*TxAuxData) error {
	tx, err := DeserializeTx(txData)
	if err != nil {
		return fmt.Errorf("invalid transaction data: %w", err)
	}

	// Pass through aux data to mempool
	var txAux *TxAuxData
	if len(aux) > 0 {
		txAux = aux[0]
	}

	// Validate and add to mempool
	if err := d.mempool.AddTransaction(tx, txData, txAux); err != nil {
		return fmt.Errorf("mempool rejected: %w", err)
	}

	// Broadcast via Dandelion++ for privacy.
	// Append aux data after TX bytes so payment IDs propagate.
	broadcastData := txData
	if txAux != nil {
		broadcastData = EncodeTxWithAux(txData, txAux)
	}
	d.node.BroadcastTx(broadcastData)

	return nil
}
