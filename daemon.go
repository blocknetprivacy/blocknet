package main

import (
	"context"
	"encoding/json"
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
	"/ip4/46.62.203.242/tcp/28080/p2p/12D3KooWBLUPjZgAoizTkbNJvHxgHkb2tF1saUhmKBzFfo8zZLfj",
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
	accepted, _, err := d.chain.ProcessBlock(block)
	if err != nil || !accepted {
		log.Printf("Failed to add mined block: %v", err)
		return
	}

	// Update mempool
	d.mempool.OnBlockConnected(block)

	// Broadcast to peers
	blockData, err := json.Marshal(block)
	if err != nil {
		log.Printf("Failed to marshal block: %v", err)
		return
	}

	d.syncMgr.BroadcastBlock(blockData)

	// Notify wallet subscribers (all blocks)
	d.notifyBlock(block)

	// Only notify mined block if it's actually the chain tip
	// (not orphaned by a competing block at same height)
	blockHash := block.Hash()
	tipHash := d.chain.BestHash()
	if blockHash == tipHash {
		d.notifyMinedBlock(block)
	}
}

// handleBlock processes a block from a peer
func (d *Daemon) handleBlock(from peer.ID, data []byte) {
	var block Block
	if err := json.Unmarshal(data, &block); err != nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	accepted, _, err := d.chain.ProcessBlock(&block)
	if err != nil || !accepted {
		// May be orphan or invalid, ignore silently
		return
	}

	d.mempool.OnBlockConnected(&block)
	log.Printf("Received and accepted block at height %d from %s", block.Header.Height, from.String()[:8])

	// Relay to other peers (exclude sender)
	d.node.RelayBlock(from, data)

	// Notify wallet subscribers
	d.notifyBlock(&block)
}

// handleTx processes a transaction from a peer (fluff phase)
func (d *Daemon) handleTx(from peer.ID, data []byte) {
	var tx Transaction
	if err := json.Unmarshal(data, &tx); err != nil {
		return
	}

	if err := d.mempool.AddTransaction(&tx, data); err != nil {
		// Invalid or duplicate, ignore
		return
	}

	log.Printf("Received transaction from %s", from.String()[:8])
}

// BroadcastTransaction broadcasts a transaction via Dandelion++
func (d *Daemon) BroadcastTransaction(tx *Transaction) error {
	txData, err := json.Marshal(tx)
	if err != nil {
		return err
	}

	// Add to our mempool first
	if err := d.mempool.AddTransaction(tx, txData); err != nil {
		return err
	}

	// Broadcast via Dandelion++
	d.node.BroadcastTx(txData)

	return nil
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

	accepted, _, err := d.chain.ProcessBlock(&block)
	if err != nil {
		// Orphan blocks are not errors - just skip them
		if err == ErrOrphanBlock {
			return nil
		}
		return err
	}
	if !accepted {
		return fmt.Errorf("block not accepted")
	}

	d.mempool.OnBlockConnected(&block)
	return nil
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
	IdentityAge  string `json:"identity_age"`
}

func (d *Daemon) Stats() DaemonStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	bestHash := d.chain.BestHash()

	return DaemonStats{
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
}

// Getters for components
func (d *Daemon) Chain() *Chain     { return d.chain }
func (d *Daemon) Mempool() *Mempool { return d.mempool }
func (d *Daemon) Node() *p2p.Node   { return d.node }
func (d *Daemon) Miner() *Miner     { return d.miner }

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

// SubmitTransaction adds a transaction to mempool and broadcasts to peers
func (d *Daemon) SubmitTransaction(txData []byte) error {
	var tx Transaction
	if err := json.Unmarshal(txData, &tx); err != nil {
		return fmt.Errorf("invalid transaction data: %w", err)
	}

	// Validate and add to mempool
	if err := d.mempool.AddTransaction(&tx, txData); err != nil {
		return fmt.Errorf("mempool rejected: %w", err)
	}

	// Broadcast via Dandelion++ for privacy
	d.node.BroadcastTx(txData)

	return nil
}
