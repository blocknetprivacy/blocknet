package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
)

// ErrOrphanBlock is returned when a block's parent is not found
var ErrOrphanBlock = errors.New("orphan block")

// ============================================================================
// Constants
// ============================================================================

const (
	// Block timing
	BlockInterval       = 5 * time.Minute // Target block time
	BlockIntervalSec    = 300             // 5 minutes in seconds
	SafeConfirmations   = 10              // ~50 minutes for "safe"
	CoinbaseMaturity    = 60              // ~5 hours before mined coins spendable
	MaxReorgDepth       = 100             // Hard finality (~8 hours)
	TimestampFuturLimit = 2 * time.Hour   // Max timestamp ahead of now

	// Block size
	MaxBlockSize = 1 << 20 // 1MB hard cap

	// LWMA Difficulty adjustment (Linear Weighted Moving Average)
	// Based on Zawy's LWMA used by TurtleCoin, Monero, etc.
	LWMAWindow       = 60                   // N blocks to look back
	MinDifficulty    = uint64(4)            // Floor difficulty (Argon2id 2GB is slow, ~15s/hash)
	LWMAMinSolvetime = 1                    // Minimum solvetime (prevent div by zero, timestamp attacks)
	LWMAMaxSolvetime = BlockIntervalSec * 6 // Max solvetime (6x target, prevents difficulty drops from stuck blocks)
)

// ============================================================================
// Block Header
// ============================================================================

// BlockHeader contains the immutable header of a block
type BlockHeader struct {
	Version    uint32   // Protocol version
	Height     uint64   // Block height (explicit)
	PrevHash   [32]byte // Hash of previous block
	MerkleRoot [32]byte // Root of transaction merkle tree
	Timestamp  int64    // Unix timestamp
	Difficulty uint64   // Target difficulty for this block
	Nonce      uint64   // PoW nonce
}

// Hash returns the SHA3-256 hash of the block header
func (h *BlockHeader) Hash() [32]byte {
	data := h.Serialize()
	return sha3.Sum256(data)
}

// Serialize converts header to bytes for hashing
func (h *BlockHeader) Serialize() []byte {
	buf := make([]byte, 80) // Fixed size: 4+8+32+32+8+8+8 = 100, but we use 80 for alignment

	binary.LittleEndian.PutUint32(buf[0:4], h.Version)
	binary.LittleEndian.PutUint64(buf[4:12], h.Height)
	// PrevHash and MerkleRoot go at fixed offsets
	// We'll use a simpler serialization
	return h.serializeFull()
}

// serializeFull serializes all header fields
func (h *BlockHeader) serializeFull() []byte {
	buf := make([]byte, 4+8+32+32+8+8+8) // 100 bytes total

	offset := 0
	binary.LittleEndian.PutUint32(buf[offset:], h.Version)
	offset += 4

	binary.LittleEndian.PutUint64(buf[offset:], h.Height)
	offset += 8

	copy(buf[offset:], h.PrevHash[:])
	offset += 32

	copy(buf[offset:], h.MerkleRoot[:])
	offset += 32

	binary.LittleEndian.PutUint64(buf[offset:], uint64(h.Timestamp))
	offset += 8

	binary.LittleEndian.PutUint64(buf[offset:], h.Difficulty)
	offset += 8

	binary.LittleEndian.PutUint64(buf[offset:], h.Nonce)

	return buf
}

// SerializeForPoW serializes header WITHOUT nonce for Argon2id input
// The nonce is passed separately to the PoW function
func (h *BlockHeader) SerializeForPoW() []byte {
	buf := make([]byte, 4+8+32+32+8+8) // 92 bytes (no nonce)

	offset := 0
	binary.LittleEndian.PutUint32(buf[offset:], h.Version)
	offset += 4

	binary.LittleEndian.PutUint64(buf[offset:], h.Height)
	offset += 8

	copy(buf[offset:], h.PrevHash[:])
	offset += 32

	copy(buf[offset:], h.MerkleRoot[:])
	offset += 32

	binary.LittleEndian.PutUint64(buf[offset:], uint64(h.Timestamp))
	offset += 8

	binary.LittleEndian.PutUint64(buf[offset:], h.Difficulty)

	return buf
}

// ============================================================================
// Block
// ============================================================================

// Block represents a complete block with header and transactions
type Block struct {
	Header       BlockHeader
	Transactions []*Transaction
}

// Hash returns the block hash (header hash)
func (b *Block) Hash() [32]byte {
	return b.Header.Hash()
}

// Size returns the approximate serialized size of the block
func (b *Block) Size() int {
	size := 100 // Header size
	for _, tx := range b.Transactions {
		size += tx.Size()
	}
	return size
}

// ComputeMerkleRoot computes the merkle root of transactions
func (b *Block) ComputeMerkleRoot() ([32]byte, error) {
	if len(b.Transactions) == 0 {
		return [32]byte{}, nil
	}

	// Get transaction hashes
	hashes := make([][32]byte, len(b.Transactions))
	for i, tx := range b.Transactions {
		txID, err := tx.TxID()
		if err != nil {
			return [32]byte{}, fmt.Errorf("failed to hash tx %d: %w", i, err)
		}
		hashes[i] = txID
	}

	return computeMerkleRoot(hashes), nil
}

// computeMerkleRoot builds merkle tree and returns root
func computeMerkleRoot(hashes [][32]byte) [32]byte {
	if len(hashes) == 0 {
		return [32]byte{}
	}
	if len(hashes) == 1 {
		return hashes[0]
	}

	// Pad to even number by duplicating last hash
	if len(hashes)%2 == 1 {
		hashes = append(hashes, hashes[len(hashes)-1])
	}

	// Build next level
	nextLevel := make([][32]byte, len(hashes)/2)
	for i := 0; i < len(hashes); i += 2 {
		combined := make([]byte, 64)
		copy(combined[0:32], hashes[i][:])
		copy(combined[32:64], hashes[i+1][:])
		nextLevel[i/2] = sha3.Sum256(combined)
	}

	return computeMerkleRoot(nextLevel)
}

// ============================================================================
// Block Validation
// ============================================================================

// ValidateBlock validates a block against the chain state
func ValidateBlock(block *Block, chain *Chain) error {
	header := &block.Header

	// Version check
	if header.Version == 0 {
		return fmt.Errorf("invalid block version")
	}

	// Height check
	if header.Height != chain.Height()+1 {
		return fmt.Errorf("invalid height: expected %d, got %d", chain.Height()+1, header.Height)
	}

	// Previous hash check
	if header.PrevHash != chain.BestHash() {
		return fmt.Errorf("invalid prev hash: does not link to best block")
	}

	// Timestamp validation
	if err := validateTimestamp(header, chain); err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}

	// Difficulty check
	expectedDiff := chain.NextDifficulty()
	if header.Difficulty != expectedDiff {
		return fmt.Errorf("invalid difficulty: expected %d, got %d", expectedDiff, header.Difficulty)
	}

	// PoW check
	if !validatePoW(header) {
		return fmt.Errorf("invalid proof of work")
	}

	// Block size check
	if block.Size() > MaxBlockSize {
		return fmt.Errorf("block too large: %d > %d", block.Size(), MaxBlockSize)
	}

	// Must have at least one transaction (coinbase)
	if len(block.Transactions) == 0 {
		return fmt.Errorf("block has no transactions")
	}

	// First transaction must be coinbase
	if !block.Transactions[0].IsCoinbase() {
		return fmt.Errorf("first transaction is not coinbase")
	}

	// No other transaction can be coinbase
	for i := 1; i < len(block.Transactions); i++ {
		if block.Transactions[i].IsCoinbase() {
			return fmt.Errorf("multiple coinbase transactions")
		}
	}

	// Merkle root check
	merkleRoot, err := block.ComputeMerkleRoot()
	if err != nil {
		return fmt.Errorf("failed to compute merkle root: %w", err)
	}
	if merkleRoot != header.MerkleRoot {
		return fmt.Errorf("invalid merkle root")
	}

	// Validate all transactions
	for i, tx := range block.Transactions {
		if err := ValidateTransaction(tx, chain.IsKeyImageSpent); err != nil {
			return fmt.Errorf("invalid transaction %d: %w", i, err)
		}
	}

	return nil
}

// validateTimestamp checks block timestamp against rules
func validateTimestamp(header *BlockHeader, chain *Chain) error {
	// Must be greater than median of last 11 blocks
	medianTime := chain.MedianTimestamp(11)
	if header.Timestamp <= medianTime {
		return fmt.Errorf("timestamp %d <= median %d", header.Timestamp, medianTime)
	}

	// Must not be too far in future
	maxTime := time.Now().Add(TimestampFuturLimit).Unix()
	if header.Timestamp > maxTime {
		return fmt.Errorf("timestamp too far in future")
	}

	return nil
}

// validatePoW checks if block meets PoW difficulty using Argon2id
// This is computationally expensive (~2-3 seconds with 2GB memory)
func validatePoW(header *BlockHeader) bool {
	// Compute Argon2id hash
	headerBytes := header.SerializeForPoW()
	hash, err := PowHash(headerBytes, header.Nonce)
	if err != nil {
		return false
	}

	// Check against target
	target := DifficultyToTarget(header.Difficulty)
	return PowCheckTarget(hash, target)
}

// ============================================================================
// Chain State
// ============================================================================

// Chain represents the blockchain state
type Chain struct {
	mu sync.RWMutex

	// Persistent storage (bbolt)
	storage *Storage

	// In-memory caches for performance
	blocks map[[32]byte]*Block // hash -> block (recent blocks cache)
	workAt map[[32]byte]uint64 // hash -> cumulative work at this block

	// Main chain only
	byHeight   map[uint64][32]byte // height -> hash (main chain only)
	timestamps []int64             // recent timestamps for median calc

	// Chain state
	bestHash  [32]byte
	height    uint64
	totalWork uint64

	// Key image set (for double-spend checking)
	keyImages map[[32]byte]uint64 // key_image -> height spent
}

// NewChain creates a new chain, loading state from storage
func NewChain(dataDir string) (*Chain, error) {
	storage, err := NewStorage(dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open storage: %w", err)
	}

	c := &Chain{
		storage:    storage,
		blocks:     make(map[[32]byte]*Block),
		workAt:     make(map[[32]byte]uint64),
		byHeight:   make(map[uint64][32]byte),
		timestamps: make([]int64, 0, LWMAWindow+1),
		keyImages:  make(map[[32]byte]uint64),
	}

	// Load chain state from storage
	if err := c.loadFromStorage(); err != nil {
		storage.Close()
		return nil, fmt.Errorf("failed to load chain state: %w", err)
	}

	return c, nil
}

// loadFromStorage loads chain state from disk
func (c *Chain) loadFromStorage() error {
	tipHash, tipHeight, tipWork, found := c.storage.GetTip()
	if !found {
		// Fresh chain - no state to load
		return nil
	}

	c.bestHash = tipHash
	c.height = tipHeight
	c.totalWork = tipWork

	// Load recent blocks for LWMA calculation and height index
	startHeight := uint64(0)
	if tipHeight > uint64(LWMAWindow+10) {
		startHeight = tipHeight - uint64(LWMAWindow+10)
	}

	for h := startHeight; h <= tipHeight; h++ {
		hash, found := c.storage.GetBlockHashByHeight(h)
		if !found {
			return fmt.Errorf("block at height %d not found", h)
		}

		block, err := c.storage.GetBlock(hash)
		if err != nil {
			return fmt.Errorf("failed to load block %d: %w", h, err)
		}
		if block == nil {
			return fmt.Errorf("block %x not found", hash[:8])
		}

		c.blocks[hash] = block
		c.byHeight[h] = hash

		// Calculate work
		var parentWork uint64
		if h > 0 {
			parentWork = c.workAt[block.Header.PrevHash]
		}
		c.workAt[hash] = parentWork + block.Header.Difficulty

		// Track timestamps for LWMA
		c.timestamps = append(c.timestamps, block.Header.Timestamp)
		if len(c.timestamps) > LWMAWindow+1 {
			c.timestamps = c.timestamps[1:]
		}

		// Load key images from transactions
		for _, tx := range block.Transactions {
			if !tx.IsCoinbase() {
				for _, input := range tx.Inputs {
					c.keyImages[input.KeyImage] = h
				}
			}
		}
	}

	return nil
}

// Close closes the chain storage
func (c *Chain) Close() error {
	if c.storage != nil {
		return c.storage.Close()
	}
	return nil
}

// Storage returns the underlying storage (for direct access if needed)
func (c *Chain) Storage() *Storage {
	return c.storage
}

// Height returns current chain height
func (c *Chain) Height() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.height
}

// HasGenesis returns true if the chain has at least the genesis block
func (c *Chain) HasGenesis() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check if we have a tip stored
	_, _, _, found := c.storage.GetTip()
	return found
}

// BestHash returns the hash of the best block
func (c *Chain) BestHash() [32]byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.bestHash
}

// GetBlock retrieves a block by hash
func (c *Chain) GetBlock(hash [32]byte) *Block {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check memory cache first
	if block, ok := c.blocks[hash]; ok {
		return block
	}

	// Fall back to storage
	block, _ := c.storage.GetBlock(hash)
	if block != nil {
		c.blocks[hash] = block // Cache it
	}
	return block
}

// GetBlockByHeight retrieves a block by height
func (c *Chain) GetBlockByHeight(height uint64) *Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.getBlockByHeightLocked(height)
}

// getBlockByHeightLocked is the lock-free inner implementation.
// Caller must hold at least c.mu.RLock.
func (c *Chain) getBlockByHeightLocked(height uint64) *Block {
	// Check memory cache first
	if hash, ok := c.byHeight[height]; ok {
		if block, ok := c.blocks[hash]; ok {
			return block
		}
	}

	// Fall back to storage
	hash, found := c.storage.GetBlockHashByHeight(height)
	if !found {
		return nil
	}
	block, _ := c.storage.GetBlock(hash)
	if block != nil {
		c.blocks[hash] = block
		c.byHeight[height] = hash
	}
	return block
}

// MedianTimestamp returns median of last n block timestamps
func (c *Chain) MedianTimestamp(n int) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.timestamps) == 0 {
		return 0
	}

	count := n
	if count > len(c.timestamps) {
		count = len(c.timestamps)
	}

	// Get last n timestamps
	recent := make([]int64, count)
	copy(recent, c.timestamps[len(c.timestamps)-count:])

	// Sort and get median
	for i := 0; i < len(recent); i++ {
		for j := i + 1; j < len(recent); j++ {
			if recent[i] > recent[j] {
				recent[i], recent[j] = recent[j], recent[i]
			}
		}
	}

	return recent[len(recent)/2]
}

// NextDifficulty calculates the difficulty for the next block
// NextDifficulty calculates difficulty using LWMA (Linear Weighted Moving Average)
// Based on Zawy's algorithm used by TurtleCoin, Monero, and many other coins.
//
// LWMA gives more weight to recent blocks, making it responsive to hashrate changes
// while being resistant to timestamp manipulation and oscillation attacks.
func (c *Chain) NextDifficulty() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Not enough blocks for LWMA - use minimum difficulty
	if c.height < uint64(LWMAWindow) {
		return MinDifficulty
	}

	// Collect the last LWMAWindow+1 blocks (need N+1 to get N solve times)
	blocks := make([]*Block, LWMAWindow+1)
	for i := 0; i <= LWMAWindow; i++ {
		height := c.height - uint64(LWMAWindow) + uint64(i)
		hash := c.byHeight[height]
		blocks[i] = c.blocks[hash]
	}

	// Calculate weighted sum of solve times and sum of difficulties
	var weightedSolvetimeSum int64
	var difficultySum uint64
	weightSum := int64(LWMAWindow * (LWMAWindow + 1) / 2) // Sum of 1..N

	for i := 1; i <= LWMAWindow; i++ {
		// Solve time for this block
		solvetime := blocks[i].Header.Timestamp - blocks[i-1].Header.Timestamp

		// Clamp solve time to prevent manipulation
		// Min: prevent negative or zero (timestamp attacks)
		// Max: prevent huge drops from network stalls
		if solvetime < LWMAMinSolvetime {
			solvetime = LWMAMinSolvetime
		}
		if solvetime > LWMAMaxSolvetime {
			solvetime = LWMAMaxSolvetime
		}

		// Weight increases linearly: block 1 has weight 1, block N has weight N
		weight := int64(i)
		weightedSolvetimeSum += solvetime * weight

		// Sum difficulties for averaging
		difficultySum += blocks[i].Header.Difficulty
	}

	// Calculate new difficulty
	// Formula: new_diff = avg_diff * target_time * weight_sum / weighted_solvetime_sum
	//
	// This adjusts difficulty proportionally:
	// - If blocks came too fast (weighted_solvetime_sum < expected), increase difficulty
	// - If blocks came too slow (weighted_solvetime_sum > expected), decrease difficulty
	avgDifficulty := difficultySum / uint64(LWMAWindow)
	expectedWeightedSum := int64(BlockIntervalSec) * weightSum

	// Prevent division by zero
	if weightedSolvetimeSum < 1 {
		weightedSolvetimeSum = 1
	}

	newDiff := avgDifficulty * uint64(expectedWeightedSum) / uint64(weightedSolvetimeSum)

	// Enforce minimum difficulty
	if newDiff < MinDifficulty {
		newDiff = MinDifficulty
	}

	return newDiff
}

// AddBlock adds a validated block to the chain
// AddBlock adds a block to the main chain (used for initial sync/genesis)
// For normal operation, use ProcessBlock which handles forks
func (c *Chain) AddBlock(block *Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.addBlockInternal(block)
}

// addBlockInternal adds block to main chain (caller holds lock)
func (c *Chain) addBlockInternal(block *Block) error {
	hash := block.Hash()

	// Calculate cumulative work
	var parentWork uint64
	if block.Header.Height > 0 {
		parentWork = c.workAt[block.Header.PrevHash]
	}
	blockWork := parentWork + block.Header.Difficulty

	// Collect outputs and key images from transactions
	var newOutputs []*UTXO
	var spentKeyImages [][32]byte

	for _, tx := range block.Transactions {
		txid, _ := tx.TxID()

		// Collect outputs
		for idx, out := range tx.Outputs {
			newOutputs = append(newOutputs, &UTXO{
				TxID:        txid,
				OutputIndex: uint32(idx),
				Output:      out,
				BlockHeight: block.Header.Height,
			})
		}

		// Collect key images (except coinbase)
		if !tx.IsCoinbase() {
			for _, input := range tx.Inputs {
				spentKeyImages = append(spentKeyImages, input.KeyImage)
				c.keyImages[input.KeyImage] = block.Header.Height
			}
		}
	}

	// Commit to storage atomically
	commit := &BlockCommit{
		Block:        block,
		Height:       block.Header.Height,
		Hash:         hash,
		Work:         blockWork,
		IsMainTip:    true,
		NewOutputs:   newOutputs,
		SpentKeyImgs: spentKeyImages,
	}

	if err := c.storage.CommitBlock(commit); err != nil {
		return fmt.Errorf("failed to persist block: %w", err)
	}

	// Update in-memory state
	c.blocks[hash] = block
	c.workAt[hash] = blockWork
	c.byHeight[block.Header.Height] = hash
	c.bestHash = hash
	c.height = block.Header.Height
	c.totalWork = blockWork

	// Track timestamp for LWMA
	c.timestamps = append(c.timestamps, block.Header.Timestamp)
	if len(c.timestamps) > LWMAWindow+1 {
		c.timestamps = c.timestamps[1:]
	}

	return nil
}

// ProcessBlock validates and adds a block, handling fork choice
// Returns true if block was accepted (even if not on main chain)
func (c *Chain) ProcessBlock(block *Block) (accepted bool, isMainChain bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	hash := block.Hash()

	// Already have this block? Check memory and storage
	if _, exists := c.blocks[hash]; exists {
		return false, false, nil
	}
	if c.storage.HasBlock(hash) {
		return false, false, nil
	}

	// Must have parent (except genesis)
	if block.Header.Height > 0 {
		hasParent := false
		if _, ok := c.blocks[block.Header.PrevHash]; ok {
			hasParent = true
		} else if c.storage.HasBlock(block.Header.PrevHash) {
			// Load parent into cache
			parent, _ := c.storage.GetBlock(block.Header.PrevHash)
			if parent != nil {
				c.blocks[block.Header.PrevHash] = parent
				hasParent = true
			}
		}
		if !hasParent {
			// Orphan block - return special error so caller can handle appropriately
			return false, false, ErrOrphanBlock
		}
	}

	// Calculate work at this block
	var parentWork uint64
	if block.Header.Height > 0 {
		parentWork = c.workAt[block.Header.PrevHash]
	}
	blockWork := parentWork + block.Header.Difficulty

	// Store block in memory (always, even if not main chain)
	c.blocks[hash] = block
	c.workAt[hash] = blockWork

	// Does this create a heavier chain?
	if blockWork > c.totalWork {
		// Need to reorganize to this chain
		if err := c.reorganizeTo(hash); err != nil {
			// Reorg failed - remove from memory
			delete(c.blocks, hash)
			delete(c.workAt, hash)
			return false, false, fmt.Errorf("reorg failed: %w", err)
		}
		return true, true, nil
	}

	// Block accepted but not on main chain (fork) - still save to storage
	if err := c.storage.SaveBlock(block); err != nil {
		return false, false, fmt.Errorf("failed to save fork block: %w", err)
	}

	return true, false, nil
}

// reorganizeTo switches the main chain to end at newTip
func (c *Chain) reorganizeTo(newTip [32]byte) error {
	// Find common ancestor between current tip and new tip
	currentPath := c.getAncestorPath(c.bestHash)
	newPath := c.getAncestorPath(newTip)

	if currentPath == nil || newPath == nil {
		return fmt.Errorf("incomplete chain: cannot build ancestor path for reorg")
	}

	// Find where they diverge
	commonHeight := uint64(0)
	for h := uint64(0); h <= min(c.height, c.blocks[newTip].Header.Height); h++ {
		if h < uint64(len(currentPath)) && h < uint64(len(newPath)) {
			if currentPath[h] == newPath[h] {
				commonHeight = h
			} else {
				break
			}
		}
	}

	// Collect blocks to disconnect
	var disconnect []*Block
	for h := c.height; h > commonHeight; h-- {
		block := c.blocks[c.byHeight[h]]
		disconnect = append(disconnect, block)
	}

	// Collect blocks to connect
	newBlock := c.blocks[newTip]
	var connect []*Block
	for h := newBlock.Header.Height; h > commonHeight; h-- {
		connect = append([]*Block{c.blocks[newPath[h]]}, connect...)
	}

	// Commit reorg atomically to storage
	reorgCommit := &ReorgCommit{
		Disconnect: disconnect,
		Connect:    connect,
		NewTip:     newTip,
		NewHeight:  newBlock.Header.Height,
		NewWork:    c.workAt[newTip],
	}

	if err := c.storage.CommitReorg(reorgCommit); err != nil {
		return fmt.Errorf("failed to persist reorg: %w", err)
	}

	// Update in-memory state

	// Remove disconnected blocks from height index and key images
	for _, block := range disconnect {
		delete(c.byHeight, block.Header.Height)
		for _, tx := range block.Transactions {
			if !tx.IsCoinbase() {
				for _, input := range tx.Inputs {
					delete(c.keyImages, input.KeyImage)
				}
			}
		}
	}

	// Add connected blocks to height index and key images
	for _, block := range connect {
		hash := block.Hash()
		c.byHeight[block.Header.Height] = hash
		c.timestamps = append(c.timestamps, block.Header.Timestamp)
		if len(c.timestamps) > LWMAWindow+1 {
			c.timestamps = c.timestamps[1:]
		}
		for _, tx := range block.Transactions {
			if !tx.IsCoinbase() {
				for _, input := range tx.Inputs {
					c.keyImages[input.KeyImage] = block.Header.Height
				}
			}
		}
	}

	// Update chain state
	c.bestHash = newTip
	c.height = newBlock.Header.Height
	c.totalWork = c.workAt[newTip]

	return nil
}

// getAncestorPath returns array of block hashes from genesis to the given hash
func (c *Chain) getAncestorPath(tip [32]byte) [][32]byte {
	block, exists := c.blocks[tip]
	if !exists {
		if b, _ := c.storage.GetBlock(tip); b != nil {
			c.blocks[tip] = b
			block = b
		} else {
			return nil
		}
	}

	path := make([][32]byte, block.Header.Height+1)
	current := tip
	for {
		b, exists := c.blocks[current]
		if !exists {
			if loaded, _ := c.storage.GetBlock(current); loaded != nil {
				c.blocks[current] = loaded
				b = loaded
			} else {
				return nil
			}
		}
		path[b.Header.Height] = current
		if b.Header.Height == 0 {
			break
		}
		current = b.Header.PrevHash
	}
	return path
}

// TotalWork returns the cumulative work of the main chain
func (c *Chain) TotalWork() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.totalWork
}

// HasBlock returns true if the block is known (on any chain)
func (c *Chain) HasBlock(hash [32]byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, exists := c.blocks[hash]; exists {
		return true
	}
	return c.storage.HasBlock(hash)
}

// IsKeyImageSpent checks if a key image has been used (double-spend check)
func (c *Chain) IsKeyImageSpent(keyImage [32]byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check memory first
	if _, exists := c.keyImages[keyImage]; exists {
		return true
	}

	// Check storage
	spent, _ := c.storage.IsKeyImageSpent(keyImage)
	return spent
}

// GetAllOutputs returns all outputs for ring member selection
func (c *Chain) GetAllOutputs() ([]*UTXO, error) {
	return c.storage.GetAllOutputs()
}

// SelectRingMembersWithCommitments selects ring members for a transaction input
func (c *Chain) SelectRingMembersWithCommitments(realPubKey, realCommitment [32]byte) (*RingMemberData, error) {
	allOutputs, err := c.storage.GetAllOutputs()
	if err != nil {
		return nil, fmt.Errorf("failed to get outputs: %w", err)
	}

	ringSize := RingSize

	// Filter out the real key from decoy selection
	decoyPool := make([]*UTXO, 0, len(allOutputs))
	for _, utxo := range allOutputs {
		if utxo.Output.PublicKey != realPubKey {
			decoyPool = append(decoyPool, utxo)
		}
	}

	if len(decoyPool) < ringSize-1 {
		return nil, fmt.Errorf("not enough outputs for ring (need %d, have %d)", ringSize-1, len(decoyPool))
	}

	// Cryptographically secure shuffle using Fisher-Yates with crypto/rand
	for i := len(decoyPool) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, fmt.Errorf("secure random failed: %w", err)
		}
		j := int(jBig.Int64())
		decoyPool[i], decoyPool[j] = decoyPool[j], decoyPool[i]
	}
	decoys := decoyPool[:ringSize-1]

	// Create ring with random position for real key (crypto/rand)
	secretIdxBig, err := rand.Int(rand.Reader, big.NewInt(int64(ringSize)))
	if err != nil {
		return nil, fmt.Errorf("secure random failed: %w", err)
	}
	secretIndex := int(secretIdxBig.Int64())
	keys := make([][32]byte, ringSize)
	commitments := make([][32]byte, ringSize)

	decoyIdx := 0
	for i := 0; i < ringSize; i++ {
		if i == secretIndex {
			keys[i] = realPubKey
			commitments[i] = realCommitment
		} else {
			keys[i] = decoys[decoyIdx].Output.PublicKey
			commitments[i] = decoys[decoyIdx].Output.Commitment
			decoyIdx++
		}
	}

	return &RingMemberData{
		Keys:        keys,
		Commitments: commitments,
		SecretIndex: secretIndex,
	}, nil
}

// IsFinalized returns true if a block at given height is beyond reorg depth
func (c *Chain) IsFinalized(height uint64) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.height < height {
		return false
	}
	return c.height-height >= MaxReorgDepth
}

// FindTxByHashStr searches for a transaction by hex hash string, scanning
// blocks from tip backwards. Returns the transaction, block height, and
// whether it was found.
func (c *Chain) FindTxByHashStr(hashStr string) (*Transaction, uint64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for h := c.height; ; h-- {
		block := c.getBlockByHeightLocked(h)
		if block == nil {
			if h == 0 {
				break
			}
			continue
		}

		for _, tx := range block.Transactions {
			txID, err := tx.TxID()
			if err != nil {
				continue
			}
			if fmt.Sprintf("%x", txID) == hashStr {
				return tx, h, true
			}
		}

		if h == 0 {
			break
		}
	}
	return nil, 0, false
}

// ============================================================================
// Genesis Block
// ============================================================================

// Source: https://cnbc.com/2026/02/02/bitcoin-btc-price-today-cryptocurrency.html
const GenesisMessage = "CNBC 02/Feb/2026 Bitcoin is coming off a brutal week"

// GenesisPrevHash returns SHA3-256(GenesisMessage)
func GenesisPrevHash() [32]byte {
	return sha3.Sum256([]byte(GenesisMessage))
}

// GenesisTimestamp is the fixed genesis block timestamp (Feb 5, 2026 00:00:00 UTC)
const GenesisTimestamp int64 = 1770249600

// GetGenesisBlock returns the hardcoded genesis block (same for all nodes)
func GetGenesisBlock() (*Block, error) {
	// Genesis has no transactions - no coinbase, no burned coins
	// First real block at height 1 will have the first coinbase
	block := &Block{
		Header: BlockHeader{
			Version:    1,
			Height:     0,
			PrevHash:   GenesisPrevHash(),
			Timestamp:  GenesisTimestamp,
			Difficulty: MinDifficulty,
			Nonce:      0,
		},
		Transactions: []*Transaction{},
	}

	// Empty merkle root for no transactions
	block.Header.MerkleRoot = [32]byte{}

	return block, nil
}

// CreateGenesisBlock creates a genesis block (for testing - use GetGenesisBlock for mainnet)
func CreateGenesisBlock(minerSpendPub, minerViewPub [32]byte, reward uint64) (*Block, error) {
	// Create coinbase for genesis
	coinbase, err := CreateCoinbase(minerSpendPub, minerViewPub, reward)
	if err != nil {
		return nil, fmt.Errorf("failed to create genesis coinbase: %w", err)
	}

	block := &Block{
		Header: BlockHeader{
			Version:    1,
			Height:     0,
			PrevHash:   GenesisPrevHash(),
			Timestamp:  time.Now().Unix(),
			Difficulty: MinDifficulty,
			Nonce:      0,
		},
		Transactions: []*Transaction{coinbase.Tx},
	}

	// Compute merkle root
	merkleRoot, err := block.ComputeMerkleRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to compute merkle root: %w", err)
	}
	block.Header.MerkleRoot = merkleRoot

	return block, nil
}

// ============================================================================
// Transaction Size (add to transaction.go or here)
// ============================================================================

// Size returns the approximate serialized size of a transaction
func (tx *Transaction) Size() int {
	// Rough estimate:
	// - Version: 4 bytes
	// - Each input: 32 (keyimage) + ringSize * 32 (ring) + sig bytes
	// - Each output: 32 (commitment) + 32 (pubkey) + rangeproof bytes
	// - Fee: 8 bytes
	// - TxPubKey: 32 bytes

	size := 4 + 8 + 32 // version + fee + txpubkey

	for _, in := range tx.Inputs {
		size += 32 // key image
		size += len(in.RingMembers) * 32
		size += len(in.RingSignature)
	}

	for _, out := range tx.Outputs {
		size += 32 // commitment
		size += 32 // pubkey
		size += len(out.RangeProof)
	}

	return size
}
