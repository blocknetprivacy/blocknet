package main

import (
	"container/heap"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// MempoolConfig configures the mempool
type MempoolConfig struct {
	// MaxSize is the maximum number of transactions
	MaxSize int

	// MaxSizeBytes is the maximum total size in bytes
	MaxSizeBytes int

	// MinFeeRate is the minimum fee per byte to accept
	MinFeeRate uint64

	// ExpirationTime is how long a tx stays in mempool
	ExpirationTime time.Duration
}

// DefaultMempoolConfig returns sensible defaults
func DefaultMempoolConfig() MempoolConfig {
	return MempoolConfig{
		MaxSize:        5000,
		MaxSizeBytes:   100 * 1024 * 1024, // 100 MB
		MinFeeRate:     1,                 // 1 unit per byte
		ExpirationTime: 24 * time.Hour,
	}
}

// TxAuxData holds auxiliary metadata for a transaction (not part of TxID)
type TxAuxData struct {
	// PaymentIDs maps output index to encrypted payment ID
	PaymentIDs map[int][8]byte
}

// MempoolEntry represents a transaction in the mempool
type MempoolEntry struct {
	Tx      *Transaction
	TxID    [32]byte   // Transaction ID hash
	TxData  []byte     // Serialized transaction
	Fee     uint64     // Transaction fee
	FeeRate uint64     // Fee per byte
	Size    int        // Size in bytes
	AddedAt time.Time  // When added to mempool
	Height  uint64     // Block height when added
	Aux     *TxAuxData // Optional auxiliary data (payment IDs)

	// For priority queue
	index int
}

// Mempool stores unconfirmed transactions
type Mempool struct {
	mu sync.RWMutex

	config MempoolConfig

	// Transaction storage
	txByID    map[[32]byte]*MempoolEntry // TxID -> Entry
	txByImage map[[32]byte][32]byte      // KeyImage -> TxID (for double-spend detection)

	// Priority queue (highest fee rate first)
	priorityQueue txPriorityQueue

	// Key image checker for validation (provided by chain)
	isKeyImageSpent KeyImageChecker

	// Stats
	totalSize int // Total bytes in mempool
}

// NewMempool creates a new mempool
func NewMempool(cfg MempoolConfig, isSpent KeyImageChecker) *Mempool {
	return &Mempool{
		config:          cfg,
		txByID:          make(map[[32]byte]*MempoolEntry),
		txByImage:       make(map[[32]byte][32]byte),
		priorityQueue:   make(txPriorityQueue, 0),
		isKeyImageSpent: isSpent,
	}
}

// AddTransaction adds a transaction to the mempool.
// aux is optional auxiliary data (e.g. encrypted payment IDs).
func (m *Mempool) AddTransaction(tx *Transaction, txData []byte, aux ...*TxAuxData) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	txID, err := tx.TxID()
	if err != nil {
		return fmt.Errorf("failed to get tx ID: %w", err)
	}

	// Check if already in mempool
	if _, exists := m.txByID[txID]; exists {
		return nil // Already have it
	}

	// Check for double-spend with mempool txs
	for _, input := range tx.Inputs {
		if existingTxID, exists := m.txByImage[input.KeyImage]; exists {
			return fmt.Errorf("double-spend: key image already in mempool (tx %x...)", existingTxID[:8])
		}
	}

	// Validate against UTXO set (doesn't modify it)
	if !tx.IsCoinbase() {
		if err := ValidateTransaction(tx, m.isKeyImageSpent); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}

	// Calculate fee rate
	size := len(txData)
	feeRate := tx.Fee / uint64(size)
	if feeRate < m.config.MinFeeRate {
		return fmt.Errorf("fee rate too low: %d < %d", feeRate, m.config.MinFeeRate)
	}

	// Check mempool limits
	if len(m.txByID) >= m.config.MaxSize {
		// Try to evict lowest fee rate tx
		if !m.evictLowest(feeRate) {
			return fmt.Errorf("mempool full")
		}
	}

	if m.totalSize+size > m.config.MaxSizeBytes {
		// Try to make room
		for m.totalSize+size > m.config.MaxSizeBytes && len(m.priorityQueue) > 0 {
			if !m.evictLowest(feeRate) {
				return fmt.Errorf("mempool size limit exceeded")
			}
		}
	}

	// Add to mempool
	entry := &MempoolEntry{
		Tx:      tx,
		TxID:    txID,
		TxData:  txData,
		Fee:     tx.Fee,
		FeeRate: feeRate,
		Size:    size,
		AddedAt: time.Now(),
	}
	if len(aux) > 0 && aux[0] != nil {
		entry.Aux = aux[0]
	}

	m.txByID[txID] = entry
	for _, input := range tx.Inputs {
		m.txByImage[input.KeyImage] = txID
	}
	heap.Push(&m.priorityQueue, entry)
	m.totalSize += size

	return nil
}

// evictLowest removes the lowest fee rate transaction if it's lower than minFeeRate
func (m *Mempool) evictLowest(minFeeRate uint64) bool {
	if len(m.priorityQueue) == 0 {
		return false
	}

	// Peek at lowest
	// Note: our heap is max-heap by fee rate, so we need min-heap for eviction
	// For simplicity, we'll just remove oldest if at capacity
	var oldest *MempoolEntry
	var oldestID [32]byte
	for id, entry := range m.txByID {
		if oldest == nil || entry.AddedAt.Before(oldest.AddedAt) {
			oldest = entry
			oldestID = id
		}
	}

	if oldest != nil && oldest.FeeRate < minFeeRate {
		m.removeTxByID(oldestID)
		return true
	}

	return false
}

// removeTxByID removes a transaction from mempool by ID
func (m *Mempool) removeTxByID(txID [32]byte) {
	entry, exists := m.txByID[txID]
	if !exists {
		return
	}

	delete(m.txByID, txID)
	for _, input := range entry.Tx.Inputs {
		delete(m.txByImage, input.KeyImage)
	}
	m.totalSize -= entry.Size

	// Remove from priority queue
	if entry.index >= 0 && entry.index < len(m.priorityQueue) {
		heap.Remove(&m.priorityQueue, entry.index)
	}
}

// RemoveTransaction removes a transaction by ID
func (m *Mempool) RemoveTransaction(txID [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeTxByID(txID)
}

// RemoveTransactions removes multiple transactions
func (m *Mempool) RemoveTransactions(txIDs [][32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, txID := range txIDs {
		m.removeTxByID(txID)
	}
}

// RemoveByKeyImage removes any transaction using a specific key image
func (m *Mempool) RemoveByKeyImage(keyImage [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if txID, exists := m.txByImage[keyImage]; exists {
		m.removeTxByID(txID)
	}
}

// GetTransaction returns a transaction by ID
func (m *Mempool) GetTransaction(txID [32]byte) (*Transaction, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.txByID[txID]
	if !exists {
		return nil, false
	}
	return entry.Tx, true
}

// GetTransactionWithAux returns a transaction and its aux data by ID
func (m *Mempool) GetTransactionWithAux(txID [32]byte) (*Transaction, *TxAuxData, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.txByID[txID]
	if !exists {
		return nil, nil, false
	}
	return entry.Tx, entry.Aux, true
}

// HasTransaction checks if a transaction is in the mempool
func (m *Mempool) HasTransaction(txID [32]byte) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.txByID[txID]
	return exists
}

// HasKeyImage checks if a key image is used by any mempool tx
func (m *Mempool) HasKeyImage(keyImage [32]byte) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.txByImage[keyImage]
	return exists
}

// GetTransactionsForBlock returns transactions and their aux data for mining,
// sorted by fee rate. The returned auxData maps txID to TxAuxData for
// transactions that carry payment IDs.
func (m *Mempool) GetTransactionsForBlock(maxSize int, maxCount int) ([]*Transaction, map[[32]byte]*TxAuxData) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Collect entries sorted by fee rate (priority queue gives us this)
	entries := make([]*MempoolEntry, 0, len(m.txByID))
	for _, entry := range m.txByID {
		entries = append(entries, entry)
	}

	// Sort by fee rate descending
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].FeeRate > entries[i].FeeRate {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Select transactions
	result := make([]*Transaction, 0, maxCount)
	auxData := make(map[[32]byte]*TxAuxData)
	totalSize := 0

	for _, entry := range entries {
		if len(result) >= maxCount {
			break
		}
		if totalSize+entry.Size > maxSize {
			continue // Skip, try next
		}

		result = append(result, entry.Tx)
		totalSize += entry.Size

		if entry.Aux != nil {
			auxData[entry.TxID] = entry.Aux
		}
	}

	return result, auxData
}

// Size returns the number of transactions in mempool
func (m *Mempool) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.txByID)
}

// SizeBytes returns the total size in bytes
func (m *Mempool) SizeBytes() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.totalSize
}

// Clear removes all transactions
func (m *Mempool) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.txByID = make(map[[32]byte]*MempoolEntry)
	m.txByImage = make(map[[32]byte][32]byte)
	m.priorityQueue = make(txPriorityQueue, 0)
	m.totalSize = 0
}

// RemoveExpired removes transactions that have been in mempool too long
func (m *Mempool) RemoveExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-m.config.ExpirationTime)
	removed := 0

	// Collect IDs to remove (can't modify map while iterating)
	var toRemove [][32]byte
	for txID, entry := range m.txByID {
		if entry.AddedAt.Before(cutoff) {
			toRemove = append(toRemove, txID)
		}
	}

	for _, txID := range toRemove {
		m.removeTxByID(txID)
		removed++
	}

	return removed
}

// OnBlockConnected updates mempool when a block is connected
// Removes transactions that were included in the block
func (m *Mempool) OnBlockConnected(block *Block) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, tx := range block.Transactions {
		txID, err := tx.TxID()
		if err != nil {
			continue
		}
		if _, exists := m.txByID[txID]; exists {
			m.removeTxByID(txID)
		}

		// Also remove by key images (in case of double-spend attempts)
		for _, input := range tx.Inputs {
			if existingTxID, exists := m.txByImage[input.KeyImage]; exists {
				m.removeTxByID(existingTxID)
			}
		}
	}
}

// OnBlockDisconnected updates mempool when a block is disconnected (reorg)
// Re-adds valid transactions from the disconnected block
func (m *Mempool) OnBlockDisconnected(block *Block, txDataMap map[[32]byte][]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, tx := range block.Transactions {
		// Skip coinbase - can't go back to mempool
		if tx.IsCoinbase() {
			continue
		}

		txID, err := tx.TxID()
		if err != nil {
			continue
		}
		// Already present (e.g. gossiped while block was on-chain) - keep existing
		// entry/heap state unchanged.
		if _, exists := m.txByID[txID]; exists {
			continue
		}

		// Get serialized tx data if available
		txData, ok := txDataMap[txID]
		if !ok {
			txData = tx.Serialize()
		}
		txData, aux := DecodeTxWithAux(txData)

		// Check if any inputs are now spent (by another chain)
		// Skip if key images are spent
		valid := true
		for _, input := range tx.Inputs {
			// Keep mempool free of double-spends.
			if existingTxID, exists := m.txByImage[input.KeyImage]; exists && existingTxID != txID {
				valid = false
				break
			}
			if m.isKeyImageSpent(input.KeyImage) {
				valid = false
				break
			}
		}

		if valid {
			// Re-add to mempool (using internal method to avoid double-lock)
			size := len(txData)
			if size == 0 {
				continue
			}
			feeRate := tx.Fee / uint64(size)

			entry := &MempoolEntry{
				Tx:      tx,
				TxID:    txID,
				TxData:  txData,
				Fee:     tx.Fee,
				FeeRate: feeRate,
				Size:    size,
				AddedAt: time.Now(),
				Aux:     aux,
			}

			m.txByID[txID] = entry
			for _, input := range tx.Inputs {
				m.txByImage[input.KeyImage] = txID
			}
			heap.Push(&m.priorityQueue, entry)
			m.totalSize += size
		}
	}
}

// GetAllTransactionData returns all serialized transactions
func (m *Mempool) GetAllTransactionData() [][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([][]byte, 0, len(m.txByID))
	for _, entry := range m.txByID {
		result = append(result, entry.TxData)
	}
	return result
}

// GetAllTransactionDataWithAux returns all serialized transactions with aux data appended
func (m *Mempool) GetAllTransactionDataWithAux() [][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([][]byte, 0, len(m.txByID))
	for _, entry := range m.txByID {
		if entry.Aux != nil {
			result = append(result, EncodeTxWithAux(entry.TxData, entry.Aux))
		} else {
			result = append(result, entry.TxData)
		}
	}
	return result
}

// Stats returns mempool statistics
type MempoolStats struct {
	Count     int     `json:"count"`
	SizeBytes int     `json:"size_bytes"`
	MinFee    uint64  `json:"min_fee"`
	MaxFee    uint64  `json:"max_fee"`
	AvgFee    float64 `json:"avg_fee"`
}

func (m *Mempool) Stats() MempoolStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := MempoolStats{
		Count:     len(m.txByID),
		SizeBytes: m.totalSize,
	}

	if stats.Count == 0 {
		return stats
	}

	var totalFee uint64
	for _, entry := range m.txByID {
		if stats.MinFee == 0 || entry.Fee < stats.MinFee {
			stats.MinFee = entry.Fee
		}
		if entry.Fee > stats.MaxFee {
			stats.MaxFee = entry.Fee
		}
		totalFee += entry.Fee
	}
	stats.AvgFee = float64(totalFee) / float64(stats.Count)

	return stats
}

// GetAllEntries returns all mempool entries sorted by fee rate (highest first)
func (m *Mempool) GetAllEntries() []*MempoolEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entries := make([]*MempoolEntry, 0, len(m.txByID))
	for _, entry := range m.txByID {
		entries = append(entries, entry)
	}

	// Sort by fee rate descending
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].FeeRate > entries[i].FeeRate {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	return entries
}

// MarshalJSON serializes mempool for debugging
func (m *Mempool) MarshalJSON() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data := struct {
		Count     int      `json:"count"`
		SizeBytes int      `json:"size_bytes"`
		TxIDs     []string `json:"tx_ids"`
	}{
		Count:     len(m.txByID),
		SizeBytes: m.totalSize,
		TxIDs:     make([]string, 0, len(m.txByID)),
	}

	for txID := range m.txByID {
		data.TxIDs = append(data.TxIDs, fmt.Sprintf("%x", txID))
	}

	return json.Marshal(data)
}

// Priority queue implementation for mempool

type txPriorityQueue []*MempoolEntry

func (pq txPriorityQueue) Len() int { return len(pq) }

func (pq txPriorityQueue) Less(i, j int) bool {
	// Higher fee rate = higher priority
	return pq[i].FeeRate > pq[j].FeeRate
}

func (pq txPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *txPriorityQueue) Push(x interface{}) {
	n := len(*pq)
	entry := x.(*MempoolEntry)
	entry.index = n
	*pq = append(*pq, entry)
}

func (pq *txPriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	entry := old[n-1]
	old[n-1] = nil
	entry.index = -1
	*pq = old[0 : n-1]
	return entry
}
