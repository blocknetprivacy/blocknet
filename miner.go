package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"sync/atomic"
	"time"
)

// Emission curve: smooth exponential decay
// Target supply: 10M coins over 4 years
// Tail emission: 0.2 coins/block forever
const (
	InitialReward = 72_325_093_035 // 72.33 coins in smallest units
	TailEmission  = 200_000_000    // 0.2 coins
	MonthsToTail  = 48
	DecayRate     = 0.75 // per year
)

// BlocksPerMonth is derived from block interval (defined in block.go)
// ~8766 blocks/month at 5-minute intervals
const BlocksPerMonth = (30 * 24 * 60 * 60) / BlockIntervalSec

// MinerConfig holds mining configuration
type MinerConfig struct {
	// MinerSpendPub is the spend public key for coinbase rewards
	MinerSpendPub [32]byte
	// MinerViewPub is the view public key for coinbase rewards
	MinerViewPub [32]byte
	// Threads is the number of mining threads (0 = auto)
	Threads int
	// PeerCount returns the number of connected peers (nil = skip check)
	PeerCount func() int
}

// MinerStats holds mining statistics
type MinerStats struct {
	HashCount    uint64
	BlocksFound  uint64
	StartTime    time.Time
	LastHashTime time.Time
}

// Miner handles proof of work mining
type Miner struct {
	config  MinerConfig
	chain   *Chain
	mempool *Mempool
	stats   MinerStats
	running atomic.Bool
	cancel  context.CancelFunc
}

// NewMiner creates a new miner
func NewMiner(chain *Chain, mempool *Mempool, config MinerConfig) *Miner {
	return &Miner{
		config:  config,
		chain:   chain,
		mempool: mempool,
		stats: MinerStats{
			StartTime: time.Now(),
		},
	}
}

// MineBlock attempts to mine a single block
// Returns the mined block or nil if cancelled
func (m *Miner) MineBlock(ctx context.Context, mempool []*Transaction) (*Block, error) {
	// Create coinbase transaction
	coinbase, err := CreateCoinbase(m.config.MinerSpendPub, m.config.MinerViewPub, GetBlockReward(m.chain.Height()+1))
	if err != nil {
		return nil, fmt.Errorf("failed to create coinbase: %w", err)
	}

	// Build transaction list (coinbase first)
	txs := make([]*Transaction, 0, len(mempool)+1)
	txs = append(txs, coinbase.Tx)
	txs = append(txs, mempool...)

	// Create block template
	block := &Block{
		Header: BlockHeader{
			Version:    1,
			Height:     m.chain.Height() + 1,
			PrevHash:   m.chain.BestHash(),
			Timestamp:  time.Now().Unix(),
			Difficulty: m.chain.NextDifficulty(),
			Nonce:      0,
		},
		Transactions: txs,
	}

	// Compute merkle root
	merkleRoot, err := block.ComputeMerkleRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to compute merkle root: %w", err)
	}
	block.Header.MerkleRoot = merkleRoot

	// Get target
	target := DifficultyToTarget(block.Header.Difficulty)

	// Serialize header for PoW (without nonce)
	headerBytes := block.Header.SerializeForPoW()

	// Number of mining threads
	// Default to 1 for Argon2id since each hash uses 2GB RAM
	// User can override with config.Threads
	numThreads := m.config.Threads
	if numThreads <= 0 {
		numThreads = 1
	}

	// Channel to receive winning result
	resultChan := make(chan uint64, 1)
	mineCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start mining threads
	for t := 0; t < numThreads; t++ {
		go func(threadID int) {
			nonce := uint64(threadID)
			step := uint64(numThreads)
			localHeader := make([]byte, len(headerBytes))
			copy(localHeader, headerBytes)
			lastTimestamp := block.Header.Timestamp

			for {
				select {
				case <-mineCtx.Done():
					return
				default:
				}

				// Yield to scheduler periodically to keep CLI responsive
				if nonce%uint64(numThreads*10) == uint64(threadID) {
					runtime.Gosched()
				}

				// Compute Argon2id hash
				hash, err := PowHash(localHeader, nonce)
				if err != nil {
					nonce += step
					continue
				}

				atomic.AddUint64(&m.stats.HashCount, 1)

				// Check if we found a valid block
				if PowCheckTarget(hash, target) {
					select {
					case resultChan <- nonce:
					default:
					}
					return
				}

				nonce += step

				// Update timestamp periodically
				if nonce%(step*10) == uint64(threadID) {
					newTime := time.Now().Unix()
					if newTime != lastTimestamp {
						lastTimestamp = newTime
						// Update local header with new timestamp
						binary.LittleEndian.PutUint64(localHeader[40:48], uint64(newTime))
					}
				}
			}
		}(t)
	}

	// Wait for result or cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case winningNonce := <-resultChan:
		block.Header.Nonce = winningNonce
		atomic.AddUint64(&m.stats.BlocksFound, 1)
		m.stats.LastHashTime = time.Now()
		return block, nil
	}
}

// Start begins mining in a background goroutine
func (m *Miner) Start(ctx context.Context, blockChan chan<- *Block) {
	if m.running.Swap(true) {
		return // Already running
	}

	// Create a cancellable context for this mining session
	mineCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	go func() {
		defer m.running.Store(false)
		defer cancel()

		for {
			select {
			case <-mineCtx.Done():
				return
			default:
			}

		// Wait for peers before mining (avoid divergent chains)
		if m.config.PeerCount != nil {
			for m.config.PeerCount() == 0 {
				select {
				case <-mineCtx.Done():
					return
				case <-time.After(5 * time.Second):
					fmt.Println("Waiting for peers before mining...")
				}
			}
		}

		// Get transactions from mempool
		var txs []*Transaction
		if m.mempool != nil {
			txs = m.mempool.GetTransactionsForBlock(MaxBlockSize-1000, 1000) // Leave room for coinbase, max 1000 txs
		}

			block, err := m.MineBlock(mineCtx, txs)
			if err != nil {
				if mineCtx.Err() != nil {
					return // Context cancelled
				}
				fmt.Printf("Mining error: %v\n", err)
				time.Sleep(time.Second)
				continue
			}

			// Send mined block
			select {
			case blockChan <- block:
			case <-mineCtx.Done():
				return
			}
		}
	}()
}

// Stop stops the miner
func (m *Miner) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.running.Store(false)
}

// IsRunning returns true if miner is running
func (m *Miner) IsRunning() bool {
	return m.running.Load()
}

// Stats returns current mining statistics
func (m *Miner) Stats() MinerStats {
	return MinerStats{
		HashCount:    atomic.LoadUint64(&m.stats.HashCount),
		BlocksFound:  atomic.LoadUint64(&m.stats.BlocksFound),
		StartTime:    m.stats.StartTime,
		LastHashTime: m.stats.LastHashTime,
	}
}

// HashRate returns the current hash rate (hashes per second)
func (m *Miner) HashRate() float64 {
	stats := m.Stats()
	elapsed := time.Since(stats.StartTime).Seconds()
	if elapsed < 1 {
		return 0
	}
	return float64(stats.HashCount) / elapsed
}

// GetBlockReward returns the block reward for a given height
// Uses smooth exponential decay to tail emission
func GetBlockReward(height uint64) uint64 {
	month := height / BlocksPerMonth
	if month >= MonthsToTail {
		return TailEmission
	}

	years := float64(month) / 12.0
	decay := math.Exp(-DecayRate * years)
	reward := float64(InitialReward-TailEmission)*decay + float64(TailEmission)

	if reward < float64(TailEmission) {
		return TailEmission
	}
	return uint64(reward)
}
