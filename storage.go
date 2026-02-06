package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

// Bucket names
var (
	bucketBlocks    = []byte("blocks")     // hash -> block bytes
	bucketHeights   = []byte("heights")    // height (big-endian) -> hash (main chain only)
	bucketOutputs   = []byte("outputs")    // outpoint -> output bytes (ALL outputs, for ring selection)
	bucketKeyImages = []byte("key_images") // key_image -> block height (spent tracking)
	bucketMeta      = []byte("meta")       // metadata: tip, height, etc.

	metaKeyTip    = []byte("tip")
	metaKeyHeight = []byte("height")
	metaKeyWork   = []byte("work")
)

// Storage wraps bbolt for chain persistence
type Storage struct {
	db *bolt.DB
}

// NewStorage opens or creates the chain database
func NewStorage(dataDir string) (*Storage, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "chain.db")
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{
		NoSync: false, // Ensure durability
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create buckets
	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{bucketBlocks, bucketHeights, bucketOutputs, bucketKeyImages, bucketMeta} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create buckets: %w", err)
	}

	return &Storage{db: db}, nil
}

// Close closes the database
func (s *Storage) Close() error {
	return s.db.Close()
}

// ============================================================================
// Block Operations
// ============================================================================

// SaveBlock stores a block by its hash
func (s *Storage) SaveBlock(block *Block) error {
	hash := block.Hash()
	data, err := json.Marshal(block)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketBlocks).Put(hash[:], data)
	})
}

// GetBlock retrieves a block by hash
func (s *Storage) GetBlock(hash [32]byte) (*Block, error) {
	var block *Block

	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketBlocks).Get(hash[:])
		if data == nil {
			return nil // Not found
		}
		block = &Block{}
		return json.Unmarshal(data, block)
	})

	return block, err
}

// HasBlock checks if a block exists
func (s *Storage) HasBlock(hash [32]byte) bool {
	var exists bool
	s.db.View(func(tx *bolt.Tx) error {
		exists = tx.Bucket(bucketBlocks).Get(hash[:]) != nil
		return nil
	})
	return exists
}

// ============================================================================
// Height Index (Main Chain Only)
// ============================================================================

// SetMainChainBlock sets the block hash at a height (main chain)
func (s *Storage) SetMainChainBlock(height uint64, hash [32]byte) error {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, height)

	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketHeights).Put(key, hash[:])
	})
}

// GetBlockHashByHeight gets the main chain block hash at height
func (s *Storage) GetBlockHashByHeight(height uint64) ([32]byte, bool) {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, height)

	var hash [32]byte
	var found bool

	s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketHeights).Get(key)
		if data != nil {
			copy(hash[:], data)
			found = true
		}
		return nil
	})

	return hash, found
}

// RemoveMainChainBlock removes a height from main chain index (for reorgs)
func (s *Storage) RemoveMainChainBlock(height uint64) error {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, height)

	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketHeights).Delete(key)
	})
}

// ============================================================================
// Output Operations (Privacy Coin Model)
// In a privacy coin, we store ALL outputs ever created (for ring member selection)
// and track spent key images separately.
// ============================================================================

// outpointKey creates a key from txid and output index
func outpointKey(txid [32]byte, index uint32) []byte {
	key := make([]byte, 36)
	copy(key[:32], txid[:])
	binary.BigEndian.PutUint32(key[32:], index)
	return key
}

// SaveOutput stores an output (never deleted - needed for ring selection)
func (s *Storage) SaveOutput(output *UTXO) error {
	key := outpointKey(output.TxID, output.OutputIndex)
	data, err := json.Marshal(output)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOutputs).Put(key, data)
	})
}

// GetOutput retrieves an output by txid and index
func (s *Storage) GetOutput(txid [32]byte, index uint32) (*UTXO, error) {
	key := outpointKey(txid, index)
	var output *UTXO

	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketOutputs).Get(key)
		if data == nil {
			return nil
		}
		output = &UTXO{}
		return json.Unmarshal(data, output)
	})

	return output, err
}

// GetAllOutputs returns all outputs for ring member selection
func (s *Storage) GetAllOutputs() ([]*UTXO, error) {
	var outputs []*UTXO

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketOutputs)
		return b.ForEach(func(k, v []byte) error {
			output := &UTXO{}
			if err := json.Unmarshal(v, output); err != nil {
				return err
			}
			outputs = append(outputs, output)
			return nil
		})
	})

	return outputs, err
}

// CountOutputs returns total number of outputs
func (s *Storage) CountOutputs() int {
	var count int
	s.db.View(func(tx *bolt.Tx) error {
		count = tx.Bucket(bucketOutputs).Stats().KeyN
		return nil
	})
	return count
}

// ============================================================================
// Key Image Operations (Double-Spend Prevention)
// ============================================================================

// MarkKeyImageSpent records a key image as spent at a block height
func (s *Storage) MarkKeyImageSpent(keyImage [32]byte, height uint64) error {
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, height)

	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketKeyImages).Put(keyImage[:], heightBytes)
	})
}

// IsKeyImageSpent checks if a key image has been used
func (s *Storage) IsKeyImageSpent(keyImage [32]byte) (spent bool, height uint64) {
	s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketKeyImages).Get(keyImage[:])
		if data != nil {
			spent = true
			if len(data) == 8 {
				height = binary.BigEndian.Uint64(data)
			}
		}
		return nil
	})
	return
}

// UnmarkKeyImageSpent removes a key image (for reorgs)
func (s *Storage) UnmarkKeyImageSpent(keyImage [32]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketKeyImages).Delete(keyImage[:])
	})
}

// GetSpentKeyImageCount returns number of spent key images
func (s *Storage) GetSpentKeyImageCount() int {
	var count int
	s.db.View(func(tx *bolt.Tx) error {
		count = tx.Bucket(bucketKeyImages).Stats().KeyN
		return nil
	})
	return count
}

// ============================================================================
// Metadata Operations
// ============================================================================

// GetTip returns the best block hash and height
func (s *Storage) GetTip() (hash [32]byte, height uint64, work uint64, found bool) {
	s.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)

		if data := meta.Get(metaKeyTip); data != nil {
			copy(hash[:], data)
			found = true
		}

		if data := meta.Get(metaKeyHeight); len(data) == 8 {
			height = binary.BigEndian.Uint64(data)
		}

		if data := meta.Get(metaKeyWork); len(data) == 8 {
			work = binary.BigEndian.Uint64(data)
		}

		return nil
	})
	return
}

// SetTip updates the chain tip
func (s *Storage) SetTip(hash [32]byte, height, work uint64) error {
	heightBytes := make([]byte, 8)
	workBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, height)
	binary.BigEndian.PutUint64(workBytes, work)

	return s.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		if err := meta.Put(metaKeyTip, hash[:]); err != nil {
			return err
		}
		if err := meta.Put(metaKeyHeight, heightBytes); err != nil {
			return err
		}
		return meta.Put(metaKeyWork, workBytes)
	})
}

// ============================================================================
// Batch Operations (for atomic block commits)
// Privacy coin model: outputs are never deleted, key images are tracked
// ============================================================================

// BlockCommit represents an atomic block commit with all changes
type BlockCommit struct {
	Block        *Block
	Height       uint64
	Hash         [32]byte
	Work         uint64
	IsMainTip    bool       // Update tip?
	NewOutputs   []*UTXO    // Outputs to add
	SpentKeyImgs [][32]byte // Key images that are spent
}

// CommitBlock atomically writes a block and all related changes
func (s *Storage) CommitBlock(commit *BlockCommit) error {
	blockData, err := json.Marshal(commit.Block)
	if err != nil {
		return err
	}

	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, commit.Height)

	return s.db.Update(func(tx *bolt.Tx) error {
		blocks := tx.Bucket(bucketBlocks)
		heights := tx.Bucket(bucketHeights)
		outputs := tx.Bucket(bucketOutputs)
		keyImages := tx.Bucket(bucketKeyImages)
		meta := tx.Bucket(bucketMeta)

		// Store block
		if err := blocks.Put(commit.Hash[:], blockData); err != nil {
			return err
		}

		// If this is the new main chain tip
		if commit.IsMainTip {
			// Set height -> hash mapping
			if err := heights.Put(heightBytes, commit.Hash[:]); err != nil {
				return err
			}

			// Add new outputs (never deleted)
			for _, out := range commit.NewOutputs {
				key := outpointKey(out.TxID, out.OutputIndex)
				data, err := json.Marshal(out)
				if err != nil {
					return err
				}
				if err := outputs.Put(key, data); err != nil {
					return err
				}
			}

			// Mark key images as spent
			for _, ki := range commit.SpentKeyImgs {
				if err := keyImages.Put(ki[:], heightBytes); err != nil {
					return err
				}
			}

			// Update tip metadata
			workBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(workBytes, commit.Work)

			if err := meta.Put(metaKeyTip, commit.Hash[:]); err != nil {
				return err
			}
			if err := meta.Put(metaKeyHeight, heightBytes); err != nil {
				return err
			}
			if err := meta.Put(metaKeyWork, workBytes); err != nil {
				return err
			}
		}

		return nil
	})
}

// ReorgCommit handles rolling back and applying blocks atomically
type ReorgCommit struct {
	// Blocks to disconnect (key images unmarked, height index removed)
	Disconnect []*Block
	// Blocks to connect (outputs added, key images marked)
	Connect []*Block
	// New tip after reorg
	NewTip    [32]byte
	NewHeight uint64
	NewWork   uint64
}

// CommitReorg atomically performs a chain reorganization
func (s *Storage) CommitReorg(commit *ReorgCommit) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		heights := tx.Bucket(bucketHeights)
		outputs := tx.Bucket(bucketOutputs)
		keyImages := tx.Bucket(bucketKeyImages)
		meta := tx.Bucket(bucketMeta)

		// Disconnect blocks (reverse order, unmark key images)
		for i := len(commit.Disconnect) - 1; i >= 0; i-- {
			block := commit.Disconnect[i]

			// Remove from height index
			heightKey := make([]byte, 8)
			binary.BigEndian.PutUint64(heightKey, block.Header.Height)
			heights.Delete(heightKey)

			// Unmark key images from this block's transactions
			for _, txn := range block.Transactions {
				if !txn.IsCoinbase() {
					for _, input := range txn.Inputs {
						keyImages.Delete(input.KeyImage[:])
					}
				}
			}

			// Note: Outputs are NOT deleted - they're still needed for ring selection
			// A reorged block's outputs may still be referenced by other blocks
		}

		// Connect new blocks (forward order)
		blocks := tx.Bucket(bucketBlocks)
		for _, block := range commit.Connect {
			heightKey := make([]byte, 8)
			binary.BigEndian.PutUint64(heightKey, block.Header.Height)
			hash := block.Hash()

			// Save block data
			blockData, err := json.Marshal(block)
			if err != nil {
				return fmt.Errorf("failed to marshal block: %w", err)
			}
			if err := blocks.Put(hash[:], blockData); err != nil {
				return fmt.Errorf("failed to save block: %w", err)
			}

			// Add to height index
			heights.Put(heightKey, hash[:])

			// Add outputs
			for _, txn := range block.Transactions {
				txid, _ := txn.TxID()
				for idx, out := range txn.Outputs {
					newOutput := &UTXO{
						TxID:        txid,
						OutputIndex: uint32(idx),
						Output:      out,
						BlockHeight: block.Header.Height,
					}
					data, _ := json.Marshal(newOutput)
					key := outpointKey(txid, uint32(idx))
					outputs.Put(key, data)
				}
			}

			// Mark key images as spent
			for _, txn := range block.Transactions {
				if !txn.IsCoinbase() {
					for _, input := range txn.Inputs {
						keyImages.Put(input.KeyImage[:], heightKey)
					}
				}
			}
		}

		// Update tip
		heightBytes := make([]byte, 8)
		workBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(heightBytes, commit.NewHeight)
		binary.BigEndian.PutUint64(workBytes, commit.NewWork)

		meta.Put(metaKeyTip, commit.NewTip[:])
		meta.Put(metaKeyHeight, heightBytes)
		meta.Put(metaKeyWork, workBytes)

		return nil
	})
}
