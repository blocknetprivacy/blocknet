package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"blocknet/p2p"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestReproSync_NearTipOverlap_DeepReorgStalls(t *testing.T) {
	baseDir := t.TempDir()
	local := mustNewChain(t, filepath.Join(baseDir, "local"))
	remote := mustNewChain(t, filepath.Join(baseDir, "remote"))

	genesis, err := GetGenesisBlock()
	if err != nil {
		t.Fatalf("failed to create genesis: %v", err)
	}
	if err := local.AddBlock(cloneBlock(genesis)); err != nil {
		t.Fatalf("failed to add local genesis: %v", err)
	}
	if err := remote.AddBlock(cloneBlock(genesis)); err != nil {
		t.Fatalf("failed to add remote genesis: %v", err)
	}

	// Build a common prefix, then diverge deeper than the 10-block near-tip overlap.
	const sharedDepth uint64 = 5
	const targetHeight uint64 = 25
	const localDiff = MinDifficulty
	const remoteDiff = MinDifficulty * 3

	commonTipHash := genesis.Hash()
	commonTs := genesis.Header.Timestamp

	for h := uint64(1); h <= sharedDepth; h++ {
		commonTs += BlockIntervalSec
		block := syntheticBlock(h, commonTipHash, commonTs, MinDifficulty)
		if err := local.AddBlock(cloneBlock(block)); err != nil {
			t.Fatalf("failed to add local shared block %d: %v", h, err)
		}
		if err := remote.AddBlock(cloneBlock(block)); err != nil {
			t.Fatalf("failed to add remote shared block %d: %v", h, err)
		}
		commonTipHash = block.Hash()
	}

	localTipHash := commonTipHash
	remoteTipHash := commonTipHash
	localTs := commonTs
	remoteTs := commonTs

	for h := sharedDepth + 1; h <= targetHeight; h++ {
		localTs += BlockIntervalSec
		localBlock := syntheticBlock(h, localTipHash, localTs, localDiff)
		if err := local.AddBlock(localBlock); err != nil {
			t.Fatalf("failed to add local fork block %d: %v", h, err)
		}
		localTipHash = localBlock.Hash()

		remoteTs += BlockIntervalSec
		remoteBlock := syntheticBlock(h, remoteTipHash, remoteTs, remoteDiff)
		if err := remote.AddBlock(remoteBlock); err != nil {
			t.Fatalf("failed to add remote fork block %d: %v", h, err)
		}
		remoteTipHash = remoteBlock.Hash()
	}

	if local.Height() != remote.Height() {
		t.Fatalf("expected equal heights for reorg sync case: local=%d remote=%d", local.Height(), remote.Height())
	}
	if remote.TotalWork() <= local.TotalWork() {
		t.Fatalf("test setup invalid: remote work must exceed local work")
	}

	// Simulate legacy sync attempts using the near-tip window logic, without
	// orphan backfill recovery.
	for attempt := 1; attempt <= 2; attempt++ {
		err := syncAttemptLikeNearTip(local, remote)
		if err == nil {
			t.Fatalf("expected legacy sync attempt %d to fail with orphan", attempt)
		}
		if err.Error() != "process block 15: orphan block" {
			t.Fatalf("unexpected legacy sync error (attempt %d): %v", attempt, err)
		}
	}
}

func TestReproSync_BehindByMoreThanOverlap_OneBlockTipForkStalls(t *testing.T) {
	baseDir := t.TempDir()
	local := mustNewChain(t, filepath.Join(baseDir, "local"))
	remote := mustNewChain(t, filepath.Join(baseDir, "remote"))

	genesis, err := GetGenesisBlock()
	if err != nil {
		t.Fatalf("failed to create genesis: %v", err)
	}
	if err := local.AddBlock(cloneBlock(genesis)); err != nil {
		t.Fatalf("failed to add local genesis: %v", err)
	}
	if err := remote.AddBlock(cloneBlock(genesis)); err != nil {
		t.Fatalf("failed to add remote genesis: %v", err)
	}

	// Build common chain to 59, then fork at height 60.
	// Local stays on stale tip 60; remote extends far ahead (>50 block gap).
	const commonTip uint64 = 59
	const localTip uint64 = 60
	const remoteTip uint64 = 120

	commonTipHash := genesis.Hash()
	ts := genesis.Header.Timestamp

	for h := uint64(1); h <= commonTip; h++ {
		ts += BlockIntervalSec
		block := syntheticBlock(h, commonTipHash, ts, MinDifficulty)
		if err := local.AddBlock(cloneBlock(block)); err != nil {
			t.Fatalf("failed to add local shared block %d: %v", h, err)
		}
		if err := remote.AddBlock(cloneBlock(block)); err != nil {
			t.Fatalf("failed to add remote shared block %d: %v", h, err)
		}
		commonTipHash = block.Hash()
	}

	ts += BlockIntervalSec
	local60 := syntheticBlock(localTip, commonTipHash, ts, MinDifficulty)
	if err := local.AddBlock(local60); err != nil {
		t.Fatalf("failed to add local tip block: %v", err)
	}

	remoteTs := ts
	remote60 := syntheticBlock(localTip, commonTipHash, remoteTs, MinDifficulty*2)
	if err := remote.AddBlock(remote60); err != nil {
		t.Fatalf("failed to add remote fork block 60: %v", err)
	}
	remoteTipHash := remote60.Hash()

	for h := localTip + 1; h <= remoteTip; h++ {
		remoteTs += BlockIntervalSec
		b := syntheticBlock(h, remoteTipHash, remoteTs, MinDifficulty*2)
		if err := remote.AddBlock(b); err != nil {
			t.Fatalf("failed to add remote fork block %d: %v", h, err)
		}
		remoteTipHash = b.Hash()
	}

	if local.Height() != localTip {
		t.Fatalf("unexpected local height: got=%d want=%d", local.Height(), localTip)
	}
	if remote.Height() != remoteTip {
		t.Fatalf("unexpected remote height: got=%d want=%d", remote.Height(), remoteTip)
	}
	if remote.TotalWork() <= local.TotalWork() {
		t.Fatalf("test setup invalid: remote work must exceed local work")
	}

	err = syncAttemptLikeNearTip(local, remote)
	if err == nil {
		t.Fatalf("expected legacy sync to fail with orphan")
	}
	if err.Error() != "process block 61: orphan block" {
		t.Fatalf("unexpected legacy sync error: %v", err)
	}
}

func mustNewChain(t *testing.T, dataDir string) *Chain {
	t.Helper()

	chain, err := NewChain(dataDir)
	if err != nil {
		t.Fatalf("failed to create chain at %s: %v", dataDir, err)
	}
	t.Cleanup(func() {
		if err := chain.Close(); err != nil {
			t.Errorf("failed to close chain at %s: %v", dataDir, err)
		}
	})
	return chain
}

func syntheticBlock(height uint64, prevHash [32]byte, timestamp int64, difficulty uint64) *Block {
	return &Block{
		Header: BlockHeader{
			Version:    1,
			Height:     height,
			PrevHash:   prevHash,
			MerkleRoot: [32]byte{},
			Timestamp:  timestamp,
			Difficulty: difficulty,
			Nonce:      0,
		},
		Transactions: []*Transaction{},
	}
}

func cloneBlock(b *Block) *Block {
	copied := *b
	copied.Transactions = append([]*Transaction(nil), b.Transactions...)
	return &copied
}

func syncAttemptLikeNearTip(local, remote *Chain) error {
	ourHeight := local.Height()
	targetHeight := remote.Height()
	if targetHeight < ourHeight {
		return nil
	}

	startHeight := ourHeight + 1
	if gap := targetHeight - ourHeight; gap <= 50 && ourHeight > 10 {
		startHeight = ourHeight - 10
	}

	for h := startHeight; h <= targetHeight; h++ {
		block := remote.GetBlockByHeight(h)
		if block == nil {
			return fmt.Errorf("remote missing block at height %d", h)
		}

		data, err := json.Marshal(block)
		if err != nil {
			return fmt.Errorf("marshal block %d: %w", h, err)
		}

		if err := processBlockDataLikeDaemon(local, data); err != nil {
			return fmt.Errorf("process block %d: %w", h, err)
		}
	}

	return nil
}

func processBlockDataLikeDaemon(chain *Chain, data []byte) error {
	var block Block
	if err := json.Unmarshal(data, &block); err != nil {
		return err
	}

	accepted, _, err := chain.ProcessBlock(&block)
	if err != nil {
		return err
	}
	if !accepted {
		// Duplicate block we already have.
		return nil
	}

	return nil
}

// fetchBlockByHashFromRemote builds a FetchBlocksByHash callback that serves
// blocks from the given remote chain, keyed by hash.
func fetchBlockByHashFromRemote(remote *Chain) func(context.Context, peer.ID, [][32]byte) ([][]byte, error) {
	return func(_ context.Context, _ peer.ID, hashes [][32]byte) ([][]byte, error) {
		var out [][]byte
		for _, h := range hashes {
			block := remote.GetBlock(h)
			if block == nil {
				continue
			}
			data, err := json.Marshal(block)
			if err != nil {
				return nil, err
			}
			out = append(out, data)
		}
		return out, nil
	}
}

func syncWithRecovery(local, remote *Chain) error {
	ourHeight := local.Height()
	targetHeight := remote.Height()
	if targetHeight < ourHeight {
		return nil
	}

	startHeight := ourHeight + 1
	if gap := targetHeight - ourHeight; gap <= 50 && ourHeight > 10 {
		startHeight = ourHeight - 10
	}

	sm := p2p.NewSyncManager(nil, p2p.SyncConfig{
		ProcessBlock:  func(data []byte) error { return processBlockDataLikeDaemon(local, data) },
		IsOrphanError: func(err error) bool { return errors.Is(err, ErrOrphanBlock) },
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
		FetchBlocksByHash: fetchBlockByHashFromRemote(remote),
	})

	peers := []p2p.PeerStatus{{Peer: peer.ID("test-remote")}}

	for h := startHeight; h <= targetHeight; h++ {
		block := remote.GetBlockByHeight(h)
		if block == nil {
			return fmt.Errorf("remote missing block at height %d", h)
		}
		data, err := json.Marshal(block)
		if err != nil {
			return fmt.Errorf("marshal block %d: %w", h, err)
		}
		if err := sm.ProcessBlockWithRecovery(data, peers); err != nil {
			return fmt.Errorf("process block %d: %w", h, err)
		}
	}
	return nil
}

func TestSyncWithRecovery_DeepReorg(t *testing.T) {
	baseDir := t.TempDir()
	local := mustNewChain(t, filepath.Join(baseDir, "local"))
	remote := mustNewChain(t, filepath.Join(baseDir, "remote"))

	genesis, err := GetGenesisBlock()
	if err != nil {
		t.Fatalf("failed to create genesis: %v", err)
	}
	if err := local.AddBlock(cloneBlock(genesis)); err != nil {
		t.Fatalf("failed to add local genesis: %v", err)
	}
	if err := remote.AddBlock(cloneBlock(genesis)); err != nil {
		t.Fatalf("failed to add remote genesis: %v", err)
	}

	const sharedDepth uint64 = 5
	const targetHeight uint64 = 25
	const remoteDiff = MinDifficulty * 3

	commonTipHash := genesis.Hash()
	commonTs := genesis.Header.Timestamp

	for h := uint64(1); h <= sharedDepth; h++ {
		commonTs += BlockIntervalSec
		block := syntheticBlock(h, commonTipHash, commonTs, MinDifficulty)
		if err := local.AddBlock(cloneBlock(block)); err != nil {
			t.Fatalf("shared block %d: %v", h, err)
		}
		if err := remote.AddBlock(cloneBlock(block)); err != nil {
			t.Fatalf("shared block %d: %v", h, err)
		}
		commonTipHash = block.Hash()
	}

	localTipHash := commonTipHash
	remoteTipHash := commonTipHash
	localTs := commonTs
	remoteTs := commonTs

	for h := sharedDepth + 1; h <= targetHeight; h++ {
		localTs += BlockIntervalSec
		lb := syntheticBlock(h, localTipHash, localTs, MinDifficulty)
		if err := local.AddBlock(lb); err != nil {
			t.Fatalf("local fork block %d: %v", h, err)
		}
		localTipHash = lb.Hash()

		remoteTs += BlockIntervalSec
		rb := syntheticBlock(h, remoteTipHash, remoteTs, remoteDiff)
		if err := remote.AddBlock(rb); err != nil {
			t.Fatalf("remote fork block %d: %v", h, err)
		}
		remoteTipHash = rb.Hash()
	}

	if err := syncWithRecovery(local, remote); err != nil {
		t.Fatalf("sync with recovery failed: %v", err)
	}

	localBest, remoteBest := local.BestHash(), remote.BestHash()
	if localBest != remoteBest {
		t.Fatalf("chains did not converge: local=%x remote=%x", localBest[:8], remoteBest[:8])
	}
}

func TestSyncWithRecovery_BehindByMoreThanOverlap(t *testing.T) {
	baseDir := t.TempDir()
	local := mustNewChain(t, filepath.Join(baseDir, "local"))
	remote := mustNewChain(t, filepath.Join(baseDir, "remote"))

	genesis, err := GetGenesisBlock()
	if err != nil {
		t.Fatalf("failed to create genesis: %v", err)
	}
	if err := local.AddBlock(cloneBlock(genesis)); err != nil {
		t.Fatalf("local genesis: %v", err)
	}
	if err := remote.AddBlock(cloneBlock(genesis)); err != nil {
		t.Fatalf("remote genesis: %v", err)
	}

	const commonTip uint64 = 59
	const localTip uint64 = 60
	const remoteTip uint64 = 120

	commonTipHash := genesis.Hash()
	ts := genesis.Header.Timestamp

	for h := uint64(1); h <= commonTip; h++ {
		ts += BlockIntervalSec
		block := syntheticBlock(h, commonTipHash, ts, MinDifficulty)
		if err := local.AddBlock(cloneBlock(block)); err != nil {
			t.Fatalf("shared block %d: %v", h, err)
		}
		if err := remote.AddBlock(cloneBlock(block)); err != nil {
			t.Fatalf("shared block %d: %v", h, err)
		}
		commonTipHash = block.Hash()
	}

	ts += BlockIntervalSec
	local60 := syntheticBlock(localTip, commonTipHash, ts, MinDifficulty)
	if err := local.AddBlock(local60); err != nil {
		t.Fatalf("local tip: %v", err)
	}

	remoteTs := ts
	remote60 := syntheticBlock(localTip, commonTipHash, remoteTs, MinDifficulty*2)
	if err := remote.AddBlock(remote60); err != nil {
		t.Fatalf("remote fork 60: %v", err)
	}
	remoteTipHash := remote60.Hash()

	for h := localTip + 1; h <= remoteTip; h++ {
		remoteTs += BlockIntervalSec
		b := syntheticBlock(h, remoteTipHash, remoteTs, MinDifficulty*2)
		if err := remote.AddBlock(b); err != nil {
			t.Fatalf("remote fork block %d: %v", h, err)
		}
		remoteTipHash = b.Hash()
	}

	if err := syncWithRecovery(local, remote); err != nil {
		t.Fatalf("sync with recovery failed: %v", err)
	}

	localBest, remoteBest := local.BestHash(), remote.BestHash()
	if localBest != remoteBest {
		t.Fatalf("chains did not converge: local=%x remote=%x", localBest[:8], remoteBest[:8])
	}
	if local.Height() != remoteTip {
		t.Fatalf("local height mismatch: got=%d want=%d", local.Height(), remoteTip)
	}
}
