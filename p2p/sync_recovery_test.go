package p2p

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

var errTestOrphan = errors.New("orphan block")
var errTestInvalid = errors.New("invalid block body")

type testBlock struct {
	Header struct {
		Height   uint64   `json:"Height"`
		PrevHash [32]byte `json:"PrevHash"`
	} `json:"header"`
}

func makeTestBlock(height uint64, prev [32]byte) ([]byte, [32]byte, error) {
	var block testBlock
	block.Header.Height = height
	block.Header.PrevHash = prev

	data, err := json.Marshal(block)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return data, sha256.Sum256(data), nil
}

func testGetBlockMeta(data []byte) (uint64, [32]byte, error) {
	var block testBlock
	if err := json.Unmarshal(data, &block); err != nil {
		return 0, [32]byte{}, err
	}
	return block.Header.Height, block.Header.PrevHash, nil
}

func testGetBlockHash(data []byte) ([32]byte, error) {
	return sha256.Sum256(data), nil
}

func TestProcessBlockWithRecovery_ResolvesMissingParentChain(t *testing.T) {
	genesisData, genesisHash, err := makeTestBlock(0, [32]byte{})
	if err != nil {
		t.Fatalf("genesis encode failed: %v", err)
	}
	_ = genesisData

	// Local chain: genesis + local1.
	local1Data, local1Hash, err := makeTestBlock(1, genesisHash)
	if err != nil {
		t.Fatalf("local1 encode failed: %v", err)
	}
	_ = local1Data
	_ = local1Hash

	// Remote fork chain: genesis + r1 + r2 + r3.
	r1Data, r1Hash, err := makeTestBlock(1, genesisHash)
	if err != nil {
		t.Fatalf("r1 encode failed: %v", err)
	}
	r2Data, r2Hash, err := makeTestBlock(2, r1Hash)
	if err != nil {
		t.Fatalf("r2 encode failed: %v", err)
	}
	r3Data, r3Hash, err := makeTestBlock(3, r2Hash)
	if err != nil {
		t.Fatalf("r3 encode failed: %v", err)
	}

	known := map[[32]byte]struct{}{
		genesisHash: {},
		local1Hash:  {},
	}

	remoteBlocks := map[[32]byte][]byte{
		r1Hash: r1Data,
		r2Hash: r2Data,
		r3Hash: r3Data,
	}

	processBlock := func(data []byte) error {
		height, prevHash, err := testGetBlockMeta(data)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(data)
		if _, exists := known[hash]; exists {
			return nil // duplicate
		}
		if height > 0 {
			if _, hasParent := known[prevHash]; !hasParent {
				return errTestOrphan
			}
		}
		known[hash] = struct{}{}
		return nil
	}

	fetchByHash := func(_ context.Context, _ peer.ID, hashes [][32]byte) ([][]byte, error) {
		if len(hashes) == 0 {
			return nil, nil
		}
		if data, ok := remoteBlocks[hashes[0]]; ok {
			return [][]byte{data}, nil
		}
		return nil, nil
	}

	sm := NewSyncManager(nil, SyncConfig{
		ProcessBlock:      processBlock,
		IsOrphanError:     func(err error) bool { return errors.Is(err, errTestOrphan) },
		GetBlockMeta:      testGetBlockMeta,
		GetBlockHash:      testGetBlockHash,
		FetchBlocksByHash: fetchByHash,
	})

	peers := []PeerStatus{{Peer: peer.ID("peer-1")}}
	if err := sm.ProcessBlockWithRecovery(r3Data, peers); err != nil {
		t.Fatalf("recovery failed: %v", err)
	}

	if _, ok := known[r1Hash]; !ok {
		t.Fatalf("missing recovered block r1")
	}
	if _, ok := known[r2Hash]; !ok {
		t.Fatalf("missing recovered block r2")
	}
	if _, ok := known[r3Hash]; !ok {
		t.Fatalf("missing recovered block r3")
	}
}

func TestProcessBlockWithRecovery_FailsWhenParentUnavailable(t *testing.T) {
	genesisData, genesisHash, err := makeTestBlock(0, [32]byte{})
	if err != nil {
		t.Fatalf("genesis encode failed: %v", err)
	}
	_ = genesisData

	// Child references unknown parent.
	var missingParent [32]byte
	missingParent[0] = 99
	orphanData, _, err := makeTestBlock(2, missingParent)
	if err != nil {
		t.Fatalf("orphan encode failed: %v", err)
	}

	known := map[[32]byte]struct{}{
		genesisHash: {},
	}

	processBlock := func(data []byte) error {
		height, prevHash, err := testGetBlockMeta(data)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(data)
		if _, exists := known[hash]; exists {
			return nil
		}
		if height > 0 {
			if _, hasParent := known[prevHash]; !hasParent {
				return errTestOrphan
			}
		}
		known[hash] = struct{}{}
		return nil
	}

	sm := NewSyncManager(nil, SyncConfig{
		ProcessBlock:      processBlock,
		IsOrphanError:     func(err error) bool { return errors.Is(err, errTestOrphan) },
		GetBlockMeta:      testGetBlockMeta,
		GetBlockHash:      testGetBlockHash,
		FetchBlocksByHash: func(context.Context, peer.ID, [][32]byte) ([][]byte, error) { return nil, nil },
	})

	err = sm.ProcessBlockWithRecovery(orphanData, []PeerStatus{{Peer: peer.ID("peer-1")}})
	if err == nil {
		t.Fatalf("expected recovery failure for missing parent")
	}
	if !strings.Contains(err.Error(), "failed to fetch parent") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProcessBlockWithRecovery_UsesDeadlineBoundFetchContext(t *testing.T) {
	orphanData, _, err := makeTestBlock(2, [32]byte{1})
	if err != nil {
		t.Fatalf("orphan encode failed: %v", err)
	}

	deadlineSeen := make(chan bool, 1)

	sm := NewSyncManager(nil, SyncConfig{
		ProcessBlock:  func([]byte) error { return errTestOrphan },
		IsOrphanError: func(err error) bool { return errors.Is(err, errTestOrphan) },
		GetBlockMeta:  testGetBlockMeta,
		GetBlockHash:  testGetBlockHash,
		FetchBlocksByHash: func(ctx context.Context, _ peer.ID, _ [][32]byte) ([][]byte, error) {
			_, ok := ctx.Deadline()
			deadlineSeen <- ok
			return nil, nil
		},
	})

	err = sm.ProcessBlockWithRecovery(orphanData, []PeerStatus{{Peer: peer.ID("peer-1")}})
	if err == nil {
		t.Fatalf("expected recovery to fail when parent cannot be fetched")
	}

	select {
	case ok := <-deadlineSeen:
		if !ok {
			t.Fatalf("expected fetch callback context to have a deadline")
		}
	default:
		t.Fatalf("fetch callback was not invoked")
	}
}

func TestProcessBlockWithRecoveryCtx_UsesCallerCancellation(t *testing.T) {
	orphanData, _, err := makeTestBlock(2, [32]byte{9})
	if err != nil {
		t.Fatalf("orphan encode failed: %v", err)
	}

	sm := NewSyncManager(nil, SyncConfig{
		ProcessBlock:  func([]byte) error { return errTestOrphan },
		IsOrphanError: func(err error) bool { return errors.Is(err, errTestOrphan) },
		GetBlockMeta:  testGetBlockMeta,
		GetBlockHash:  testGetBlockHash,
		FetchBlocksByHash: func(ctx context.Context, _ peer.ID, _ [][32]byte) ([][]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = sm.ProcessBlockWithRecoveryCtx(ctx, orphanData, []PeerStatus{{Peer: peer.ID("peer-1")}})
	if err == nil {
		t.Fatalf("expected cancellation error")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected caller context cancellation, got: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("recovery did not stop promptly on caller cancellation")
	}
}

func TestProcessBlockWithRecovery_RetriesOtherPeersOnInvalidParentData(t *testing.T) {
	type wireBlock struct {
		Header struct {
			Height   uint64   `json:"Height"`
			PrevHash [32]byte `json:"PrevHash"`
		} `json:"header"`
		Hash  [32]byte `json:"hash"`
		Valid bool     `json:"valid"`
	}

	encode := func(height uint64, prev, hash [32]byte, valid bool) []byte {
		var b wireBlock
		b.Header.Height = height
		b.Header.PrevHash = prev
		b.Hash = hash
		b.Valid = valid
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}
		return data
	}
	getMeta := func(data []byte) (uint64, [32]byte, error) {
		var b wireBlock
		if err := json.Unmarshal(data, &b); err != nil {
			return 0, [32]byte{}, err
		}
		return b.Header.Height, b.Header.PrevHash, nil
	}
	getHash := func(data []byte) ([32]byte, error) {
		var b wireBlock
		if err := json.Unmarshal(data, &b); err != nil {
			return [32]byte{}, err
		}
		return b.Hash, nil
	}

	var genesisHash [32]byte
	genesisHash[0] = 1
	var parentHash [32]byte
	parentHash[0] = 2
	var childHash [32]byte
	childHash[0] = 3

	parentBad := encode(1, genesisHash, parentHash, false)
	parentGood := encode(1, genesisHash, parentHash, true)
	child := encode(2, parentHash, childHash, true)

	known := map[[32]byte]struct{}{
		genesisHash: {},
	}

	processBlock := func(data []byte) error {
		var b wireBlock
		if err := json.Unmarshal(data, &b); err != nil {
			return err
		}
		if _, exists := known[b.Hash]; exists {
			return nil
		}
		if !b.Valid {
			return errTestInvalid
		}
		if b.Header.Height > 0 {
			if _, hasParent := known[b.Header.PrevHash]; !hasParent {
				return errTestOrphan
			}
		}
		known[b.Hash] = struct{}{}
		return nil
	}

	sm := NewSyncManager(nil, SyncConfig{
		ProcessBlock:  processBlock,
		IsOrphanError: func(err error) bool { return errors.Is(err, errTestOrphan) },
		GetBlockMeta:  getMeta,
		GetBlockHash:  getHash,
		FetchBlocksByHash: func(_ context.Context, p peer.ID, _ [][32]byte) ([][]byte, error) {
			if p == peer.ID("bad-peer") {
				return [][]byte{parentBad}, nil
			}
			time.Sleep(25 * time.Millisecond)
			return [][]byte{parentGood}, nil
		},
	})

	err := sm.ProcessBlockWithRecovery(child, []PeerStatus{
		{Peer: peer.ID("bad-peer")},
		{Peer: peer.ID("good-peer")},
	})
	if err != nil {
		t.Fatalf("expected recovery to retry another peer after invalid parent, got: %v", err)
	}

	if _, ok := known[parentHash]; !ok {
		t.Fatalf("missing recovered parent block")
	}
	if _, ok := known[childHash]; !ok {
		t.Fatalf("missing recovered child block")
	}
}

func TestFetchBlockByHashFromAnyPeer_VerifiesReturnedHash(t *testing.T) {
	correctData, correctHash, err := makeTestBlock(7, [32]byte{3})
	if err != nil {
		t.Fatalf("correct block encode failed: %v", err)
	}
	wrongData, _, err := makeTestBlock(7, [32]byte{4})
	if err != nil {
		t.Fatalf("wrong block encode failed: %v", err)
	}

	sm := NewSyncManager(nil, SyncConfig{
		GetBlockHash: testGetBlockHash,
		FetchBlocksByHash: func(_ context.Context, p peer.ID, _ [][32]byte) ([][]byte, error) {
			if p == peer.ID("bad-peer") {
				return [][]byte{wrongData}, nil
			}
			time.Sleep(25 * time.Millisecond)
			return [][]byte{correctData}, nil
		},
	})

	block, _, err := sm.fetchBlockByHashFromAnyPeer(context.Background(), []PeerStatus{
		{Peer: peer.ID("bad-peer")},
		{Peer: peer.ID("good-peer")},
	}, correctHash, nil)
	if err != nil {
		t.Fatalf("expected successful fetch from good peer after rejecting bad peer data: %v", err)
	}
	if !bytes.Equal(block, correctData) {
		t.Fatalf("returned block did not match expected block")
	}
}
