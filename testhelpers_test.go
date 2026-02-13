package main

import (
	"blocknet/p2p"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func mustCreateTestChain(t *testing.T) (*Chain, *Storage, func()) {
	t.Helper()

	dataDir := t.TempDir()
	chain, err := NewChain(dataDir)
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}

	cleanup := func() {
		if err := chain.Close(); err != nil {
			t.Fatalf("failed to close chain: %v", err)
		}
	}

	return chain, chain.Storage(), cleanup
}

func mustAddGenesisBlock(t *testing.T, chain *Chain) {
	t.Helper()

	genesis, err := GetGenesisBlock()
	if err != nil {
		t.Fatalf("failed to load canonical genesis block: %v", err)
	}

	if err := chain.addGenesisBlock(genesis); err != nil {
		t.Fatalf("failed to add genesis block: %v", err)
	}
}

func assertTipUnchanged(t *testing.T, chain *Chain, wantHash [32]byte, wantHeight uint64) {
	t.Helper()

	if gotHeight := chain.Height(); gotHeight != wantHeight {
		t.Fatalf("tip height changed: got %d, want %d", gotHeight, wantHeight)
	}
	if gotHash := chain.BestHash(); gotHash != wantHash {
		t.Fatalf("tip hash changed: got %x, want %x", gotHash[:8], wantHash[:8])
	}

	tipHash, tipHeight, _, found := chain.Storage().GetTip()
	if !found {
		t.Fatalf("expected storage tip to exist")
	}
	if tipHeight != wantHeight {
		t.Fatalf("storage tip height changed: got %d, want %d", tipHeight, wantHeight)
	}
	if tipHash != wantHash {
		t.Fatalf("storage tip hash changed: got %x, want %x", tipHash[:8], wantHash[:8])
	}
}

func mustStartTestDaemon(t *testing.T, chain *Chain) (*Daemon, func()) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	mempool := NewMempool(DefaultMempoolConfig(), chain.IsKeyImageSpent, chain.IsCanonicalRingMember)
	miner := NewMiner(chain, mempool, MinerConfig{})

	d := &Daemon{
		chain:   chain,
		mempool: mempool,
		miner:   miner,
		ctx:     ctx,
		cancel:  cancel,
	}

	cleanup := func() {
		cancel()
	}

	return d, cleanup
}

func mustMakeHTTPJSONRequest(
	t *testing.T,
	handler http.Handler,
	method, path string,
	body []byte,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func mustCraftMalformedTxVariant(t *testing.T, kind string) []byte {
	t.Helper()

	switch kind {
	case "empty-ringct-signature":
		ringMembers := make([][32]byte, RingSize)
		ringCommitments := make([][32]byte, RingSize)
		tx := &Transaction{
			Version: 1,
			Fee:     1,
			Inputs: []TxInput{
				{
					RingMembers:     ringMembers,
					RingCommitments: ringCommitments,
					RingSignature:   nil,
				},
			},
			Outputs: []TxOutput{
				{
					Commitment: [32]byte{},
					PublicKey:  [32]byte{},
				},
			},
		}
		return tx.Serialize()
	default:
		t.Fatalf("unknown malformed tx variant: %s", kind)
		return nil
	}
}

func mustStartLinkedTestNodes(t *testing.T) (*p2p.Node, *p2p.Node, func()) {
	t.Helper()

	cfg := p2p.DefaultNodeConfig()
	cfg.ListenAddrs = []string{"/ip4/127.0.0.1/tcp/0"}
	cfg.SeedNodes = nil

	a, err := p2p.NewNode(cfg)
	if err != nil {
		t.Fatalf("failed to create node A: %v", err)
	}
	b, err := p2p.NewNode(cfg)
	if err != nil {
		_ = a.Stop()
		t.Fatalf("failed to create node B: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Connect(ctx, peer.AddrInfo{ID: b.PeerID(), Addrs: b.Addrs()}); err != nil {
		_ = a.Stop()
		_ = b.Stop()
		t.Fatalf("failed to connect A->B: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.Host().Network().Connectedness(b.PeerID()) == network.Connected {
			cleanup := func() {
				_ = a.Stop()
				_ = b.Stop()
			}
			return a, b, cleanup
		}
		time.Sleep(20 * time.Millisecond)
	}

	_ = a.Stop()
	_ = b.Stop()
	t.Fatal("nodes failed to connect in time")
	return nil, nil, func() {}
}

func assertPeerPenalized(t *testing.T, n *p2p.Node, pid peer.ID, minPenalty int) {
	t.Helper()
	if n == nil {
		t.Fatal("node is nil")
	}
	// Severe penalties in this codebase are expected to ban.
	if !n.IsBanned(pid) {
		t.Fatalf("expected peer %s to be penalized/banned (minPenalty=%d)", pid, minPenalty)
	}
}
