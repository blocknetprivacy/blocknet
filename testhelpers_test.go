package main

import "testing"

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
