package main

import "testing"

func TestDaemonTxIngestRejectsCoinbaseTransaction(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	daemon, stopDaemon := mustStartTestDaemon(t, chain)
	defer stopDaemon()

	keys, err := GenerateStealthKeys()
	if err != nil {
		t.Fatalf("failed to generate stealth keys: %v", err)
	}
	coinbase, err := CreateCoinbase(keys.SpendPubKey, keys.ViewPubKey, GetBlockReward(1), 1)
	if err != nil {
		t.Fatalf("failed to create coinbase tx: %v", err)
	}

	txData := coinbase.Tx.Serialize()
	if err := daemon.processTxData(txData); err != nil {
		t.Fatalf("processTxData returned unexpected error: %v", err)
	}

	txID, err := coinbase.Tx.TxID()
	if err != nil {
		t.Fatalf("failed to compute coinbase txid: %v", err)
	}
	if _, exists := daemon.Mempool().GetTransaction(txID); exists {
		t.Fatalf("coinbase transaction was admitted through daemon ingest: %x", txID[:8])
	}
	if got := daemon.Mempool().Size(); got != 0 {
		t.Fatalf("mempool should remain empty after daemon ingest coinbase attempt, size=%d", got)
	}
}

func TestDaemonTxIngestRejectsTamperedRingCTExternalKeyImage(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	daemon, stopDaemon := mustStartTestDaemon(t, chain)
	defer stopDaemon()

	// Isolate the RingCT binding behavior in daemon ingest without unrelated
	// canonical ring-member/storage coupling.
	daemon.mempool = NewMempool(
		DefaultMempoolConfig(),
		func(_ [32]byte) bool { return false },
		func(_, _ [32]byte) bool { return true },
	)

	tx := mustBuildValidRingCTBindingTestTx(t)
	tx.Inputs[0].KeyImage[0] ^= 0x01

	txData := tx.Serialize()
	if err := daemon.processTxData(txData); err != nil {
		t.Fatalf("processTxData returned unexpected error: %v", err)
	}

	txID, err := tx.TxID()
	if err != nil {
		t.Fatalf("failed to compute tampered txid: %v", err)
	}
	if _, exists := daemon.Mempool().GetTransaction(txID); exists {
		t.Fatalf("tampered RingCT transaction was admitted through daemon ingest: %x", txID[:8])
	}
	if got := daemon.Mempool().Size(); got != 0 {
		t.Fatalf("mempool should remain empty after daemon ingest tampered tx attempt, size=%d", got)
	}
}
