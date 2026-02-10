package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestProcessBlockData_ReorgRemovesTxsFromAllConnectedBlocks(t *testing.T) {
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

	// Shared block at height 1.
	commonTs := genesis.Header.Timestamp + BlockIntervalSec
	common1 := syntheticBlock(1, genesis.Hash(), commonTs, MinDifficulty)
	if err := local.AddBlock(cloneBlock(common1)); err != nil {
		t.Fatalf("failed to add local shared block: %v", err)
	}
	if err := remote.AddBlock(cloneBlock(common1)); err != nil {
		t.Fatalf("failed to add remote shared block: %v", err)
	}

	// Local chain extends to height 4 at low work.
	localTipHash := common1.Hash()
	localTs := commonTs
	for h := uint64(2); h <= 4; h++ {
		localTs += BlockIntervalSec
		block := syntheticBlock(h, localTipHash, localTs, MinDifficulty)
		if err := local.AddBlock(block); err != nil {
			t.Fatalf("failed to add local block %d: %v", h, err)
		}
		localTipHash = block.Hash()
	}

	// Remote fork has higher work and includes trackedTx at height 2.
	trackedTx := &Transaction{
		Version: 1,
		Outputs: []TxOutput{{}},
		Fee:     10_000,
	}
	trackedID, err := trackedTx.TxID()
	if err != nil {
		t.Fatalf("failed to compute tx id: %v", err)
	}

	remoteTipHash := common1.Hash()
	remoteTs := commonTs + BlockIntervalSec
	r2 := syntheticBlock(2, remoteTipHash, remoteTs, MinDifficulty*3)
	r2.Transactions = []*Transaction{trackedTx}
	if err := remote.AddBlock(r2); err != nil {
		t.Fatalf("failed to add remote block 2: %v", err)
	}
	remoteTipHash = r2.Hash()

	remoteTs += BlockIntervalSec
	r3 := syntheticBlock(3, remoteTipHash, remoteTs, MinDifficulty*3)
	if err := remote.AddBlock(r3); err != nil {
		t.Fatalf("failed to add remote block 3: %v", err)
	}

	d := &Daemon{
		chain:   local,
		mempool: NewMempool(DefaultMempoolConfig(), local.IsKeyImageSpent),
	}
	if err := d.mempool.AddTransaction(trackedTx, trackedTx.Serialize()); err != nil {
		t.Fatalf("failed to seed mempool: %v", err)
	}

	// Height 2 fork block is accepted off-main-chain; tx should remain in mempool.
	r2Data, err := json.Marshal(r2)
	if err != nil {
		t.Fatalf("failed to marshal r2: %v", err)
	}
	if err := d.processBlockData(r2Data); err != nil {
		t.Fatalf("process r2 failed: %v", err)
	}
	if !d.mempool.HasTransaction(trackedID) {
		t.Fatalf("tracked tx removed before reorg connected its block")
	}

	// Height 3 makes remote fork heavier, connecting both r2 and r3 to main chain.
	r3Data, err := json.Marshal(r3)
	if err != nil {
		t.Fatalf("failed to marshal r3: %v", err)
	}
	if err := d.processBlockData(r3Data); err != nil {
		t.Fatalf("process r3 failed: %v", err)
	}

	if d.mempool.HasTransaction(trackedID) {
		t.Fatalf("tracked tx should be removed after reorg connects its containing block")
	}
}

func TestProcessBlockData_ReorgRequeuesTxsFromDisconnectedBlocks(t *testing.T) {
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

	commonTs := genesis.Header.Timestamp + BlockIntervalSec
	common1 := syntheticBlock(1, genesis.Hash(), commonTs, MinDifficulty)
	if err := local.AddBlock(cloneBlock(common1)); err != nil {
		t.Fatalf("failed to add local shared block: %v", err)
	}
	if err := remote.AddBlock(cloneBlock(common1)); err != nil {
		t.Fatalf("failed to add remote shared block: %v", err)
	}

	requeuedTx := &Transaction{
		Version: 1,
		Inputs: []TxInput{
			{KeyImage: [32]byte{42}},
		},
		Outputs: []TxOutput{{}},
		Fee:     10_000,
	}
	requeuedID, err := requeuedTx.TxID()
	if err != nil {
		t.Fatalf("failed to compute tx id: %v", err)
	}
	expectedPID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Local chain includes requeuedTx on the soon-to-be-disconnected branch.
	localTs := commonTs + BlockIntervalSec
	l2 := syntheticBlock(2, common1.Hash(), localTs, MinDifficulty)
	l2.Transactions = []*Transaction{requeuedTx}
	l2.AuxData = &BlockAuxData{
		PaymentIDs: map[string][8]byte{
			"0:0": expectedPID,
		},
	}
	if err := local.AddBlock(l2); err != nil {
		t.Fatalf("failed to add local block 2: %v", err)
	}

	localTs += BlockIntervalSec
	l3 := syntheticBlock(3, l2.Hash(), localTs, MinDifficulty)
	if err := local.AddBlock(l3); err != nil {
		t.Fatalf("failed to add local block 3: %v", err)
	}

	// Remote fork only becomes heavier at height 3 (not yet at height 2).
	remoteTs := commonTs + BlockIntervalSec
	r2 := syntheticBlock(2, common1.Hash(), remoteTs, MinDifficulty*2)
	if err := remote.AddBlock(r2); err != nil {
		t.Fatalf("failed to add remote block 2: %v", err)
	}

	remoteTs += BlockIntervalSec
	r3 := syntheticBlock(3, r2.Hash(), remoteTs, MinDifficulty*2)
	if err := remote.AddBlock(r3); err != nil {
		t.Fatalf("failed to add remote block 3: %v", err)
	}

	d := &Daemon{
		chain:   local,
		mempool: NewMempool(DefaultMempoolConfig(), local.IsKeyImageSpent),
	}

	// Accept fork block at height 2 off-main-chain; no reorg yet.
	r2Data, err := json.Marshal(r2)
	if err != nil {
		t.Fatalf("failed to marshal r2: %v", err)
	}
	if err := d.processBlockData(r2Data); err != nil {
		t.Fatalf("process r2 failed: %v", err)
	}
	if d.mempool.HasTransaction(requeuedID) {
		t.Fatalf("tx should not be requeued before reorg")
	}

	// Height 3 triggers reorg; local l2/l3 disconnect and requeuedTx should return.
	r3Data, err := json.Marshal(r3)
	if err != nil {
		t.Fatalf("failed to marshal r3: %v", err)
	}
	if err := d.processBlockData(r3Data); err != nil {
		t.Fatalf("process r3 failed: %v", err)
	}
	if !d.mempool.HasTransaction(requeuedID) {
		t.Fatalf("tx from disconnected block should be requeued in mempool after reorg")
	}

	_, aux, found := d.mempool.GetTransactionWithAux(requeuedID)
	if !found {
		t.Fatalf("requeued tx not found in mempool")
	}
	if aux == nil {
		t.Fatalf("requeued tx aux data should be preserved")
	}
	gotPID, ok := aux.PaymentIDs[0]
	if !ok {
		t.Fatalf("missing output 0 payment ID in requeued tx aux")
	}
	if gotPID != expectedPID {
		t.Fatalf("unexpected requeued tx payment ID: got=%x want=%x", gotPID, expectedPID)
	}

	serializedWithAux := d.mempool.GetAllTransactionDataWithAux()
	if len(serializedWithAux) != 1 {
		t.Fatalf("expected exactly one mempool tx, got %d", len(serializedWithAux))
	}
	raw, parsedAux := DecodeTxWithAux(serializedWithAux[0])
	if parsedAux == nil {
		t.Fatalf("serialized requeued tx missing aux trailer")
	}
	parsedPID, ok := parsedAux.PaymentIDs[0]
	if !ok || parsedPID != expectedPID {
		t.Fatalf("serialized requeued tx missing expected payment ID")
	}
	if !bytes.Equal(raw, requeuedTx.Serialize()) {
		t.Fatalf("serialized requeued tx payload mismatch")
	}
}
