package main

import "testing"

func testReorgTx(keyImageByte byte, fee uint64) *Transaction {
	return &Transaction{
		Version: 1,
		Inputs: []TxInput{
			{KeyImage: [32]byte{keyImageByte}},
		},
		Outputs: []TxOutput{{}},
		Fee:     fee,
	}
}

func TestOnBlockDisconnected_RequeuedTxMaintainsHeapInvariants(t *testing.T) {
	m := NewMempool(DefaultMempoolConfig(), func([32]byte) bool { return false })

	baseTx := &Transaction{
		Version: 1,
		Outputs: []TxOutput{{}},
		Fee:     5_000,
	}
	baseData := baseTx.Serialize()
	if err := m.AddTransaction(baseTx, baseData); err != nil {
		t.Fatalf("failed to seed mempool: %v", err)
	}
	baseID, err := baseTx.TxID()
	if err != nil {
		t.Fatalf("failed to compute base tx id: %v", err)
	}

	reorgTx := testReorgTx(9, 8_000)
	reorgID, err := reorgTx.TxID()
	if err != nil {
		t.Fatalf("failed to compute reorg tx id: %v", err)
	}

	m.OnBlockDisconnected(&Block{
		Transactions: []*Transaction{reorgTx},
	}, map[[32]byte][]byte{
		reorgID: reorgTx.Serialize(),
	})

	if !m.HasTransaction(reorgID) {
		t.Fatalf("requeued tx missing from mempool")
	}
	if len(m.priorityQueue) != 2 {
		t.Fatalf("priority queue size mismatch after requeue: got=%d want=2", len(m.priorityQueue))
	}

	requeuedEntry := m.txByID[reorgID]
	if requeuedEntry == nil {
		t.Fatalf("missing mempool entry for requeued tx")
	}
	if requeuedEntry.index < 0 || requeuedEntry.index >= len(m.priorityQueue) {
		t.Fatalf("requeued entry index out of bounds: %d", requeuedEntry.index)
	}
	if m.priorityQueue[requeuedEntry.index] != requeuedEntry {
		t.Fatalf("priority queue index does not reference requeued entry")
	}

	m.RemoveTransaction(reorgID)

	if !m.HasTransaction(baseID) {
		t.Fatalf("removing requeued tx should not remove existing tx")
	}
	if len(m.priorityQueue) != 1 {
		t.Fatalf("priority queue size mismatch after removal: got=%d want=1", len(m.priorityQueue))
	}
	if m.priorityQueue[0] == nil || m.priorityQueue[0].TxID != baseID {
		t.Fatalf("unexpected tx remained in priority queue after removal")
	}
}

func TestOnBlockDisconnected_DuplicateTxDoesNotCorruptBookkeeping(t *testing.T) {
	m := NewMempool(DefaultMempoolConfig(), func([32]byte) bool { return false })

	reorgTx := testReorgTx(7, 10_000)
	reorgID, err := reorgTx.TxID()
	if err != nil {
		t.Fatalf("failed to compute reorg tx id: %v", err)
	}

	block := &Block{Transactions: []*Transaction{reorgTx}}
	txDataMap := map[[32]byte][]byte{reorgID: reorgTx.Serialize()}

	m.OnBlockDisconnected(block, txDataMap)

	initialTotalSize := m.totalSize
	initialQueueLen := len(m.priorityQueue)
	if initialQueueLen != 1 {
		t.Fatalf("expected one queued entry after first requeue, got %d", initialQueueLen)
	}

	m.OnBlockDisconnected(block, txDataMap)

	if m.totalSize != initialTotalSize {
		t.Fatalf("duplicate requeue changed totalSize: got=%d want=%d", m.totalSize, initialTotalSize)
	}
	if len(m.txByID) != 1 {
		t.Fatalf("duplicate requeue changed tx count: got=%d want=1", len(m.txByID))
	}
	if len(m.priorityQueue) != initialQueueLen {
		t.Fatalf("duplicate requeue changed priority queue size: got=%d want=%d", len(m.priorityQueue), initialQueueLen)
	}
}
