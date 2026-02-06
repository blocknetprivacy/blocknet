package p2p

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// Sync message types
const (
	SyncMsgGetHeaders        byte = 0x01 // Request block headers from a height
	SyncMsgHeaders           byte = 0x02 // Response with headers
	SyncMsgGetBlocks         byte = 0x03 // Request full blocks by hash
	SyncMsgBlocks            byte = 0x04 // Response with blocks
	SyncMsgStatus            byte = 0x05 // Exchange chain status
	SyncMsgNewBlock          byte = 0x06 // Announce new block
	SyncMsgGetMempool        byte = 0x07 // Request mempool transactions
	SyncMsgMempool           byte = 0x08 // Response with mempool txs
	SyncMsgGetBlocksByHeight byte = 0x09 // Request blocks by height range
)

// MaxHeadersPerRequest is the maximum headers to request at once
const MaxHeadersPerRequest = 500

// MaxBlocksPerRequest is the maximum blocks to request at once
const MaxBlocksPerRequest = 100

// ChainStatus represents a peer's chain status
type ChainStatus struct {
	BestHash  [32]byte `json:"best_hash"`
	Height    uint64   `json:"height"`
	TotalWork uint64   `json:"total_work"`
	Version   uint32   `json:"version"`
}

// HeadersRequest requests headers starting from a height
type HeadersRequest struct {
	StartHeight uint64 `json:"start_height"`
	MaxHeaders  int    `json:"max_headers"`
}

// BlocksRequest requests specific blocks by hash
type BlocksRequest struct {
	Hashes [][32]byte `json:"hashes"`
}

// BlocksByHeightRequest requests blocks by height range
type BlocksByHeightRequest struct {
	StartHeight uint64 `json:"start_height"`
	MaxBlocks   int    `json:"max_blocks"`
}

// SyncManager handles chain synchronization
type SyncManager struct {
	mu sync.RWMutex

	node *Node

	// Callbacks for chain operations
	getStatus         func() ChainStatus
	getHeaders        func(startHeight uint64, max int) ([][]byte, error)
	getBlocks         func(hashes [][32]byte) ([][]byte, error)
	getBlocksByHeight func(startHeight uint64, max int) ([][]byte, error)
	processBlock      func(data []byte) error
	processHeader     func(data []byte) error

	// Sync state
	syncing       bool
	syncPeer      peer.ID
	syncStartTime time.Time

	ctx    context.Context
	cancel context.CancelFunc
}

// SyncConfig configures the sync manager
type SyncConfig struct {
	GetStatus         func() ChainStatus
	GetHeaders        func(startHeight uint64, max int) ([][]byte, error)
	GetBlocks         func(hashes [][32]byte) ([][]byte, error)
	GetBlocksByHeight func(startHeight uint64, max int) ([][]byte, error)
	ProcessBlock      func(data []byte) error
	ProcessHeader     func(data []byte) error
}

// NewSyncManager creates a new sync manager
func NewSyncManager(node *Node, cfg SyncConfig) *SyncManager {
	return &SyncManager{
		node:              node,
		getStatus:         cfg.GetStatus,
		getHeaders:        cfg.GetHeaders,
		getBlocks:         cfg.GetBlocks,
		getBlocksByHeight: cfg.GetBlocksByHeight,
		processBlock:      cfg.ProcessBlock,
		processHeader:     cfg.ProcessHeader,
	}
}

// Start begins sync operations
func (sm *SyncManager) Start(ctx context.Context) {
	sm.ctx, sm.cancel = context.WithCancel(ctx)

	// Update the node's sync handler
	sm.node.host.SetStreamHandler(ProtocolSync, sm.HandleStream)

	// Start sync loop
	go sm.syncLoop()
}

// Stop halts sync operations
func (sm *SyncManager) Stop() {
	if sm.cancel != nil {
		sm.cancel()
	}
}

// HandleStream handles incoming sync protocol streams
func (sm *SyncManager) HandleStream(s network.Stream) {
	defer s.Close()

	msgType, data, err := readMessage(s)
	if err != nil {
		return
	}

	switch msgType {
	case SyncMsgStatus:
		sm.handleStatus(s, data)
	case SyncMsgGetHeaders:
		sm.handleGetHeaders(s, data)
	case SyncMsgGetBlocks:
		sm.handleGetBlocks(s, data)
	case SyncMsgGetBlocksByHeight:
		sm.handleGetBlocksByHeight(s, data)
	case SyncMsgNewBlock:
		sm.handleNewBlock(s.Conn().RemotePeer(), data)
	case SyncMsgGetMempool:
		sm.handleGetMempool(s)
	}
}

// handleStatus processes a status message
func (sm *SyncManager) handleStatus(s network.Stream, data []byte) {
	var status ChainStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return
	}

	// Send our status back
	ourStatus := sm.getStatus()
	statusData, _ := json.Marshal(ourStatus)
	writeMessage(s, SyncMsgStatus, statusData)

	// Check if we need to sync from this peer
	if status.TotalWork > ourStatus.TotalWork {
		go sm.syncFrom(s.Conn().RemotePeer(), status)
	}
}

// handleGetHeaders responds to a headers request
func (sm *SyncManager) handleGetHeaders(s network.Stream, data []byte) {
	var req HeadersRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return
	}

	if req.MaxHeaders > MaxHeadersPerRequest {
		req.MaxHeaders = MaxHeadersPerRequest
	}

	headers, err := sm.getHeaders(req.StartHeight, req.MaxHeaders)
	if err != nil {
		return
	}

	// Send headers
	headersData, _ := json.Marshal(headers)
	writeMessage(s, SyncMsgHeaders, headersData)
}

// handleGetBlocks responds to a blocks request
func (sm *SyncManager) handleGetBlocks(s network.Stream, data []byte) {
	var req BlocksRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return
	}

	if len(req.Hashes) > MaxBlocksPerRequest {
		req.Hashes = req.Hashes[:MaxBlocksPerRequest]
	}

	blocks, err := sm.getBlocks(req.Hashes)
	if err != nil {
		return
	}

	// Send blocks
	blocksData, _ := json.Marshal(blocks)
	writeMessage(s, SyncMsgBlocks, blocksData)
}

// handleGetBlocksByHeight handles requests for blocks by height range
func (sm *SyncManager) handleGetBlocksByHeight(s network.Stream, data []byte) {
	var req BlocksByHeightRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return
	}

	if req.MaxBlocks > MaxBlocksPerRequest {
		req.MaxBlocks = MaxBlocksPerRequest
	}

	blocks, err := sm.getBlocksByHeight(req.StartHeight, req.MaxBlocks)
	if err != nil {
		return
	}

	blocksData, _ := json.Marshal(blocks)
	writeMessage(s, SyncMsgBlocks, blocksData)
}

// handleNewBlock processes a new block announcement and relays to other peers
func (sm *SyncManager) handleNewBlock(from peer.ID, data []byte) {
	if sm.processBlock != nil {
		if err := sm.processBlock(data); err != nil {
			return // Don't relay invalid blocks
		}
		// Relay to other peers (exclude sender)
		sm.relayBlock(from, data)
	}
}

// relayBlock sends a block to all peers except the sender
func (sm *SyncManager) relayBlock(from peer.ID, data []byte) {
	peers := sm.node.Peers()
	for _, p := range peers {
		if p == from {
			continue
		}
		go func(pid peer.ID) {
			ctx, cancel := context.WithTimeout(sm.ctx, 10*time.Second)
			defer cancel()

			s, err := sm.node.host.NewStream(ctx, pid, ProtocolSync)
			if err != nil {
				return
			}
			defer s.Close()

			writeMessage(s, SyncMsgNewBlock, data)
		}(p)
	}
}

// handleGetMempool responds to a mempool request
func (sm *SyncManager) handleGetMempool(s network.Stream) {
	// Will be implemented with mempool integration
	writeMessage(s, SyncMsgMempool, []byte("[]"))
}

// syncLoop periodically checks if we need to sync
func (sm *SyncManager) syncLoop() {
	// Initial sync after short delay
	time.Sleep(5 * time.Second)
	sm.checkSync()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			sm.checkSync()
		}
	}
}

// TriggerSync forces a sync check (called when new peer connects)
func (sm *SyncManager) TriggerSync() {
	go sm.checkSync()
}

// checkSync checks if we're behind and need to sync
func (sm *SyncManager) checkSync() {
	sm.mu.RLock()
	if sm.syncing {
		sm.mu.RUnlock()
		return
	}
	sm.mu.RUnlock()

	peers := sm.node.Peers()
	if len(peers) == 0 {
		return
	}

	ourStatus := sm.getStatus()

	// Find the peer with the most work/height
	var bestPeer peer.ID
	var bestStatus ChainStatus

	for _, p := range peers {
		status, err := sm.getStatusFrom(p)
		if err != nil {
			// log.Printf("[sync] failed to get status from %s: %v", p.String()[:16], err)
			continue
		}


		if status.TotalWork > bestStatus.TotalWork ||
			(status.TotalWork == bestStatus.TotalWork && status.Height > bestStatus.Height) {
			bestPeer = p
			bestStatus = status
		}
	}

	if bestPeer == "" {
		return
	}

	// Sync if peer has more work OR more height (handles fork recovery)
	if bestStatus.TotalWork > ourStatus.TotalWork {
		go sm.syncFrom(bestPeer, bestStatus)
	} else if bestStatus.Height > ourStatus.Height {
		go sm.syncFrom(bestPeer, bestStatus)
	}
}

// getStatusFrom requests status from a peer
func (sm *SyncManager) getStatusFrom(p peer.ID) (ChainStatus, error) {
	ctx, cancel := context.WithTimeout(sm.ctx, 30*time.Second)
	defer cancel()

	s, err := sm.node.host.NewStream(ctx, p, ProtocolSync)
	if err != nil {
		return ChainStatus{}, err
	}
	defer s.Close()

	// Send our status
	ourStatus := sm.getStatus()
	statusData, _ := json.Marshal(ourStatus)
	if err := writeMessage(s, SyncMsgStatus, statusData); err != nil {
		return ChainStatus{}, err
	}

	// Read their status
	msgType, data, err := readMessage(s)
	if err != nil {
		return ChainStatus{}, err
	}

	if msgType != SyncMsgStatus {
		return ChainStatus{}, fmt.Errorf("unexpected message type: %d", msgType)
	}

	var status ChainStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return ChainStatus{}, err
	}

	return status, nil
}

// syncFrom performs chain sync from a peer
func (sm *SyncManager) syncFrom(p peer.ID, peerStatus ChainStatus) {
	sm.mu.Lock()
	if sm.syncing {
		sm.mu.Unlock()
		return
	}
	sm.syncing = true
	sm.syncPeer = p
	sm.syncStartTime = time.Now()
	sm.mu.Unlock()

	defer func() {
		sm.mu.Lock()
		sm.syncing = false
		sm.syncPeer = ""
		sm.mu.Unlock()
	}()

	// Get our current height
	ourStatus := sm.getStatus()
	startHeight := ourStatus.Height + 1

	// log.Printf("[sync] starting sync from height %d to %d from peer %s", startHeight, peerStatus.Height, p.String()[:16])

	// Fetch full blocks in batches (more private than header-first)
	for {
		blocks, err := sm.fetchBlocksByHeight(p, startHeight, MaxBlocksPerRequest)
		if err != nil {
			// log.Printf("[sync] failed to fetch blocks at height %d: %v", startHeight, err)
			sm.node.PenalizePeer(p, ScorePenaltyTimeout, "fetch blocks timeout")
			break
		}
		if len(blocks) == 0 {
			// log.Printf("[sync] no blocks returned at height %d", startHeight)
			break
		}

		// log.Printf("[sync] received %d blocks starting at height %d", len(blocks), startHeight)

		// Process blocks (validates and adds to chain)
		for _, blockData := range blocks {
			if err := sm.processBlock(blockData); err != nil {
				// log.Printf("[sync] failed to process block at height %d: %v", startHeight+uint64(i), err)
				// Penalize peer for sending invalid blocks
				sm.node.PenalizePeer(p, ScorePenaltyInvalid, "invalid block data")
				return // Stop syncing with this peer
			}
			// Reward peer for valid blocks
			sm.node.RewardPeer(p)
		}

		startHeight += uint64(len(blocks))

		// Check if we've caught up
		if startHeight > peerStatus.Height {
			// log.Printf("[sync] sync complete, now at height %d", startHeight-1)
			break
		}
	}
}

// fetchHeaders fetches headers from a peer
func (sm *SyncManager) fetchHeaders(p peer.ID, startHeight uint64, max int) ([][]byte, error) {
	ctx, cancel := context.WithTimeout(sm.ctx, 60*time.Second)
	defer cancel()

	s, err := sm.node.host.NewStream(ctx, p, ProtocolSync)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	// Send request
	req := HeadersRequest{
		StartHeight: startHeight,
		MaxHeaders:  max,
	}
	reqData, _ := json.Marshal(req)
	if err := writeMessage(s, SyncMsgGetHeaders, reqData); err != nil {
		return nil, err
	}

	// Read response
	msgType, data, err := readMessage(s)
	if err != nil {
		return nil, err
	}

	if msgType != SyncMsgHeaders {
		return nil, fmt.Errorf("unexpected message type: %d", msgType)
	}

	var headers [][]byte
	if err := json.Unmarshal(data, &headers); err != nil {
		return nil, err
	}

	return headers, nil
}

// FetchBlocks fetches full blocks from a peer
func (sm *SyncManager) FetchBlocks(p peer.ID, hashes [][32]byte) ([][]byte, error) {
	ctx, cancel := context.WithTimeout(sm.ctx, 120*time.Second)
	defer cancel()

	s, err := sm.node.host.NewStream(ctx, p, ProtocolSync)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	req := BlocksRequest{Hashes: hashes}
	reqData, _ := json.Marshal(req)
	if err := writeMessage(s, SyncMsgGetBlocks, reqData); err != nil {
		return nil, err
	}

	msgType, data, err := readMessage(s)
	if err != nil {
		return nil, err
	}

	if msgType != SyncMsgBlocks {
		return nil, fmt.Errorf("unexpected message type: %d", msgType)
	}

	var blocks [][]byte
	if err := json.Unmarshal(data, &blocks); err != nil {
		return nil, err
	}

	return blocks, nil
}

// fetchBlocksByHeight requests blocks by height range (internal for sync)
func (sm *SyncManager) fetchBlocksByHeight(p peer.ID, startHeight uint64, max int) ([][]byte, error) {
	ctx, cancel := context.WithTimeout(sm.ctx, 120*time.Second)
	defer cancel()

	s, err := sm.node.host.NewStream(ctx, p, ProtocolSync)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	req := BlocksByHeightRequest{
		StartHeight: startHeight,
		MaxBlocks:   max,
	}
	reqData, _ := json.Marshal(req)
	if err := writeMessage(s, SyncMsgGetBlocksByHeight, reqData); err != nil {
		return nil, err
	}

	msgType, data, err := readMessage(s)
	if err != nil {
		return nil, err
	}

	if msgType != SyncMsgBlocks {
		return nil, fmt.Errorf("unexpected message type: %d", msgType)
	}

	var blocks [][]byte
	if err := json.Unmarshal(data, &blocks); err != nil {
		return nil, err
	}

	return blocks, nil
}

// BroadcastBlock announces a new block to all peers
func (sm *SyncManager) BroadcastBlock(blockData []byte) {
	peers := sm.node.Peers()

	for _, p := range peers {
		go func(pid peer.ID) {
			ctx, cancel := context.WithTimeout(sm.ctx, 10*time.Second)
			defer cancel()

			s, err := sm.node.host.NewStream(ctx, pid, ProtocolSync)
			if err != nil {
				return
			}
			defer s.Close()

			writeMessage(s, SyncMsgNewBlock, blockData)
		}(p)
	}
}

// IsSyncing returns whether we're currently syncing
func (sm *SyncManager) IsSyncing() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.syncing
}

// SyncProgress returns sync progress info
func (sm *SyncManager) SyncProgress() (peer.ID, time.Duration) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.syncing {
		return "", 0
	}

	return sm.syncPeer, time.Since(sm.syncStartTime)
}
