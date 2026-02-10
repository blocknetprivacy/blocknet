package p2p

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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

// PeerStatus combines peer ID with their chain status
type PeerStatus struct {
	Peer   peer.ID
	Status ChainStatus
}

// SyncWork represents a batch of blocks to download
type SyncWork struct {
	Start uint64
	End   uint64
}

// DownloadedBlock represents a block downloaded from a peer
type DownloadedBlock struct {
	Height uint64
	Data   []byte
	Peer   peer.ID
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
	getMempool        func() [][]byte
	processTx         func(data []byte) error
	onBlockAccepted   func(data []byte)
	isOrphanError     func(error) bool
	getBlockMeta      func(data []byte) (height uint64, prevHash [32]byte, err error)
	getBlockHash      func(data []byte) (hash [32]byte, err error)
	fetchBlocksByHash func(context.Context, peer.ID, [][32]byte) ([][]byte, error)

	// Sync state
	syncing        bool
	syncPeer       peer.ID
	syncStartTime  time.Time
	syncTarget     uint64            // Target height we're syncing to
	syncProgress   uint64            // Current height we've processed to
	downloadBuffer map[uint64][]byte // Buffer for out-of-order blocks

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
	GetMempool        func() [][]byte                                              // Get all mempool transactions
	ProcessTx         func(data []byte) error                                      // Process a mempool transaction
	OnBlockAccepted   func(data []byte)                                            // Called when a new block announcement is accepted
	IsOrphanError     func(error) bool                                             // Orphan classifier for sync recovery (required for recovery to work)
	GetBlockMeta      func(data []byte) (uint64, [32]byte, error)                  // Extract (height, prevHash) from serialized block; required for orphan recovery
	GetBlockHash      func(data []byte) ([32]byte, error)                          // Extract block hash from serialized block; required for parent hash verification in orphan recovery
	FetchBlocksByHash func(context.Context, peer.ID, [][32]byte) ([][]byte, error) // Override block-by-hash fetching (default: p2p FetchBlocks)
}

// NewSyncManager creates a new sync manager
func NewSyncManager(node *Node, cfg SyncConfig) *SyncManager {
	sm := &SyncManager{
		node:              node,
		getStatus:         cfg.GetStatus,
		getHeaders:        cfg.GetHeaders,
		getBlocks:         cfg.GetBlocks,
		getBlocksByHeight: cfg.GetBlocksByHeight,
		processBlock:      cfg.ProcessBlock,
		processHeader:     cfg.ProcessHeader,
		getMempool:        cfg.GetMempool,
		processTx:         cfg.ProcessTx,
		onBlockAccepted:   cfg.OnBlockAccepted,
		isOrphanError:     cfg.IsOrphanError,
		getBlockMeta:      cfg.GetBlockMeta,
		getBlockHash:      cfg.GetBlockHash,
		downloadBuffer:    make(map[uint64][]byte),
	}
	if cfg.FetchBlocksByHash != nil {
		sm.fetchBlocksByHash = cfg.FetchBlocksByHash
	} else if node != nil {
		sm.fetchBlocksByHash = sm.FetchBlocks
	}
	return sm
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
	s.SetDeadline(time.Now().Add(60 * time.Second))

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
		// Notify daemon (miner restart, wallet subscribers)
		if sm.onBlockAccepted != nil {
			sm.onBlockAccepted(data)
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
	if sm.getMempool == nil {
		writeMessage(s, SyncMsgMempool, []byte("[]"))
		return
	}

	txs := sm.getMempool()
	data, err := json.Marshal(txs)
	if err != nil {
		writeMessage(s, SyncMsgMempool, []byte("[]"))
		return
	}

	writeMessage(s, SyncMsgMempool, data)
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

	// Query status from all peers concurrently
	type statusResult struct {
		ps  PeerStatus
		err error
	}
	resultCh := make(chan statusResult, len(peers))
	for _, p := range peers {
		go func(pid peer.ID) {
			status, err := sm.getStatusFrom(pid)
			resultCh <- statusResult{ps: PeerStatus{Peer: pid, Status: status}, err: err}
		}(p)
	}

	var peerStatuses []PeerStatus
	statusTimeout := time.After(15 * time.Second)
collectStatuses:
	for i := 0; i < len(peers); i++ {
		select {
		case r := <-resultCh:
			if r.err == nil {
				peerStatuses = append(peerStatuses, r.ps)
			}
		case <-statusTimeout:
			break collectStatuses
		case <-sm.ctx.Done():
			return
		}
	}

	if len(peerStatuses) == 0 {
		return
	}

	// Find peers with the most work
	var maxWork uint64
	for _, ps := range peerStatuses {
		if ps.Status.TotalWork > maxWork {
			maxWork = ps.Status.TotalWork
		}
	}

	// Collect all peers with max work (or close to it)
	var syncPeers []PeerStatus
	for _, ps := range peerStatuses {
		if ps.Status.TotalWork >= maxWork {
			syncPeers = append(syncPeers, ps)
		}
	}

	if len(syncPeers) == 0 {
		return
	}

	// Use the highest height among max work peers as target
	targetHeight := syncPeers[0].Status.Height
	for _, ps := range syncPeers {
		if ps.Status.Height > targetHeight {
			targetHeight = ps.Status.Height
		}
	}

	// Sync if we're behind
	if maxWork > ourStatus.TotalWork || targetHeight > ourStatus.Height {
		go sm.parallelSyncFrom(syncPeers, targetHeight)
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
	s.SetDeadline(time.Now().Add(30 * time.Second))

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

// parallelSyncFrom performs parallel chain sync from multiple peers
func (sm *SyncManager) parallelSyncFrom(peers []PeerStatus, targetHeight uint64) {
	sm.mu.Lock()
	if sm.syncing {
		sm.mu.Unlock()
		return
	}
	sm.syncing = true
	if len(peers) > 0 {
		sm.syncPeer = peers[0].Peer // Primary peer for display
	}
	sm.syncStartTime = time.Now()
	sm.syncTarget = targetHeight
	sm.downloadBuffer = make(map[uint64][]byte) // Reset buffer
	sm.mu.Unlock()

	defer func() {
		sm.mu.Lock()
		sm.syncing = false
		sm.syncPeer = ""
		sm.syncTarget = 0
		sm.syncProgress = 0
		sm.downloadBuffer = make(map[uint64][]byte) // Clear buffer
		sm.mu.Unlock()
	}()

	// Get our current height
	ourStatus := sm.getStatus()
	startHeight := ourStatus.Height + 1

	// When close to the tip, overlap by a few blocks so we pick up
	// any short-fork blocks the peer has that differ from ours.
	if gap := targetHeight - ourStatus.Height; gap <= 50 && ourStatus.Height > 10 {
		startHeight = ourStatus.Height - 10
	}

	sm.mu.Lock()
	sm.syncProgress = ourStatus.Height
	sm.mu.Unlock()

	// log.Printf("[sync] starting parallel sync from height %d to %d with %d peers", startHeight, targetHeight, len(peers))

	// Use up to 3 peers for parallel download
	numDownloaders := len(peers)
	if numDownloaders > 3 {
		numDownloaders = 3
	}

	// Channel to receive downloaded blocks
	blockChan := make(chan DownloadedBlock, MaxBlocksPerRequest*numDownloaders)

	// Channel to distribute work
	workChan := make(chan SyncWork, 10)

	// Context for downloaders
	ctx, cancel := context.WithCancel(sm.ctx)
	defer cancel()

	var downloadWg sync.WaitGroup

	// Start downloader goroutines
	for i := 0; i < numDownloaders && i < len(peers); i++ {
		downloadWg.Add(1)
		peerID := peers[i].Peer
		go func(p peer.ID) {
			defer downloadWg.Done()
			sm.downloader(ctx, p, workChan, blockChan)
		}(peerID)
	}

	// Start work distributor
	go func() {
		currentHeight := startHeight
		for currentHeight <= targetHeight {
			batchSize := uint64(MaxBlocksPerRequest)
			if currentHeight+batchSize-1 > targetHeight {
				batchSize = targetHeight - currentHeight + 1
			}

			select {
			case workChan <- SyncWork{Start: currentHeight, End: currentHeight + batchSize - 1}:
				currentHeight += batchSize
			case <-ctx.Done():
				return
			}
		}
		close(workChan)
	}()

	// Process blocks sequentially in order
	nextHeight := startHeight
	processorDone := make(chan struct{})

	go func() {
		defer close(processorDone)
		for nextHeight <= targetHeight {
			// Try to get block from buffer first
			sm.mu.Lock()
			blockData, inBuffer := sm.downloadBuffer[nextHeight]
			if inBuffer {
				delete(sm.downloadBuffer, nextHeight)
			}
			sm.mu.Unlock()

			if !inBuffer {
				// Wait for block to arrive
				select {
				case block := <-blockChan:
					if block.Height == nextHeight {
						blockData = block.Data
					} else {
						// Out of order - buffer it
						sm.mu.Lock()
						sm.downloadBuffer[block.Height] = block.Data
						sm.mu.Unlock()
						continue
					}
				case <-ctx.Done():
					return
				case <-time.After(30 * time.Second):
					// Downloader stalled - fan out to ALL peers concurrently for a batch
					batchSize := int(targetHeight - nextHeight + 1)
					if batchSize > MaxBlocksPerRequest {
						batchSize = MaxBlocksPerRequest
					}

					var rescue [][]byte
					for attempt := 0; attempt < 3; attempt++ {
						if ctx.Err() != nil {
							return
						}
						rescue = sm.fetchBlocksFromAnyPeer(peers, nextHeight, batchSize)
						if len(rescue) > 0 {
							break
						}
						// Brief pause before retry
						select {
						case <-time.After(5 * time.Second):
						case <-ctx.Done():
							return
						}
					}

					if len(rescue) == 0 {
						return
					}
					blockData = rescue[0]
					// Buffer the rest so we don't stall again immediately
					if len(rescue) > 1 {
						sm.mu.Lock()
						for i := 1; i < len(rescue); i++ {
							sm.downloadBuffer[nextHeight+uint64(i)] = rescue[i]
						}
						sm.mu.Unlock()
					}
				}
			}

			// Process block (with orphan recovery for reorg sync).
			if err := sm.ProcessBlockWithRecoveryCtx(ctx, blockData, peers); err != nil {
				log.Printf("[sync] block %d failed: %v", nextHeight, err)
				return
			}

			// Update progress
			sm.mu.Lock()
			sm.syncProgress = nextHeight
			sm.mu.Unlock()

			nextHeight++

			// Log progress every 50 blocks
			if nextHeight%50 == 0 || nextHeight == targetHeight+1 {
				// log.Printf("[sync] progress: %d/%d (%.1f%%)", nextHeight-1, targetHeight, float64(nextHeight-1)/float64(targetHeight)*100)
			}
		}
	}()

	// Wait for processing to complete or timeout
	select {
	case <-processorDone:
		// log.Printf("[sync] sync complete at height %d", nextHeight-1)
	case <-time.After(10 * time.Minute):
		// log.Printf("[sync] sync timeout")
	case <-ctx.Done():
		// log.Printf("[sync] sync cancelled")
	}

	// Signal downloaders to stop
	cancel()
	downloadWg.Wait()

	// After syncing blocks, request mempool from first peer
	if len(peers) > 0 && sm.getMempool != nil && sm.processTx != nil {
		if err := sm.fetchAndProcessMempool(peers[0].Peer); err != nil {
			// log.Printf("[sync] failed to fetch mempool: %v", err)
		}
	}

	// If we didn't reach target, immediately re-check instead of waiting
	// for the 30s periodic tick. Covers transient peer failures.
	finalHeight := sm.getStatus().Height
	if finalHeight < targetHeight && sm.ctx != nil && sm.ctx.Err() == nil {
		go func() {
			select {
			case <-time.After(3 * time.Second):
				sm.checkSync()
			case <-sm.ctx.Done():
			}
		}()
	}
}

// downloader fetches blocks for assigned ranges
func (sm *SyncManager) downloader(ctx context.Context, p peer.ID, workChan <-chan SyncWork, blockChan chan<- DownloadedBlock) {
	for {
		select {
		case work, ok := <-workChan:
			if !ok {
				return
			}

			// Calculate batch size
			batchSize := int(work.End - work.Start + 1)
			if batchSize > MaxBlocksPerRequest {
				batchSize = MaxBlocksPerRequest
			}

			// Fetch blocks
			blocks, err := sm.fetchBlocksByHeight(p, work.Start, batchSize)
			if err != nil {
				// log.Printf("[sync] peer %s failed to fetch blocks %d-%d: %v", p.String()[:8], work.Start, work.End, err)
				sm.node.PenalizePeer(p, ScorePenaltyTimeout, "fetch blocks timeout")
				// Exit - work distributor will handle missing blocks via timeout
				return
			}

			if len(blocks) == 0 {
				// log.Printf("[sync] peer %s returned no blocks for range %d-%d", p.String()[:8], work.Start, work.End)
				return
			}

			// Send blocks to processor
			for i, blockData := range blocks {
				height := work.Start + uint64(i)
				select {
				case blockChan <- DownloadedBlock{Height: height, Data: blockData, Peer: p}:
					// Reward peer for valid data
					sm.node.RewardPeer(p)
				case <-ctx.Done():
					return
				}
			}

		case <-ctx.Done():
			return
		}
	}
}

func (sm *SyncManager) isOrphanErr(err error) bool {
	if err == nil || sm.isOrphanError == nil {
		return false
	}
	return sm.isOrphanError(err)
}

func (sm *SyncManager) ProcessBlockWithRecovery(blockData []byte, peers []PeerStatus) error {
	return sm.ProcessBlockWithRecoveryCtx(sm.ctx, blockData, peers)
}

func (sm *SyncManager) ProcessBlockWithRecoveryCtx(ctx context.Context, blockData []byte, peers []PeerStatus) error {
	if sm.processBlock == nil {
		return nil
	}

	err := sm.processBlock(blockData)
	if err == nil {
		return nil
	}
	if !sm.isOrphanErr(err) {
		return err
	}

	// Recover by fetching and connecting the missing parent chain by hash.
	if recErr := sm.recoverOrphanChain(ctx, blockData, peers); recErr != nil {
		return recErr
	}
	return nil
}

func (sm *SyncManager) recoverOrphanChain(ctx context.Context, blockData []byte, peers []PeerStatus) error {
	const maxRecoveryDepth = 512
	const recoveryTimeout = 10 * time.Minute

	if len(peers) == 0 {
		return fmt.Errorf("orphan recovery failed: no peers available")
	}
	if sm.getBlockMeta == nil {
		return fmt.Errorf("orphan recovery failed: GetBlockMeta callback not configured")
	}
	if sm.getBlockHash == nil {
		return fmt.Errorf("orphan recovery failed: GetBlockHash callback not configured")
	}
	if sm.fetchBlocksByHash == nil {
		return fmt.Errorf("orphan recovery failed: FetchBlocksByHash callback not configured")
	}

	baseCtx := ctx
	if baseCtx == nil {
		baseCtx = sm.ctx
	}
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, recoveryTimeout)
	defer cancel()

	pending := make([][]byte, 0, 8)
	pending = append(pending, blockData)
	current := blockData
	seenParents := make(map[[32]byte]struct{})

outer:
	for depth := 0; depth < maxRecoveryDepth; depth++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("orphan recovery timed out after fetching %d parents: %w", depth, err)
		}

		height, prevHash, err := sm.getBlockMeta(current)
		if err != nil {
			return fmt.Errorf("orphan recovery failed to decode block metadata: %w", err)
		}
		if height == 0 {
			return fmt.Errorf("orphan recovery reached genesis without finding connectable parent")
		}

		parentHash := prevHash
		if _, exists := seenParents[parentHash]; exists {
			return fmt.Errorf("orphan recovery detected parent cycle at %x", parentHash[:8])
		}
		seenParents[parentHash] = struct{}{}

		invalidPeers := make(map[peer.ID]struct{})
		var lastProcessErr error
		for len(invalidPeers) < len(peers) {
			parentData, sourcePeer, err := sm.fetchBlockByHashFromAnyPeer(ctx, peers, parentHash, invalidPeers)
			if err != nil {
				if lastProcessErr != nil {
					return fmt.Errorf(
						"orphan recovery failed while processing parent %x after %d invalid peer responses: %w",
						parentHash[:8], len(invalidPeers), lastProcessErr,
					)
				}
				return fmt.Errorf("orphan recovery failed to fetch parent %x (child height %d): %w", parentHash[:8], height, err)
			}

			// If the parent is known, this returns nil (accepted or duplicate).
			if err := sm.processBlock(parentData); err != nil {
				if sm.isOrphanErr(err) {
					pending = append(pending, parentData)
					current = parentData
					continue outer
				}

				// This peer returned hash-matching data that still fails validation.
				// Keep trying other peers for the same parent hash before failing.
				invalidPeers[sourcePeer] = struct{}{}
				lastProcessErr = err
				continue
			}

			// Parent chain is now connected; replay queued children from oldest to newest.
			for i := len(pending) - 1; i >= 0; i-- {
				if err := sm.processBlock(pending[i]); err != nil {
					return fmt.Errorf("orphan recovery replay failed: %w", err)
				}
			}
			return nil
		}

		if lastProcessErr != nil {
			return fmt.Errorf(
				"orphan recovery failed while processing parent %x after %d invalid peer responses: %w",
				parentHash[:8], len(invalidPeers), lastProcessErr,
			)
		}
		return fmt.Errorf("orphan recovery failed: no peers left to try for parent %x", parentHash[:8])
	}

	return fmt.Errorf("orphan recovery exceeded max depth (%d)", maxRecoveryDepth)
}

func (sm *SyncManager) fetchBlockByHashFromAnyPeer(
	ctx context.Context, peers []PeerStatus, hash [32]byte, exclude map[peer.ID]struct{},
) ([]byte, peer.ID, error) {
	type result struct {
		block []byte
		peer  peer.ID
		err   error
	}
	if sm.fetchBlocksByHash == nil {
		return nil, "", fmt.Errorf("FetchBlocksByHash callback not configured")
	}
	if sm.getBlockHash == nil {
		return nil, "", fmt.Errorf("GetBlockHash callback not configured")
	}

	// ctx may be nil when called outside of Start() (e.g. unit tests).
	if ctx == nil {
		ctx = context.Background()
	}

	activePeers := make([]PeerStatus, 0, len(peers))
	for _, ps := range peers {
		if exclude != nil {
			if _, skip := exclude[ps.Peer]; skip {
				continue
			}
		}
		activePeers = append(activePeers, ps)
	}
	if len(activePeers) == 0 {
		return nil, "", fmt.Errorf("no peers available for block %x", hash[:8])
	}

	// Cancel remaining goroutines once we get a successful result.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan result, len(activePeers))
	for _, ps := range activePeers {
		go func(p peer.ID) {
			blocks, err := sm.fetchBlocksByHash(ctx, p, [][32]byte{hash})
			if err != nil {
				ch <- result{peer: p, err: err}
				return
			}
			if len(blocks) == 0 || len(blocks[0]) == 0 {
				ch <- result{peer: p, err: fmt.Errorf("peer %s returned no blocks for %x", p, hash[:8])}
				return
			}
			blockHash, err := sm.getBlockHash(blocks[0])
			if err != nil {
				ch <- result{peer: p, err: fmt.Errorf("peer %s returned undecodable block for %x: %w", p, hash[:8], err)}
				return
			}
			if blockHash != hash {
				ch <- result{peer: p, err: fmt.Errorf("peer %s returned mismatched block hash %x for %x", p, blockHash[:8], hash[:8])}
				return
			}
			ch <- result{peer: p, block: blocks[0]}
		}(ps.Peer)
	}

	var lastErr error
	for i := 0; i < len(activePeers); i++ {
		select {
		case r := <-ch:
			if r.err == nil && len(r.block) > 0 {
				return r.block, r.peer, nil
			}
			if r.err != nil {
				lastErr = r.err
			} else {
				lastErr = fmt.Errorf("peer returned empty block for %x", hash[:8])
			}
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}

	if lastErr != nil {
		return nil, "", lastErr
	}
	return nil, "", fmt.Errorf("block %x not found on sync peers", hash[:8])
}

// syncFrom wraps single peer sync in the parallel sync mechanism
func (sm *SyncManager) syncFrom(p peer.ID, peerStatus ChainStatus) {
	peers := []PeerStatus{{Peer: p, Status: peerStatus}}
	sm.parallelSyncFrom(peers, peerStatus.Height)
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
	s.SetDeadline(time.Now().Add(60 * time.Second))

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
func (sm *SyncManager) FetchBlocks(ctx context.Context, p peer.ID, hashes [][32]byte) ([][]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	s, err := sm.node.host.NewStream(ctx, p, ProtocolSync)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(120 * time.Second))

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

// fetchBlocksFromAnyPeer fires concurrent requests to ALL peers for the same
// block range and returns the first successful batch. This ensures a single
// slow or dead peer can't stall the sync.
func (sm *SyncManager) fetchBlocksFromAnyPeer(peers []PeerStatus, startHeight uint64, count int) [][]byte {
	type result struct {
		blocks [][]byte
	}

	ch := make(chan result, len(peers))
	for _, ps := range peers {
		go func(p peer.ID) {
			blocks, err := sm.fetchBlocksByHeight(p, startHeight, count)
			if err != nil || len(blocks) == 0 {
				ch <- result{}
			} else {
				ch <- result{blocks: blocks}
			}
		}(ps.Peer)
	}

	for i := 0; i < len(peers); i++ {
		select {
		case r := <-ch:
			if len(r.blocks) > 0 {
				return r.blocks
			}
		case <-sm.ctx.Done():
			return nil
		}
	}

	return nil
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
	s.SetDeadline(time.Now().Add(120 * time.Second))

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

// SyncProgress returns sync progress info (current, target, elapsed)
func (sm *SyncManager) SyncProgress() (uint64, uint64, time.Duration) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.syncing {
		return 0, 0, 0
	}

	return sm.syncProgress, sm.syncTarget, time.Since(sm.syncStartTime)
}

// fetchAndProcessMempool requests mempool transactions from a peer and processes them
func (sm *SyncManager) fetchAndProcessMempool(p peer.ID) error {
	ctx, cancel := context.WithTimeout(sm.ctx, 60*time.Second)
	defer cancel()

	s, err := sm.node.host.NewStream(ctx, p, ProtocolSync)
	if err != nil {
		return err
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(60 * time.Second))

	// Request mempool
	if err := writeMessage(s, SyncMsgGetMempool, []byte{}); err != nil {
		return err
	}

	// Read response
	msgType, data, err := readMessage(s)
	if err != nil {
		return err
	}

	if msgType != SyncMsgMempool {
		return fmt.Errorf("unexpected message type: %d", msgType)
	}

	var txs [][]byte
	if err := json.Unmarshal(data, &txs); err != nil {
		return err
	}

	// Process each transaction
	for _, txData := range txs {
		// Ignore errors - some txs might be duplicates or invalid
		sm.processTx(txData)
	}

	return nil
}
