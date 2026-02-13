package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// handleEvents streams real-time events via Server-Sent Events.
// Event types: new_block, mined_block, sync_status
// GET /api/events
func (s *APIServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	// Disable write timeout for this long-lived connection.
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Subscribe to block events
	blockCh := s.daemon.SubscribeBlocks()
	minedCh := s.daemon.SubscribeMinedBlocks()
	defer s.daemon.UnsubscribeBlocks(blockCh)
	defer s.daemon.UnsubscribeMinedBlocks(minedCh)

	// Send initial status so the client knows the connection is live
	syncing := false
	if s.daemon != nil && s.daemon.syncMgr != nil {
		syncing = s.daemon.syncMgr.IsSyncing()
	}
	s.sendSSE(w, flusher, "connected", map[string]any{
		"chain_height": s.daemon.Chain().Height(),
		"syncing":      syncing,
	})

	// Keepalive ticker (SSE comment line to prevent proxies from killing idle connections)
	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case block := <-blockCh:
			if block == nil {
				continue
			}
			s.sendSSE(w, flusher, "new_block", map[string]any{
				"height":    block.Header.Height,
				"hash":      fmt.Sprintf("%x", block.Hash()),
				"timestamp": block.Header.Timestamp,
				"tx_count":  len(block.Transactions),
			})

		case block := <-minedCh:
			if block == nil {
				continue
			}
			s.sendSSE(w, flusher, "mined_block", map[string]any{
				"height": block.Header.Height,
				"hash":   fmt.Sprintf("%x", block.Hash()),
				"reward": GetBlockReward(block.Header.Height),
			})

		case <-keepalive.C:
			// SSE comment line — keeps the connection alive through proxies/load balancers
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// sendSSE writes a single SSE event.
func (s *APIServer) sendSSE(w http.ResponseWriter, flusher http.Flusher, event string, data any) {
	payload, err := json.Marshal(data)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, payload)
	flusher.Flush()
}
