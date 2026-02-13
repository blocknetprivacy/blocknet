package main

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandleEventsUnsubscribesOnClientDisconnect(t *testing.T) {
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	daemon, stopDaemon := mustStartTestDaemon(t, chain)
	defer stopDaemon()

	server := &APIServer{daemon: daemon}

	req := httptest.NewRequest("GET", "/api/events", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleEvents(rr, req)
	}()

	waitFor := func(cond func() bool, timeout time.Duration) bool {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if cond() {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return cond()
	}

	subscribed := waitFor(func() bool {
		daemon.blockSubsMu.Lock()
		blockN := len(daemon.blockSubs)
		daemon.blockSubsMu.Unlock()

		daemon.minedSubsMu.Lock()
		minedN := len(daemon.minedSubs)
		daemon.minedSubsMu.Unlock()

		return blockN == 1 && minedN == 1
	}, time.Second)
	if !subscribed {
		t.Fatal("expected SSE handler to subscribe to block and mined channels")
	}

	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SSE handler did not exit after client disconnect")
	}

	unsubscribed := waitFor(func() bool {
		daemon.blockSubsMu.Lock()
		blockN := len(daemon.blockSubs)
		daemon.blockSubsMu.Unlock()

		daemon.minedSubsMu.Lock()
		minedN := len(daemon.minedSubs)
		daemon.minedSubsMu.Unlock()

		return blockN == 0 && minedN == 0
	}, time.Second)
	if !unsubscribed {
		t.Fatal("expected SSE handler disconnect to unsubscribe channels")
	}
}
