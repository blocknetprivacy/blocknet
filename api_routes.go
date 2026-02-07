package main

import "net/http"

// registerPublicRoutes adds read-only endpoints.
// These are shared between --api (authenticated) and --explorer (public).
func (s *APIServer) registerPublicRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/block/{id}", s.handleBlock)
	mux.HandleFunc("GET /api/tx/{hash}", s.handleTx)
	mux.HandleFunc("GET /api/mempool", s.handleMempool)
	mux.HandleFunc("GET /api/peers", s.handlePeers)
	mux.HandleFunc("GET /api/peers/banned", s.handleBannedPeers)
}

// registerPrivateRoutes adds wallet, mining, and control endpoints.
// Only registered for --api (always behind auth).
func (s *APIServer) registerPrivateRoutes(mux *http.ServeMux) {
	// Wallet
	mux.HandleFunc("GET /api/wallet/balance", s.handleBalance)
	mux.HandleFunc("GET /api/wallet/address", s.handleAddress)
	mux.HandleFunc("GET /api/wallet/history", s.handleHistory)
	mux.HandleFunc("POST /api/wallet/send", s.handleSend)
	mux.HandleFunc("POST /api/wallet/lock", s.handleLock)
	mux.HandleFunc("POST /api/wallet/unlock", s.handleUnlock)
	mux.HandleFunc("POST /api/wallet/seed", s.handleSeed)

	// Mining
	mux.HandleFunc("GET /api/mining", s.handleMiningStatus)
	mux.HandleFunc("POST /api/mining/start", s.handleMiningStart)
	mux.HandleFunc("POST /api/mining/stop", s.handleMiningStop)
	mux.HandleFunc("POST /api/mining/threads", s.handleMiningThreads)

	// SSE
	mux.HandleFunc("GET /api/events", s.handleEvents)
}
