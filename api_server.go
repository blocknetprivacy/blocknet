package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"blocknet/wallet"
	"golang.org/x/time/rate"
)

const maxRequestBodyBytes int64 = 1 << 20 // 1MB

const (
	unlockFailureBaseDelay  = 250 * time.Millisecond
	unlockFailureMaxDelay   = 5 * time.Second
	unlockFailureLockout    = 30 * time.Second
	unlockFailureStateTTL   = 30 * time.Minute
	unlockFailuresToLockout = 8
)

// APIServer serves the authenticated JSON API for GUI wallets.
type APIServer struct {
	daemon  *Daemon
	wallet  *wallet.Wallet
	scanner *wallet.Scanner
	dataDir string
	token   string
	server  *http.Server

	// Wallet lock state (mirrors CLI behavior)
	locked   bool
	password []byte
	mu       sync.RWMutex

	// Back-reference to CLI for wallet hot-loading in daemon mode
	cli *CLI

	// Route-scoped abuse controls for expensive block validation.
	submitBlockLimiter *perIPLimiter
	submitBlockSem     chan struct{}

	// Wallet unlock brute-force controls.
	unlockAttempts *unlockAttemptTracker
}

type perIPLimiter struct {
	mu      sync.Mutex
	clients map[string]*ipClientLimiter
	limit   rate.Limit
	burst   int
	ttl     time.Duration
}

type ipClientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type unlockAttemptTracker struct {
	mu      sync.Mutex
	clients map[string]*unlockAttemptState
}

type unlockAttemptState struct {
	failures    int
	nextAllowed time.Time
	lockoutUntil time.Time
	lastSeen    time.Time
}

func newPerIPLimiter(limit rate.Limit, burst int, ttl time.Duration) *perIPLimiter {
	return &perIPLimiter{
		clients: make(map[string]*ipClientLimiter),
		limit:   limit,
		burst:   burst,
		ttl:     ttl,
	}
}

func newUnlockAttemptTracker() *unlockAttemptTracker {
	return &unlockAttemptTracker{
		clients: make(map[string]*unlockAttemptState),
	}
}

func (t *unlockAttemptTracker) precheck(ip string) (time.Duration, time.Time) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	for key, state := range t.clients {
		if now.Sub(state.lastSeen) > unlockFailureStateTTL {
			delete(t.clients, key)
		}
	}

	state, ok := t.clients[ip]
	if !ok {
		return 0, time.Time{}
	}
	state.lastSeen = now

	if now.Before(state.lockoutUntil) {
		return 0, state.lockoutUntil
	}
	if now.Before(state.nextAllowed) {
		return state.nextAllowed.Sub(now), time.Time{}
	}
	return 0, time.Time{}
}

func (t *unlockAttemptTracker) recordFailure(ip string) (time.Duration, time.Time) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	state, ok := t.clients[ip]
	if !ok {
		state = &unlockAttemptState{}
		t.clients[ip] = state
	}

	state.lastSeen = now
	state.failures++

	shift := state.failures - 1
	if shift > 5 {
		shift = 5
	}
	delay := unlockFailureBaseDelay << shift
	if delay > unlockFailureMaxDelay {
		delay = unlockFailureMaxDelay
	}
	state.nextAllowed = now.Add(delay)

	if state.failures >= unlockFailuresToLockout {
		state.lockoutUntil = now.Add(unlockFailureLockout)
		state.nextAllowed = state.lockoutUntil
		state.failures = 0
		return delay, state.lockoutUntil
	}

	return delay, time.Time{}
}

func (t *unlockAttemptTracker) recordSuccess(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.clients, ip)
}

func (l *perIPLimiter) allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// Opportunistic cleanup keeps map bounded without extra goroutines.
	for key, client := range l.clients {
		if now.Sub(client.lastSeen) > l.ttl {
			delete(l.clients, key)
		}
	}

	client, ok := l.clients[ip]
	if !ok {
		client = &ipClientLimiter{
			limiter: rate.NewLimiter(l.limit, l.burst),
		}
		l.clients[ip] = client
	}
	client.lastSeen = now
	return client.limiter.Allow()
}

// NewAPIServer creates a new API server. wallet and scanner may be nil
// for public-only mode (e.g. seed node running --explorer).
func NewAPIServer(daemon *Daemon, w *wallet.Wallet, scanner *wallet.Scanner, dataDir string, password []byte) *APIServer {
	return &APIServer{
		daemon:             daemon,
		wallet:             w,
		scanner:            scanner,
		dataDir:            dataDir,
		password:           password,
		submitBlockLimiter: newPerIPLimiter(rate.Limit(2), 4, 10*time.Minute),
		submitBlockSem:     make(chan struct{}, 2),
		unlockAttempts:     newUnlockAttemptTracker(),
	}
}

// isLocked returns whether the wallet is locked.
func (s *APIServer) isLocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.locked
}

// requireWallet checks that the wallet exists and is unlocked.
// Returns true if the request should proceed.
func (s *APIServer) requireWallet(w http.ResponseWriter, _ *http.Request) bool {
	if s.wallet == nil {
		writeError(w, http.StatusServiceUnavailable, "no wallet loaded")
		return false
	}
	if s.isLocked() {
		writeError(w, http.StatusForbidden, "wallet is locked")
		return false
	}
	return true
}

// Start launches the full authenticated API server.
func (s *APIServer) Start(addr string) error {
	token, err := generateToken()
	if err != nil {
		return fmt.Errorf("failed to generate auth token: %w", err)
	}
	s.token = token

	if err := writeCookie(s.dataDir, token); err != nil {
		deleteCookie(s.dataDir)
		return fmt.Errorf("failed to write cookie: %w", err)
	}

	mux := http.NewServeMux()
	s.registerPublicRoutes(mux)
	s.registerPrivateRoutes(mux)

	var handler http.Handler = mux
	handler = authMiddleware(token, handler)
	handler = maxBodySize(handler, maxRequestBodyBytes)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		deleteCookie(s.dataDir)
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	log.Printf("API listening on %s", addr)

	go func() {
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("API server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the API server and removes the cookie file.
func (s *APIServer) Stop() {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.server.Shutdown(ctx)
	}
	deleteCookie(s.dataDir)
}

// maxBodySize limits request body size to prevent OOM from large payloads.
func maxBodySize(next http.Handler, bytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, bytes)
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}
