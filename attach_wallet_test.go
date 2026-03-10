package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// testSessionWithWallet sets up a session with a config that already has
// WalletFile pointed at the given name inside the wallets dir, so that
// cmdLoad doesn't attempt a core restart.
func testSessionWithWallet(t *testing.T, handler http.Handler, input, walletName string) *AttachSession {
	t.Helper()
	tmpDir := t.TempDir()
	t.Setenv("BNT_CONFIG_DIR", tmpDir)
	t.Setenv("HOME", tmpDir)

	walletsDir := filepath.Join(tmpDir, "wallets")
	os.MkdirAll(walletsDir, 0755)
	walletPath := filepath.Join(walletsDir, walletName)

	cfg := DefaultConfig()
	cfg.Cores[Mainnet].WalletFile = walletPath
	cfgData, _ := json.Marshal(cfg)
	os.WriteFile(filepath.Join(tmpDir, "config.json"), cfgData, 0644)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &AttachSession{
		client:  NewCoreClientDirect(srv.URL, "test-token"),
		reader:  bufio.NewReader(strings.NewReader(input)),
		noColor: true,
		network: Mainnet,
	}
}

func TestCmdLoad_StaleStateAfterFailedAuth(t *testing.T) {
	// Input: choose found wallet (option 1), password "testpass"
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/wallet/balance":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "no wallet loaded"})
		case "/api/wallet/load":
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "wallet already loaded"})
		}
	}), "1\ntestpass\n", "testwallet.wallet.dat")

	walletsDir := filepath.Join(os.Getenv("BNT_CONFIG_DIR"), "wallets")
	os.WriteFile(filepath.Join(walletsDir, "testwallet.wallet.dat"), []byte("dummy"), 0600)

	err := session.cmdLoad()
	if err == nil {
		t.Fatal("expected error for stale wallet state, got nil")
	}
	if !strings.Contains(err.Error(), "core thinks a wallet is already loaded") {
		t.Errorf("expected stale-state error message, got: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "blocknet restart") {
		t.Errorf("expected restart suggestion in error, got: %s", err.Error())
	}
}

func TestCmdLoad_RaceConditionWalletLoadedDuringMenu(t *testing.T) {
	var balanceCalls atomic.Int32

	// No wallet file created → 0 found wallets → option 2 is "create new"
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/wallet/balance":
			n := balanceCalls.Add(1)
			if n == 1 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "no wallet loaded"})
			} else {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]any{"spendable": 0, "pending": 0})
			}
		case "/api/wallet/load":
			t.Error("POST /api/wallet/load should not have been called")
			w.WriteHeader(http.StatusConflict)
		case "/api/wallet/create":
			t.Error("POST /api/wallet/create should not have been called")
			w.WriteHeader(http.StatusConflict)
		}
	}), "2\ntestwallet\ntestpass\n", "testwallet.wallet.dat")

	err := session.cmdLoad()
	if err != nil {
		t.Fatalf("expected nil error (graceful catch), got: %v", err)
	}
	if n := balanceCalls.Load(); n != 2 {
		t.Errorf("expected 2 balance calls (initial + recheck), got %d", n)
	}
}

func TestCmdLoad_NormalSuccess(t *testing.T) {
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/wallet/balance":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "no wallet loaded"})
		case "/api/wallet/load":
			var req map[string]string
			json.NewDecoder(r.Body).Decode(&req)
			if req["filepath"] != "testwallet.wallet.dat" {
				t.Errorf("expected filepath 'testwallet.wallet.dat', got %q", req["filepath"])
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"loaded":   true,
				"address":  "bnt1testaddress",
				"filename": "testwallet.wallet.dat",
			})
		}
	}), "1\ntestpass\n", "testwallet.wallet.dat")

	walletsDir := filepath.Join(os.Getenv("BNT_CONFIG_DIR"), "wallets")
	os.WriteFile(filepath.Join(walletsDir, "testwallet.wallet.dat"), []byte("dummy"), 0600)

	err := session.cmdLoad()
	if err != nil {
		t.Fatalf("expected successful load, got: %v", err)
	}
}

func TestCmdCreate_NormalSuccess(t *testing.T) {
	// No wallet file → 0 found wallets → option 2 is "create new"
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/wallet/balance":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "no wallet loaded"})
		case "/api/wallet/create":
			var req map[string]string
			json.NewDecoder(r.Body).Decode(&req)
			if req["filename"] != "testwallet.wallet.dat" {
				t.Errorf("expected filename 'testwallet.wallet.dat', got %q", req["filename"])
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"created":  true,
				"address":  "bnt1testaddress",
				"filename": "testwallet.wallet.dat",
			})
		}
	}), "2\ntestwallet\ntestpass\n", "testwallet.wallet.dat")

	err := session.cmdLoad()
	if err != nil {
		t.Fatalf("expected successful create, got: %v", err)
	}
}
