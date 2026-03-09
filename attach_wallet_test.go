package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func testSession(t *testing.T, handler http.Handler, input string) *AttachSession {
	t.Helper()
	tmpDir := t.TempDir()
	t.Setenv("BNT_CONFIG_DIR", tmpDir)
	t.Setenv("HOME", tmpDir)

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
	session := testSession(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/wallet/balance":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "no wallet loaded"})
		case "/api/wallet/load":
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "wallet already loaded"})
		}
	}), "2\ntestpass\n")

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

	session := testSession(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		}
	}), "2\ntestpass\n")

	err := session.cmdLoad()
	if err != nil {
		t.Fatalf("expected nil error (graceful catch), got: %v", err)
	}
	if n := balanceCalls.Load(); n != 2 {
		t.Errorf("expected 2 balance calls (initial + recheck), got %d", n)
	}
}

func TestCmdLoad_NormalSuccess(t *testing.T) {
	session := testSession(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/wallet/balance":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "no wallet loaded"})
		case "/api/wallet/load":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"loaded": true, "address": "bnt1testaddress"})
		}
	}), "2\ntestpass\n")

	err := session.cmdLoad()
	if err != nil {
		t.Fatalf("expected successful load, got: %v", err)
	}
}
