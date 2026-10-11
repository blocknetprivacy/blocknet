package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCmdCreate_PasswordMismatch(t *testing.T) {
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/wallet/balance":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "no wallet loaded"})
		case "/api/wallet/create":
			t.Error("create must not be called when passwords differ")
		}
	}), "2\ntestwallet\ntestpass\nother\n", "testwallet.wallet.dat")

	err := session.cmdLoad()
	if err == nil || err.Error() != "passwords do not match" {
		t.Fatalf("expected passwords do not match, got %v", err)
	}
}

func TestCmdLoad_CustomPathOutsideCoreFolder(t *testing.T) {
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/wallet/balance":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "no wallet loaded"})
		case "/api/wallet/load":
			t.Error("load must not be called for a file the core cannot reach")
		}
	}), "", "testwallet.wallet.dat")

	outside := filepath.Join(t.TempDir(), "elsewhere.wallet.dat")
	os.WriteFile(outside, []byte("dummy"), 0600)
	session.reader = bufio.NewReader(strings.NewReader("1\n" + outside + "\ntestpass\n"))

	err := session.cmdLoad()
	if err == nil || !strings.Contains(err.Error(), "only loads wallets from") {
		t.Fatalf("expected core folder error, got %v", err)
	}
}

func TestSendAll_FeeAtLeastBalance(t *testing.T) {
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/wallet/outputs":
			json.NewEncoder(w).Encode(map[string]any{"outputs": []map[string]any{
				{"txid": strings.Repeat("a", 64), "output_index": 0, "amount": 500, "status": "unspent"},
			}})
		case "/api/wallet/send/advanced":
			json.NewEncoder(w).Encode(map[string]any{"fee": 1000})
		}
	}), "", "testwallet.wallet.dat")

	err := session.cmdSend([]string{"9PNoaddr", "all"})
	if err == nil || !strings.Contains(err.Error(), "balance too small to cover the fee") {
		t.Fatalf("expected fee error, got %v", err)
	}
}

func TestLockedWallet_NodeCommandsStillRun(t *testing.T) {
	statusCalls := 0
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/status":
			statusCalls++
			json.NewEncoder(w).Encode(map[string]any{"chain_height": 10})
		default:
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "wallet is locked"})
		}
	}), "", "testwallet.wallet.dat")
	session.locked = true

	if err := session.executeCommand("status"); err != nil {
		t.Fatalf("status while locked: %v", err)
	}
	if statusCalls == 0 {
		t.Fatal("status did not reach the core")
	}
	if err := session.executeCommand("balance"); err != errLocked {
		t.Fatalf("balance while locked: want errLocked, got %v", err)
	}
}

func TestOutputs_RejectsExtraArgs(t *testing.T) {
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"outputs": []any{}})
	}), "", "testwallet.wallet.dat")

	for _, args := range [][]string{{"3", "4"}, {"spent", "1", "2"}, {"tx"}, {"tx", "zz"}, {"bogus"}} {
		if err := session.cmdOutputs(args); err == nil {
			t.Errorf("outputs %v: expected an error", args)
		}
	}
}

func TestHelp_CoversDispatch(t *testing.T) {
	details := helpCommandDetails()
	cmds := []string{"help", "?", "version", "status", "balance", "bal", "b", "address", "addr", "a",
		"send", "sign", "verify", "history", "hist", "h", "outputs", "outs", "out", "peers", "banned",
		"export-peer", "mining", "load", "unload", "sync", "scan", "seed", "import", "viewkeys", "prove",
		"lock", "unlock", "audit", "explore", "exp", "mempool", "purge", "certify", "save-checkpoints",
		"load-checkpoints", "license", "about", "quit", "exit", "q"}
	for _, c := range cmds {
		topic := normalizeHelpTopic(c)
		if _, ok := details[topic]; !ok {
			t.Errorf("no help for %q", c)
		}
	}
	for _, e := range details {
		for _, l := range append(append(e.description, e.notes...), e.exampleOutput...) {
			if strings.ContainsAny(l, "\u2014\u2013") {
				t.Errorf("dash in help text: %q", l)
			}
		}
	}
}
