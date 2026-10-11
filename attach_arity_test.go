package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestCommandArity_RejectsExtras walks the arity table: every fixed-arity
// command and alias must refuse one argument more than it takes, before any
// call reaches the core.
func TestCommandArity_RejectsExtras(t *testing.T) {
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("core called for %s", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}), "", "testwallet.wallet.dat")

	for cmd, a := range commandArity {
		args := make([]string, a.max+1)
		for i := range args {
			args[i] = "1"
		}
		err := session.executeCommand(cmd + " " + strings.Join(args, " "))
		if err == nil || !strings.HasPrefix(err.Error(), "too many arguments: ") {
			t.Errorf("%s with %d args: want too many arguments, got %v", cmd, len(args), err)
		}
		if a.usage == "" {
			t.Errorf("%s: empty usage", cmd)
		}
	}
}

// TestCommandArity_CoversDispatch keeps the table in step with the dispatch:
// every command is either in the table or knowingly takes free text.
func TestCommandArity_CoversDispatch(t *testing.T) {
	freeText := map[string]bool{"send": true, "sign": true, "verify": true}
	cmds := []string{"help", "?", "version", "status", "balance", "bal", "b", "address", "addr", "a",
		"send", "sign", "verify", "history", "hist", "h", "outputs", "outs", "out", "peers", "banned",
		"export-peer", "mining", "load", "unload", "sync", "scan", "seed", "import", "viewkeys", "prove",
		"lock", "unlock", "audit", "explore", "exp", "mempool", "purge", "certify", "save-checkpoints",
		"load-checkpoints", "license", "about", "quit", "exit", "q"}
	for _, c := range cmds {
		if _, ok := commandArity[c]; !ok && !freeText[c] {
			t.Errorf("%q is missing from commandArity", c)
		}
	}
}

func TestSend_BNTUnitIsNotMemo(t *testing.T) {
	var got map[string]any
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/wallet/send" {
			var req struct {
				Recipients []map[string]any `json:"recipients"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			if len(req.Recipients) > 0 {
				got = req.Recipients[0]
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"fee": 1})
	}), "n\n", "testwallet.wallet.dat")

	for _, unit := range []string{"BNT", "bnt", "Bnt"} {
		got = nil
		if err := session.cmdSend([]string{"9PNoaddr", "1", unit}); err != nil {
			t.Fatalf("send 1 %s: %v", unit, err)
		}
		if got == nil {
			t.Fatalf("send 1 %s: no request", unit)
		}
		if _, ok := got["memo_text"]; ok {
			t.Errorf("send 1 %s: unit sent as memo %v", unit, got["memo_text"])
		}
		if got["amount"] != float64(100_000_000) {
			t.Errorf("send 1 %s: amount %v", unit, got["amount"])
		}
	}

	got = nil
	if err := session.cmdSend([]string{"9PNoaddr", "1", "BNT", "thanks"}); err != nil {
		t.Fatal(err)
	}
	if got["memo_text"] != "thanks" {
		t.Errorf("memo after unit: got %v", got["memo_text"])
	}
}

func TestSendAll_BadPreviewJSON(t *testing.T) {
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/wallet/outputs":
			json.NewEncoder(w).Encode(map[string]any{"outputs": []map[string]any{
				{"txid": strings.Repeat("a", 64), "output_index": 0, "amount": 500, "status": "unspent"},
			}})
		case "/api/wallet/send/advanced":
			w.Write([]byte(`{"fee": "oops"}`))
		}
	}), "y\n", "testwallet.wallet.dat")

	if err := session.cmdSend([]string{"9PNoaddr", "all"}); err == nil {
		t.Fatal("expected an error for a bad fee preview")
	}
}

func TestEnsureUnlocked_KeepsLockOnError(t *testing.T) {
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "core busy"})
	}), "", "testwallet.wallet.dat")
	session.locked = true

	if err := session.ensureUnlocked(); err == nil {
		t.Fatal("expected the lock check error")
	}
	if !session.locked {
		t.Fatal("locked flag cleared without a confirmed unlocked answer")
	}
}

func TestBannerTitle_Fits(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	for _, v := range []string{"", "1.1.0", "v1.1.0", "v1.2.3-rc.1+build.20261011.abcdef"} {
		Version = v
		title := bannerTitle()
		if n := VisibleLen(title); n > bannerInner-2 {
			t.Errorf("version %q: title %q is %d wide", v, title, n)
		}
		if strings.Contains(title, "vv") {
			t.Errorf("version %q: double v in %q", v, title)
		}
	}
}

func TestCapitalize(t *testing.T) {
	for in, want := range map[string]string{
		"wallet is locked, use 'unlock' first": "Wallet is locked, use 'unlock' first",
		"":                                     "",
		"Already":                              "Already",
	} {
		if got := capitalize(in); got != want {
			t.Errorf("capitalize(%q) = %q, want %q", in, got, want)
		}
	}
}
