package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type sentRequest struct {
	path   string
	dryRun bool
	extra  float64
	hasFee bool
}

func feeTestSession(t *testing.T, input string) (*AttachSession, *[]sentRequest) {
	t.Helper()
	return feeTestSessionWithMempool(t, input, map[string]any{"count": 3, "base_fee_per_byte": 10, "min_tx_fee": 1000})
}

func setTestCoreVersion(t *testing.T, version string) {
	t.Helper()
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Cores[Mainnet].Version = version
	if err := SaveConfig(ConfigFile(), cfg); err != nil {
		t.Fatal(err)
	}
}

func feeTestSessionWithMempool(t *testing.T, input string, mempool map[string]any) (*AttachSession, *[]sentRequest) {
	t.Helper()
	var reqs []sentRequest
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/mempool":
			json.NewEncoder(w).Encode(mempool)
			return
		case "/api/wallet/outputs":
			json.NewEncoder(w).Encode(map[string]any{"outputs": []map[string]any{
				{"txid": strings.Repeat("a", 64), "output_index": 0, "amount": 500_000_000, "status": "unspent"},
			}})
			return
		case "/api/wallet/send", "/api/wallet/send/advanced":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			extra, has := body["extra_fee_per_byte"].(float64)
			dry, _ := body["dry_run"].(bool)
			reqs = append(reqs, sentRequest{path: r.URL.Path, dryRun: dry, extra: extra, hasFee: has})
			json.NewEncoder(w).Encode(map[string]any{"fee": 50_000, "txid": strings.Repeat("b", 64)})
			return
		}
		t.Errorf("unexpected core call %s", r.URL.Path)
	}), input, "testwallet.wallet.dat")
	setTestCoreVersion(t, "nightly")
	return session, &reqs
}

func TestSendFeePriority(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		extra  float64
		broadc bool
	}{
		{"enter uses normal", "\ny\n", 0, true},
		{"fast with y", "fast\ny\n", 10, true},
		{"prefix f is fast", "f\ny\n", 10, true},
		{"urgent with y cancels", "urgent\ny\n", 40, false},
		{"urgent with yes sends", "urgent\nyes\n", 40, true},
		{"custom with yes sends", "custom\n100\nyes\n", 100, true},
		{"custom with y cancels", "custom\n100\ny\n", 100, false},
		{"normal with n cancels", "normal\nn\n", 0, false},
		{"typo asks again", "fats\nfast\ny\n", 10, true},
		{"bad custom number asks again", "custom\n1.5\nabc\n25\nyes\n", 25, true},
		{"crazy custom with one yes cancels", "custom\n5000\nyes\n", 5000, false},
		{"crazy custom with two yes sends", "custom\n5000\nyes\nyes\n", 5000, true},
		{"just below crazy needs one yes", "custom\n989\nyes\n", 989, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session, reqs := feeTestSession(t, tc.input)
			if err := session.cmdSend([]string{"9PNoaddr", "1"}); err != nil {
				t.Fatal(err)
			}
			want := 1
			if tc.broadc {
				want = 2
			}
			if len(*reqs) != want {
				t.Fatalf("core got %d send calls, want %d", len(*reqs), want)
			}
			for i, r := range *reqs {
				if !r.hasFee || r.extra != tc.extra {
					t.Errorf("call %d: extra_fee_per_byte %v (present %v), want %v", i, r.extra, r.hasFee, tc.extra)
				}
				if r.dryRun != (i == 0) {
					t.Errorf("call %d: dry_run %v", i, r.dryRun)
				}
			}
		})
	}
}

func TestSendFeePriorityRejectsBadInput(t *testing.T) {
	for _, input := range []string{"turbo", "turbo\nturbo", "custom\n-5", "custom\nabc"} {
		session, reqs := feeTestSession(t, input)
		if err := session.cmdSend([]string{"9PNoaddr", "1"}); err == nil {
			t.Errorf("input %q: want an error", input)
		}
		if len(*reqs) != 0 {
			t.Errorf("input %q: core got %d send calls before the priority was valid", input, len(*reqs))
		}
	}
}

func TestSendAllFeePriority(t *testing.T) {
	session, reqs := feeTestSession(t, "urgent\nyes\n")
	if err := session.cmdSend([]string{"9PNoaddr", "all"}); err != nil {
		t.Fatal(err)
	}
	if len(*reqs) != 2 {
		t.Fatalf("core got %d send calls, want 2", len(*reqs))
	}
	for i, r := range *reqs {
		if r.path != "/api/wallet/send/advanced" || r.extra != 40 {
			t.Errorf("call %d: %s with extra %v, want advanced with 40", i, r.path, r.extra)
		}
	}
}

func TestPriorityDefaultIsSavedAndUsed(t *testing.T) {
	session, reqs := feeTestSession(t, "")
	if err := session.executeCommand("priority fast"); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FeePriority != "fast" || cfg.FeeExtraPerByte != 0 {
		t.Fatalf("saved %q extra %d, want fast 0", cfg.FeePriority, cfg.FeeExtraPerByte)
	}

	session.reader = bufio.NewReader(strings.NewReader("\ny\n"))
	if err := session.cmdSend([]string{"9PNoaddr", "1"}); err != nil {
		t.Fatal(err)
	}
	if len(*reqs) != 2 || (*reqs)[0].extra != 10 {
		t.Fatalf("send after 'priority fast' used %+v, want extra 10", *reqs)
	}

	if err := session.executeCommand("priority custom 250"); err != nil {
		t.Fatal(err)
	}
	if c := defaultFeeChoice(); c.name != "custom" || c.extra != 250 {
		t.Fatalf("default after 'priority custom 250' is %+v", c)
	}
	for _, bad := range []string{"priority turbo", "priority custom", "priority custom -1", "priority fast 5"} {
		if err := session.executeCommand(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
	if c := defaultFeeChoice(); c.name != "custom" || c.extra != 250 {
		t.Fatalf("a rejected command changed the default to %+v", c)
	}
}

func TestSendWithOldCoreUsesNormalFeeWithoutPrompt(t *testing.T) {
	session, reqs := feeTestSessionWithMempool(t, "y\n", map[string]any{"count": 3})
	if err := session.executeCommand("priority urgent"); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := session.cmdSend([]string{"9PNoaddr", "1"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "does not support fee priority") || strings.Contains(out, "Priority [") {
		t.Fatalf("old core output:\n%s", out)
	}
	if len(*reqs) != 2 || (*reqs)[0].extra != 0 || (*reqs)[1].extra != 0 {
		t.Fatalf("old core got %+v, want two calls with extra 0", *reqs)
	}
}

func TestFeeMultipleUsesCoreBase(t *testing.T) {
	for _, tc := range []struct {
		base, extra uint64
		want        string
	}{{10, 10, "2x"}, {10, 40, "5x"}, {10, 5, "1.5x"}, {7, 3, "1.4x"}, {20, 10, "1.5x"}} {
		if got := (feeChoice{extra: tc.extra, base: tc.base}).multiple(); got != tc.want {
			t.Errorf("base %d extra %d: %s, want %s", tc.base, tc.extra, got, tc.want)
		}
	}
}

func TestFeePriorityNeedsCoreV024OrNightly(t *testing.T) {
	session, _ := feeTestSession(t, "")
	for _, tc := range []struct {
		version string
		want    bool
	}{{"nightly", true}, {"v0.24.0", true}, {"v0.24.1", true}, {"v1.0.0", true}, {"v0.23.0", false}, {"v0.23.9", false}, {"latest", false}, {"", false}} {
		setTestCoreVersion(t, tc.version)
		if got := coreSupportsFeePriority(Mainnet); got != tc.want {
			t.Errorf("%q: supported %v, want %v", tc.version, got, tc.want)
		}
		_, ok := session.baseFeePerByte(context.Background())
		if ok != tc.want {
			t.Errorf("%q: base fee lookup %v, want %v", tc.version, ok, tc.want)
		}
	}
}

func TestSendOnOldCoreVersionSkipsPrompt(t *testing.T) {
	session, reqs := feeTestSession(t, "y\n")
	setTestCoreVersion(t, "v0.23.0")
	out := captureStdout(t, func() {
		if err := session.cmdSend([]string{"9PNoaddr", "1"}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "Priority [") || len(*reqs) != 2 || (*reqs)[0].extra != 0 {
		t.Fatalf("v0.23.0 core: prompted or sent extra: %+v\n%s", *reqs, out)
	}
}

func TestCrazyFeeIsRelativeToCoreBase(t *testing.T) {
	for _, tc := range []struct {
		name        string
		base, extra uint64
		want        bool
	}{{"custom", 10, 989, false}, {"custom", 10, 990, true}, {"custom", 20, 990, false}, {"custom", 20, 1980, true}, {"urgent", 10, 5000, false}, {"custom", 0, 5000, false}} {
		if got := (feeChoice{name: tc.name, extra: tc.extra, base: tc.base}).crazy(); got != tc.want {
			t.Errorf("%s base %d extra %d: crazy %v, want %v", tc.name, tc.base, tc.extra, got, tc.want)
		}
	}
}

type bumpCall struct {
	txid   string
	extra  float64
	dryRun bool
}

func bumpTestSession(t *testing.T, input string, preview map[string]any) (*AttachSession, *[]bumpCall) {
	t.Helper()
	var calls []bumpCall
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/mempool":
			json.NewEncoder(w).Encode(map[string]any{"count": 3, "base_fee_per_byte": 10, "min_tx_fee": 1000})
		case "/api/wallet/send/bump":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			calls = append(calls, bumpCall{txid: body["txid"].(string), extra: body["extra_fee_per_byte"].(float64), dryRun: body["dry_run"].(bool)})
			if body["dry_run"].(bool) {
				json.NewEncoder(w).Encode(preview)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"txid": strings.Repeat("c", 64)})
		default:
			t.Errorf("unexpected core call %s", r.URL.Path)
		}
	}), input, "testwallet.wallet.dat")
	setTestCoreVersion(t, "nightly")
	return session, &calls
}

func TestBumpCommand(t *testing.T) {
	txid := strings.Repeat("ab", 32)
	normal := map[string]any{"fee": 97860, "fee_per_byte": 20, "old_fee": 48930, "bump_cost": 48930}
	cases := []struct {
		name    string
		input   string
		preview map[string]any
		extra   float64
		sent    bool
		show    []string
	}{
		{"fast with y", "fast\ny\n", normal, 10, true, []string{"Old fee:", "New fee:", "(20 per byte)", "Costs:", "Sped up:"}},
		{"fast with n cancels", "fast\nn\n", normal, 10, false, []string{"Cancelled"}},
		{"urgent needs yes", "urgent\ny\n", map[string]any{"fee": 244650, "fee_per_byte": 50, "old_fee": 48930, "bump_cost": 195720}, 40, false, []string{"Type yes"}},
		{"urgent with yes", "urgent\nyes\n", map[string]any{"fee": 244650, "fee_per_byte": 50, "old_fee": 48930, "bump_cost": 195720}, 40, true, []string{"Sped up:"}},
		{"normal raised to the minimum", "\ny\n", normal, 0, true, []string{"(20 per byte)", "raised to 20 per byte"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session, calls := bumpTestSession(t, tc.input, tc.preview)
			out := captureStdout(t, func() {
				if err := session.executeCommand("bump " + txid); err != nil {
					t.Fatal(err)
				}
			})
			want := 1
			if tc.sent {
				want = 2
			}
			if len(*calls) != want {
				t.Fatalf("core got %d bump calls, want %d\n%s", len(*calls), want, out)
			}
			for i, c := range *calls {
				if c.txid != txid || c.extra != tc.extra || c.dryRun != (i == 0) {
					t.Errorf("call %d: %+v", i, c)
				}
			}
			for _, s := range tc.show {
				if !strings.Contains(out, s) {
					t.Errorf("output lacks %q:\n%s", s, out)
				}
			}
		})
	}
}

func TestBumpCommandRefusesBadInputAndOldCores(t *testing.T) {
	session, calls := bumpTestSession(t, "", nil)
	for _, cmd := range []string{"bump", "bump xyz", "bump " + strings.Repeat("a", 63)} {
		if err := session.executeCommand(cmd); err == nil {
			t.Errorf("%q: want an error", cmd)
		}
	}
	setTestCoreVersion(t, "v0.23.0")
	err := session.executeCommand("bump " + strings.Repeat("ab", 32))
	if err == nil || !strings.Contains(err.Error(), "Update it") {
		t.Fatalf("old core: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("core got %d bump calls", len(*calls))
	}
}

func TestHistoryMarksSpedUpSends(t *testing.T) {
	session := testSessionWithWallet(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/wallet/history":
			json.NewEncoder(w).Encode(map[string]any{"outputs": []any{}})
		case "/api/wallet/sends":
			json.NewEncoder(w).Encode(map[string]any{"sends": []map[string]any{
				{"txid": strings.Repeat("a", 64), "recorded_height": 10, "in_mempool": true, "total_amount": 5, "bumps": 1},
				{"txid": strings.Repeat("b", 64), "recorded_height": 9, "total_amount": 5},
			}})
		}
	}), "", "testwallet.wallet.dat")
	out := captureStdout(t, func() {
		if err := session.cmdHistory(); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Count(out, "(sped up)") != 1 || !strings.Contains(out, strings.Repeat("a", 64)+"  (sped up)") {
		t.Fatalf("history:\n%s", out)
	}
}
