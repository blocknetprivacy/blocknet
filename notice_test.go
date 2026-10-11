package main

import "testing"

func TestUpgradeNoticeComesFromCoreWithBuiltinFallback(t *testing.T) {
	if got := upgradeNoticeFrom([]byte(`{"network_upgrade":{"notice":"from the core"}}`)); got != "from the core" {
		t.Fatalf("got %q, want the core's notice", got)
	}
	for _, raw := range []string{`{}`, `{"network_upgrade":{"notice":"  "}}`, `not json`} {
		if got := upgradeNoticeFrom([]byte(raw)); got != builtinUpgradeNotice {
			t.Fatalf("%s: got %q, want the built-in notice", raw, got)
		}
	}
}
