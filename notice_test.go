package main

import (
	"strings"
	"testing"
)

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

func TestCoreNoticesShowUpdateOnlyWhenTheCoreSendsIt(t *testing.T) {
	with := captureStdout(t, func() {
		printCoreNotices([]byte(`{"update_notice":"please update"}`), true)
	})
	if !strings.Contains(with, "# Update") || !strings.Contains(with, "please update") {
		t.Fatalf("update notice missing:\n%s", with)
	}
	if !strings.Contains(with, "# Network upgrade") {
		t.Fatalf("network upgrade notice missing:\n%s", with)
	}
	for _, raw := range []string{`{}`, `{"update_notice":"  "}`, `not json`, ``} {
		out := captureStdout(t, func() { printCoreNotices([]byte(raw), true) })
		if strings.Contains(out, "# Update") {
			t.Fatalf("%q: unexpected update notice:\n%s", raw, out)
		}
	}
}
