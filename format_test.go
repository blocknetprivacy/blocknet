package main

import "testing"

func TestParseAmount(t *testing.T) {
	ok := map[string]uint64{
		"1":          100_000_000,
		"1.5":        150_000_000,
		"1.5 BNT":    150_000_000,
		"2bnt":       200_000_000,
		".5":         50_000_000,
		"5.":         500_000_000,
		"0.00000001": 1,
		"1.12345678": 112_345_678,
		" 3 Bnt ":    300_000_000,
	}
	for in, want := range ok {
		got, err := ParseAmount(in)
		if err != nil || got != want {
			t.Errorf("ParseAmount(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "0.0", ".", "-1", "+1", "1,000", "1e5", "1.123456789", "abc", "1.2.3", "BNT", "99999999999999999999"} {
		if got, err := ParseAmount(in); err == nil {
			t.Errorf("ParseAmount(%q) = %d; want error", in, got)
		}
	}
}

func TestPadIgnoresColor(t *testing.T) {
	s := ansiGreen + "ok" + ansiReset
	if got := VisibleLen(PadRight(s, 6)); got != 6 {
		t.Errorf("PadRight visible width = %d, want 6", got)
	}
	if got := PadLeft("ab", 4); got != "  ab" {
		t.Errorf("PadLeft = %q", got)
	}
}

func TestPlural(t *testing.T) {
	if Plural(1, "issue") != "1 issue" || Plural(3, "issue") != "3 issues" || Plural(2, "entry", "entries") != "2 entries" {
		t.Error("Plural wrong")
	}
}

func TestFormatDurationNegative(t *testing.T) {
	if got := FormatDuration(-5e9); got != "0s" {
		t.Errorf("FormatDuration(-5s) = %q, want 0s", got)
	}
	if got := FormatDuration(5e9); got != "5s" {
		t.Errorf("FormatDuration(5s) = %q, want 5s", got)
	}
	if got := FormatDuration(125e9); got != "2m" {
		t.Errorf("FormatDuration(125s) = %q, want 2m", got)
	}
}
