package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSHA256ForAsset_ExactMatch(t *testing.T) {
	sum := strings.Repeat("a", 64)
	content := sum + "  blocknet-core-amd64-darwin-v1.2.3.zip\n"

	got, ok := parseSHA256ForAsset(content, "blocknet-core-amd64-darwin-v1.2.3.zip")
	if !ok {
		t.Fatal("expected checksum match")
	}
	if got != sum {
		t.Fatalf("expected %s, got %s", sum, got)
	}
}

func TestParseSHA256ForAsset_AsteriskFormatAndPath(t *testing.T) {
	sum := strings.Repeat("b", 64)
	content := sum + " *./dist/blocknet-core-amd64-linux-v9.9.9.zip\n"

	got, ok := parseSHA256ForAsset(content, "blocknet-core-amd64-linux-v9.9.9.zip")
	if !ok {
		t.Fatal("expected checksum match")
	}
	if got != sum {
		t.Fatalf("expected %s, got %s", sum, got)
	}
}

func TestParseSHA256ForAsset_NoMatch(t *testing.T) {
	sum := strings.Repeat("c", 64)
	content := sum + "  other-file.zip\n"

	if _, ok := parseSHA256ForAsset(content, "blocknet-core-amd64-linux-v1.0.0.zip"); ok {
		t.Fatal("expected no match")
	}
}

func TestFileSHA256(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(p, []byte("abc"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	got, err := fileSHA256(p)
	if err != nil {
		t.Fatalf("fileSHA256 returned error: %v", err)
	}

	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}
