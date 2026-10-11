package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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

	if _, ok := parseSHA256ForAsset(content, "blocknet-core-amd64-linux-v.zip"); ok {
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

func TestListReleasesFollowsPages(t *testing.T) {
	const total = 137
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		var items []string
		for i := (page - 1) * per; i < page*per && i < total; i++ {
			items = append(items, fmt.Sprintf(`{"tag_name":"v0.%d.0"}`, i))
		}
		fmt.Fprintf(w, "[%s]", strings.Join(items, ","))
	}))
	defer srv.Close()

	rels, err := listReleasesFrom(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != total {
		t.Fatalf("got %d releases, want %d", len(rels), total)
	}
	if rels[total-1].Tag != fmt.Sprintf("v0.%d.0", total-1) {
		t.Fatalf("last tag %s", rels[total-1].Tag)
	}
}
