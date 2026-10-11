package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func serveCheckpoints(t *testing.T, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	old := checkpointsURL
	checkpointsURL = srv.URL
	t.Cleanup(func() { checkpointsURL = old })
}

func TestRefreshCheckpointsReplacesStaleFileAndKeepsBackup(t *testing.T) {
	a, b, c := strings.Repeat("A", 64), strings.Repeat("B", 64), strings.Repeat("C", 64)
	remote := "100:" + a + "\n200:" + b + "\n"
	serveCheckpoints(t, remote)

	dir := t.TempDir()
	path := CheckpointsPath(dir)
	stale := "100:" + a + "\n200:" + c + "\n"
	if err := os.WriteFile(path, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := RefreshCheckpoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Replaced || res.Entries != 2 || res.MaxHeight != 200 {
		t.Fatalf("unexpected result %+v", res)
	}
	if got, _ := os.ReadFile(path); string(got) != remote {
		t.Fatalf("file not replaced: %q", got)
	}
	if got, _ := os.ReadFile(res.Backup); string(got) != stale {
		t.Fatalf("backup does not hold the old file: %q", got)
	}
}

func TestRefreshCheckpointsKeepsLocalFileThatIsAheadOfRemote(t *testing.T) {
	a, b := strings.Repeat("A", 64), strings.Repeat("B", 64)
	serveCheckpoints(t, "100:"+a+"\n")

	dir := t.TempDir()
	local := "100:" + strings.ToLower(a) + "\n200:" + b + "\n"
	if err := os.WriteFile(CheckpointsPath(dir), []byte(local), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := RefreshCheckpoints(dir)
	if err != nil || res.Replaced {
		t.Fatalf("local file ahead of remote was replaced: %+v %v", res, err)
	}
	if got, _ := os.ReadFile(CheckpointsPath(dir)); string(got) != local {
		t.Fatalf("local file changed: %q", got)
	}
}

func TestRefreshCheckpointsRejectsRemoteWithoutEntries(t *testing.T) {
	serveCheckpoints(t, "<html>maintenance</html>")

	dir := t.TempDir()
	local := "100:" + strings.Repeat("A", 64) + "\n"
	if err := os.WriteFile(CheckpointsPath(dir), []byte(local), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := RefreshCheckpoints(dir); err == nil {
		t.Fatal("expected an error for a remote file without entries")
	}
	if got, _ := os.ReadFile(CheckpointsPath(dir)); string(got) != local {
		t.Fatalf("local file changed: %q", got)
	}
}
