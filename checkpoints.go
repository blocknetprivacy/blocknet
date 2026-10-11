package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const maxCheckpointsBytes = 32 << 20

var checkpointsURL = "https://bntpool.com/checkpoints.dat"

type CheckpointsRefresh struct {
	Replaced  bool
	Backup    string
	Entries   int
	MaxHeight uint64
}

func CheckpointsPath(dataDir string) string {
	return filepath.Join(dataDir, "checkpoints.dat")
}

func parseCheckpoints(data []byte) map[uint64]string {
	out := make(map[uint64]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h, hash, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		height, err := strconv.ParseUint(strings.TrimSpace(h), 10, 64)
		if err != nil || height == 0 {
			continue
		}
		hash = strings.ToUpper(strings.TrimPrefix(strings.TrimSpace(hash), "0x"))
		if len(hash) != 64 || strings.Trim(hash, "0123456789ABCDEF") != "" {
			continue
		}
		out[height] = hash
	}
	return out
}

func fetchCheckpoints(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkpointsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checkpoints download returned %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxCheckpointsBytes))
}

func RefreshCheckpoints(dataDir string) (CheckpointsRefresh, error) {
	var res CheckpointsRefresh

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	remoteData, err := fetchCheckpoints(ctx)
	if err != nil {
		return res, err
	}
	remote := parseCheckpoints(remoteData)
	if len(remote) == 0 {
		return res, fmt.Errorf("remote checkpoints file has no valid entries")
	}
	res.Entries = len(remote)
	for h := range remote {
		res.MaxHeight = max(res.MaxHeight, h)
	}

	path := CheckpointsPath(dataDir)
	localData, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return res, err
	}
	local := parseCheckpoints(localData)

	stale := false
	for h, hash := range remote {
		if local[h] != hash {
			stale = true
			break
		}
	}
	if !stale {
		return res, nil
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return res, err
	}
	if localData != nil {
		res.Backup = path + ".bak"
		if err := os.WriteFile(res.Backup, localData, 0o644); err != nil {
			return res, fmt.Errorf("back up checkpoints: %w", err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, remoteData, 0o644); err != nil {
		os.Remove(tmp)
		return res, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return res, err
	}
	res.Replaced = true
	return res, nil
}
