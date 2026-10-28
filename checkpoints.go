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

// CheckpointsStatus is what CheckCheckpoints found without changing anything.
type CheckpointsStatus struct {
	Missing   bool // no local checkpoints.dat
	Stale     bool // local file is missing entries or hashes from bntpool
	Entries   int
	MaxHeight uint64
}

// CheckCheckpoints downloads bntpool's checkpoints and compares them with the
// local file. It never writes anything.
func CheckCheckpoints(dataDir string) (CheckpointsStatus, error) {
	st, _, _, err := compareCheckpoints(dataDir)
	return st, err
}

func compareCheckpoints(dataDir string) (st CheckpointsStatus, remoteData, localData []byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	remoteData, err = fetchCheckpoints(ctx)
	if err != nil {
		return st, nil, nil, err
	}
	remote := parseCheckpoints(remoteData)
	if len(remote) == 0 {
		return st, nil, nil, fmt.Errorf("remote checkpoints file has no valid entries")
	}
	st.Entries = len(remote)
	for h := range remote {
		st.MaxHeight = max(st.MaxHeight, h)
	}

	localData, err = os.ReadFile(CheckpointsPath(dataDir))
	if err != nil {
		if !os.IsNotExist(err) {
			return st, nil, nil, err
		}
		st.Missing = true
		err = nil
	}
	local := parseCheckpoints(localData)
	for h, hash := range remote {
		if local[h] != hash {
			st.Stale = true
			break
		}
	}
	return st, remoteData, localData, nil
}

func RefreshCheckpoints(dataDir string) (CheckpointsRefresh, error) {
	var res CheckpointsRefresh

	st, remoteData, localData, err := compareCheckpoints(dataDir)
	if err != nil {
		return res, err
	}
	res.Entries = st.Entries
	res.MaxHeight = st.MaxHeight
	if !st.Stale {
		return res, nil
	}

	path := CheckpointsPath(dataDir)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return res, err
	}
	if localData != nil {
		res.Backup = path + ".bak"
		if err := os.WriteFile(res.Backup, localData, 0o644); err != nil {
			return res, fmt.Errorf("could not back up checkpoints: %w", err)
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

func refreshCheckpointsBeforeStart(net Network, cc *CoreConfig) {
	if net != Mainnet || cc == nil || cc.FullSync {
		return
	}
	green, _, _, _, dim, reset := Palette(NoColor)
	res, err := RefreshCheckpoints(cc.ResolveDataDir(net))
	switch {
	case err != nil:
		Warnf("checkpoints refresh failed: %v", err)
	case res.Replaced && res.Backup != "":
		fmt.Printf("  %s✓%s Checkpoints updated %s(%d entries, max %d, old file saved as %s)%s\n", green, reset, dim, res.Entries, res.MaxHeight, res.Backup, reset)
	case res.Replaced:
		fmt.Printf("  %s✓%s Checkpoints downloaded %s(%d entries, max %d)%s\n", green, reset, dim, res.Entries, res.MaxHeight, reset)
	}
}
