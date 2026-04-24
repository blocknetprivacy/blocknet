package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	releasesURL = "https://api.github.com/repos/blocknetprivacy/core/releases"
	userAgent   = "blocknet"
)

type Release struct {
	Tag        string
	Date       time.Time
	Assets     []Asset
	Prerelease bool
}

type Asset struct {
	Name string
	URL  string
}

// ListReleases fetches all releases from the core repository.
func ListReleases(ctx context.Context) ([]Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var raw []struct {
		TagName     string `json:"tag_name"`
		PublishedAt string `json:"published_at"`
		Prerelease  bool   `json:"prerelease"`
		Assets      []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse releases: %w", err)
	}

	releases := make([]Release, 0, len(raw))
	for _, r := range raw {
		t, _ := time.Parse(time.RFC3339, r.PublishedAt)
		rel := Release{
			Tag:        r.TagName,
			Date:       t,
			Prerelease: r.Prerelease,
		}
		for _, a := range r.Assets {
			rel.Assets = append(rel.Assets, Asset{
				Name: a.Name,
				URL:  a.BrowserDownloadURL,
			})
		}
		releases = append(releases, rel)
	}
	return releases, nil
}

// LatestRelease returns the newest non-prerelease version.
func LatestRelease(ctx context.Context) (*Release, error) {
	releases, err := ListReleases(ctx)
	if err != nil {
		return nil, err
	}
	for i := range releases {
		if !releases[i].Prerelease {
			return &releases[i], nil
		}
	}
	return nil, fmt.Errorf("no releases found")
}

// FindAsset picks the asset matching the current platform from a release.
// Assets follow the naming convention: blocknet-core-<arch>-<os>-<ver>.zip
func FindAsset(assets []Asset) *Asset {
	prefix := CoreAssetPrefix()
	for i, a := range assets {
		if strings.HasPrefix(a.Name, prefix) {
			return &assets[i]
		}
	}
	return nil
}

func FindChecksumAsset(assets []Asset) *Asset {
	for i, a := range assets {
		name := strings.ToLower(a.Name)
		if strings.Contains(name, "sha256") && strings.Contains(name, "sum") {
			return &assets[i]
		}
	}
	return nil
}

func ResolveAssetSHA256(ctx context.Context, assets []Asset, assetName string) (string, error) {
	checksums := FindChecksumAsset(assets)
	if checksums == nil {
		return "", fmt.Errorf("release is missing a checksum asset")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksums.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksum download returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	sum, ok := parseSHA256ForAsset(string(body), assetName)
	if !ok {
		return "", fmt.Errorf("checksum not found for %s", assetName)
	}
	return sum, nil
}

var sha256LineRE = regexp.MustCompile(`(?i)^([a-f0-9]{64})\s+\*?(.+)$`)

func parseSHA256ForAsset(content, assetName string) (string, bool) {
	target := strings.ToLower(strings.TrimSpace(assetName))
	if target == "" {
		return "", false
	}

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := sha256LineRE.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		sum := strings.ToLower(m[1])
		file := strings.ToLower(filepath.Base(strings.TrimSpace(m[2])))
		if file == target {
			return sum, true
		}
	}
	return "", false
}

type progressReader struct {
	reader     io.Reader
	total      int64
	downloaded int64
	onProgress func(downloaded, total int64)
	lastUpdate time.Time
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.downloaded += int64(n)
	now := time.Now()
	if pr.onProgress != nil && (now.Sub(pr.lastUpdate) >= 100*time.Millisecond || err == io.EOF) {
		pr.onProgress(pr.downloaded, pr.total)
		pr.lastUpdate = now
	}
	return n, err
}

// DownloadAsset downloads a URL to destPath. If the URL points to a .zip,
// the binary is extracted from the archive. Partial downloads never leave a
// broken file on disk. onProgress, if non-nil, is called periodically with
// byte counts.
func DownloadAsset(ctx context.Context, dlURL, destPath, expectedSHA256 string, onProgress func(downloaded, total int64)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	var body io.Reader = resp.Body
	if onProgress != nil {
		body = &progressReader{
			reader:     resp.Body,
			total:      resp.ContentLength,
			onProgress: onProgress,
		}
	}

	if _, err := io.Copy(tmp, body); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	sum, err := fileSHA256(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return err
	}
	if !strings.EqualFold(sum, strings.TrimSpace(expectedSHA256)) {
		os.Remove(tmpPath)
		return fmt.Errorf("checksum verification failed for download")
	}

	if strings.HasSuffix(dlURL, ".zip") {
		err := extractBinaryFromZip(tmpPath, destPath)
		os.Remove(tmpPath)
		return err
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, destPath)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extractBinaryFromZip(zipPath, destPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	prefix := "blocknet-core"
	for _, f := range r.File {
		name := filepath.Base(f.Name)
		if f.FileInfo().IsDir() || !strings.HasPrefix(name, prefix) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("extract %s: %w", name, err)
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			rc.Close()
			return err
		}

		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			rc.Close()
			return err
		}

		_, copyErr := io.Copy(out, rc)
		rc.Close()
		out.Close()
		if copyErr != nil {
			os.Remove(destPath)
			return fmt.Errorf("extract %s: %w", name, copyErr)
		}
		return nil
	}
	return fmt.Errorf("no binary matching %q found in zip", prefix)
}
