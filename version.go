package main

import (
	"strconv"
	"strings"
)

// ParseVersion extracts major.minor.patch from a version string like
// "v0.7.0", "0.7.0-rc1", or "v1.2.3+build". Returns false if the
// string cannot be parsed.
func ParseVersion(v string) ([3]int, bool) {
	var parts [3]int
	core := strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if i := strings.IndexByte(core, '-'); i >= 0 {
		core = core[:i]
	}
	if i := strings.IndexByte(core, '+'); i >= 0 {
		core = core[:i]
	}
	segs := strings.SplitN(core, ".", 3)
	if len(segs) < 1 {
		return parts, false
	}
	for i, s := range segs {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return parts, false
		}
		parts[i] = n
	}
	return parts, true
}

// CompareVersions returns -1 if a < b, 0 if a == b, 1 if a > b.
// Returns 0 if either version is unparseable.
func CompareVersions(a, b string) int {
	pa, okA := ParseVersion(a)
	pb, okB := ParseVersion(b)
	if !okA || !okB {
		return 0
	}
	for i := range pa {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	return 0
}

// IsPinned returns true if the version string is a specific tag (e.g.
// "v0.7.0") rather than a tracking label like "latest" or "nightly".
func IsPinned(version string) bool {
	switch strings.ToLower(strings.TrimSpace(version)) {
	case "latest", "nightly", "":
		return false
	default:
		return true
	}
}
