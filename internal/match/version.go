// Package match reads advisory version ranges and decides which ones catch a running version.
package match

import (
	"regexp"
	"strconv"
	"strings"
)

// Version is up to six numeric parts, padded with zeros so 1.2 == 1.2.0, then a last slot
// that's 1 for a release and 0 for a prerelease, so 2.4.1-rc1 sorts just below 2.4.1
type Version [7]int

const release = 6

var (
	leading    = regexp.MustCompile(`^[vV]?(\d+(?:\.\d+){0,5})`)
	tooLong    = regexp.MustCompile(`^\.\d`)
	prerelease = regexp.MustCompile(`(?i)^[-.~_]?(alpha|beta|rc|pre|preview|dev)[0-9.]*`)
)

// Parse reads the numeric front of a version, so -ls42 or a commit hash on the end is ignored.
// More than six numeric parts is refused rather than cut short
func Parse(raw string) (Version, bool) {
	var version Version
	raw = strings.TrimSpace(raw)
	found := leading.FindStringSubmatchIndex(raw)
	if found == nil || tooLong.MatchString(raw[found[1]:]) {
		return version, false
	}
	for i, part := range strings.Split(raw[found[2]:found[3]], ".") {
		version[i], _ = strconv.Atoi(part)
	}
	if !prerelease.MatchString(raw[found[1]:]) {
		version[release] = 1
	}
	return version, true
}

// Parts counts how many dotted numbers a version string starts with
func Parts(raw string) int {
	found := leading.FindStringSubmatch(strings.TrimSpace(raw))
	if found == nil {
		return 0
	}
	return strings.Count(found[1], ".") + 1
}

// Clean trims a version string down to what Parse reads, keeping a v prefix and any -rc1
func Clean(raw string) string {
	raw = strings.TrimSpace(raw)
	front := leading.FindString(raw)
	if front == "" {
		return ""
	}
	return front + prerelease.FindString(raw[len(front):])
}

func (v Version) Compare(other Version) int {
	for i := range v {
		if v[i] != other[i] {
			if v[i] < other[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func (v Version) Less(other Version) bool { return v.Compare(other) < 0 }
