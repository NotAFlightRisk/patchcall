// Package match reads advisory version ranges and decides which ones catch a running version.
package match

import (
	"regexp"
	"strconv"
	"strings"
)

// Version is up to four numeric parts, padded with zeros, so 1.2 == 1.2.0.0
type Version [4]int

var leading = regexp.MustCompile(`^[vV]?(\d+(?:\.\d+){0,3})`)

// Parse reads the numeric front of a version, ignoring any suffix like -rc1 or -ls42
func Parse(raw string) (Version, bool) {
	var version Version
	found := leading.FindStringSubmatch(strings.TrimSpace(raw))
	if found == nil {
		return version, false
	}
	for i, part := range strings.Split(found[1], ".") {
		version[i], _ = strconv.Atoi(part)
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

// Clean trims a version string down to what was parsed, keeping a v prefix if it had one
func Clean(raw string) string {
	return leading.FindString(strings.TrimSpace(raw))
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
