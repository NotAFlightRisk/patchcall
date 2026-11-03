package match

import (
	"cmp"
	"slices"
	"strings"
	"time"
)

type Advisory struct {
	ID        string     `json:"id"`
	CVE       string     `json:"cve,omitempty"`
	URL       string     `json:"url"`
	Summary   string     `json:"summary"`
	Severity  string     `json:"severity"`
	Published time.Time  `json:"published"`
	Affected  []Affected `json:"affected"`
}

type Affected struct {
	Package string `json:"package,omitempty"`
	Range   string `json:"range"`
	Patched string `json:"patched,omitempty"`
}

// Hit is an advisory that reaches the running version, with the lowest fix above it
type Hit struct {
	Advisory
	Fix string `json:"fix,omitempty"`
	KEV bool   `json:"kev,omitempty"`
}

type Result struct {
	Hits       []Hit  `json:"hits,omitempty"`
	Unfixed    []Hit  `json:"unfixed,omitempty"`
	Unreadable []Hit  `json:"unreadable,omitempty"`
	MoveTo     string `json:"move_to,omitempty"`
}

// Scope narrows a repo's advisories to the ones about this app, by package name
type Scope struct {
	Only []string
	Skip []string
}

func (s Scope) covers(pkg string) bool {
	return (len(s.Only) == 0 || mentions(pkg, s.Only)) && !mentions(pkg, s.Skip)
}

// Check runs every advisory in scope past the running version
func Check(running Version, advisories []Advisory, scope Scope) Result {
	var result Result
	var best Version
	for _, advisory := range advisories {
		affected := slices.DeleteFunc(slices.Clone(advisory.Affected), func(a Affected) bool {
			return !scope.covers(a.Package)
		})
		var fixes []Fix
		for _, a := range affected {
			fixes = append(fixes, Patched(a.Patched)...)
		}
		if len(affected) == 0 {
			continue
		}
		reached, readable := reaching(running, affected)
		switch {
		case len(reached) > 0 && onFixedLine(running, fixes, reached):
		case len(reached) > 0:
			fix := firstClear(running, fixes, affected)
			if fix == nil {
				result.Unfixed = append(result.Unfixed, Hit{Advisory: advisory})
				continue
			}
			result.Hits = append(result.Hits, Hit{Advisory: advisory, Fix: fix.Raw})
			if best.Less(fix.Version) {
				best, result.MoveTo = fix.Version, fix.Raw
			}
		case !readable && !onFixedLine(running, fixes, nil):
			if fix := lowestAbove(running, fixes); fix != nil {
				result.Unreadable = append(result.Unreadable, Hit{Advisory: advisory, Fix: fix.Raw})
			}
		}
	}
	for _, hits := range [][]Hit{result.Hits, result.Unfixed, result.Unreadable} {
		slices.SortStableFunc(hits, worstFirst)
	}
	return result
}

// reach is one readable range that catches a version, with its own entry's fixes
type reach struct {
	interval Interval
	fixes    []Fix
}

// reaching lists the readable ranges that catch the version, and says if any couldn't be read
func reaching(version Version, affected []Affected) (reached []reach, readable bool) {
	readable = true
	for _, a := range affected {
		intervals := Intervals(a.Range)
		if intervals == nil {
			readable = false
		}
		fixes := Patched(a.Patched)
		for _, iv := range intervals {
			if capped := iv.Capped(fixes); capped.Contains(version) {
				reached = append(reached, reach{capped, fixes})
			}
		}
	}
	return reached, readable
}

// firstClear is the lowest fix above you that the advisory no longer catches
func firstClear(running Version, fixes []Fix, affected []Affected) *Fix {
	var above []Fix
	for _, fix := range fixes {
		if running.Less(fix.Version) {
			above = append(above, fix)
		}
	}
	slices.SortFunc(above, func(a, b Fix) int { return a.Version.Compare(b.Version) })
	for i, fix := range above {
		reached, _ := reaching(fix.Version, affected)
		if len(reached) == 0 || onFixedLine(fix.Version, fixes, reached) {
			return &above[i]
		}
	}
	if len(above) == 0 {
		return nil
	}
	return &above[len(above)-1]
}

// onFixedLine is true when your major line already got its fix at or below you and nothing
// newer is due on it, so a range still catching you is another line's. That only holds for
// ranges with a fix that don't start inside your line, as those are about your line itself
func onFixedLine(version Version, fixes []Fix, reached []reach) bool {
	fixedBelow := false
	for _, fix := range fixes {
		if fix.Version[0] != version[0] {
			continue
		}
		if version.Less(fix.Version) {
			return false
		}
		fixedBelow = true
	}
	for _, r := range reached {
		startsInLine := r.interval.Lo != (Version{}) && r.interval.Lo[0] >= version[0]
		if len(r.fixes) == 0 || startsInLine {
			return false
		}
	}
	return fixedBelow
}

func lowestAbove(running Version, fixes []Fix) *Fix {
	var lowest *Fix
	for i, fix := range fixes {
		if running.Less(fix.Version) && (lowest == nil || fix.Version.Less(lowest.Version)) {
			lowest = &fixes[i]
		}
	}
	return lowest
}

func mentions(pkg string, parts []string) bool {
	pkg = strings.ToLower(pkg)
	return slices.ContainsFunc(parts, func(part string) bool {
		return strings.Contains(pkg, strings.ToLower(part))
	})
}

// Rank orders severities so the worst sorts first
func Rank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium", "moderate":
		return 2
	case "low":
		return 1
	}
	return 0
}

func worstFirst(a, b Hit) int {
	return cmp.Or(Rank(b.Severity)-Rank(a.Severity), b.Published.Compare(a.Published))
}
