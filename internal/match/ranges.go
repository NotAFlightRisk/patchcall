package match

import (
	"regexp"
	"strings"
)

// Interval is one stretch of affected versions, with Hi nil for no upper bound
type Interval struct {
	Lo     Version
	LoIncl bool
	Hi     *Version
	HiIncl bool
}

const num = `[vV]?\d+(?:\.\d+){0,5}(?:-[0-9A-Za-z.]+)?`

var (
	token     = regexp.MustCompile(`(<=|>=|<|>|==|=)?\s*(` + num + `)\b`)
	hyphen    = regexp.MustCompile(`^(` + num + `)\s*(?:-|–|to|through)\s*(` + num + `)\b`)
	trailing  = regexp.MustCompile(`^(` + num + `)\s*<$`)
	wildcard  = regexp.MustCompile(`^v?(\d+)\.(\d+)\.[x*]$`)
	separator = regexp.MustCompile(`[\s,;&|]|and|or`)
	anyNum    = regexp.MustCompile(`\b` + num + `\b`)
	symbols   = strings.NewReplacer("≤", "<=", "≥", ">=", "＜", "<", "＞", ">")
)

func bound(raw string) *Version {
	version, _ := Parse(raw)
	return &version
}

// Intervals reads a hand-written range like ">= 2.0, < 2.4.1" or "1.0 - 1.3",
// or returns nil when it's prose that can't be trusted
func Intervals(raw string) []Interval {
	text := symbols.Replace(strings.ToLower(strings.TrimSpace(raw)))
	switch {
	case text == "":
		return nil
	case text == "*" || text == "all" || text == "all versions":
		return []Interval{{LoIncl: true}}
	}
	if found := hyphen.FindStringSubmatch(text); found != nil {
		return []Interval{{Lo: *bound(found[1]), LoIncl: true, Hi: bound(found[2]), HiIncl: true}}
	}
	if found := trailing.FindStringSubmatch(text); found != nil {
		return []Interval{{LoIncl: true, Hi: bound(found[1])}}
	}
	if found := wildcard.FindStringSubmatch(text); found != nil {
		lo := *bound(found[1] + "." + found[2])
		lo[release] = 0
		hi := lo
		hi[1]++
		return []Interval{{Lo: lo, LoIncl: true, Hi: &hi}}
	}
	tokens := token.FindAllStringSubmatch(text, -1)
	if tokens == nil || separator.ReplaceAllString(token.ReplaceAllString(text, ""), "") != "" {
		return nil
	}
	var out []Interval
	var lo *Interval
	for _, tok := range tokens {
		op, version := tok[1], bound(tok[2])
		switch op {
		case ">=", ">":
			// back-to-back lower bounds are one per release line, each capped by its own fix
			if lo != nil {
				out = append(out, *lo)
			}
			lo = &Interval{Lo: *version, LoIncl: op == ">="}
		case "<", "<=":
			next := Interval{LoIncl: true, Hi: version, HiIncl: op == "<="}
			if lo != nil {
				next.Lo, next.LoIncl = lo.Lo, lo.LoIncl
			}
			out, lo = append(out, next), nil
		case "":
			// a bare version is usually "tested on", so everything up to it counts
			next := Interval{LoIncl: true, Hi: version, HiIncl: true}
			if lo != nil {
				next.Lo, next.LoIncl = lo.Lo, lo.LoIncl
			}
			out, lo = append(out, next), nil
		default:
			out, lo = append(out, Interval{Lo: *version, LoIncl: true, Hi: version, HiIncl: true}), nil
		}
	}
	if lo != nil {
		out = append(out, *lo)
	}
	return out
}

// Fix is a patched version, keeping how the advisory wrote it
type Fix struct {
	Version Version
	Raw     string
}

// Patched pulls every version out of a patched_versions field like ">= 2.4.1, 3.0.2"
func Patched(raw string) []Fix {
	var out []Fix
	for _, found := range anyNum.FindAllString(raw, -1) {
		version, _ := Parse(found)
		out = append(out, Fix{version, found})
	}
	return out
}

func (iv Interval) Contains(version Version) bool {
	above := iv.Lo.Less(version) || (iv.LoIncl && iv.Lo == version)
	below := iv.Hi == nil || version.Less(*iv.Hi) || (iv.HiIncl && version == *iv.Hi)
	return above && below
}

// Capped lets a patched version stand in for a missing or too-generous upper bound
func (iv Interval) Capped(fixes []Fix) Interval {
	for _, fix := range fixes {
		if !iv.Lo.Less(fix.Version) {
			continue
		}
		if iv.Hi == nil || !iv.Hi.Less(fix.Version) {
			capped := fix.Version
			iv.Hi, iv.HiIncl = &capped, false
		}
	}
	return iv
}
