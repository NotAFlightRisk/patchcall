package match

import (
	"testing"
)

func version(t *testing.T, raw string) Version {
	t.Helper()
	parsed, ok := Parse(raw)
	if !ok {
		t.Fatalf("couldn't parse %q", raw)
	}
	return parsed
}

func advisory(id, severity string, affected ...Affected) Advisory {
	return Advisory{ID: id, Severity: severity, Affected: affected}
}

func TestIntervalsReadsTheWaysPeopleWriteRanges(t *testing.T) {
	cases := []struct {
		raw     string
		inside  []string
		outside []string
	}{
		{">= 2.0.0, < 2.4.1", []string{"2.0.0", "2.4.0"}, []string{"1.9.9", "2.4.1"}},
		{">= 2.0.0 && <= 2.1.3 ", []string{"2.1.3"}, []string{"2.1.4"}},
		{"v6.0 - v6.4.2", []string{"6.0", "6.4.2"}, []string{"5.9", "6.4.3"}},
		{"<= 12.0-RC5", []string{"11.0"}, []string{"12.1"}},
		{"2025.1.4<", []string{"2025.1.3"}, []string{"2025.1.4"}},
		{"2.6.x", []string{"2.6.0", "2.6.9"}, []string{"2.5.9", "2.7.0"}},
		{"< 1.2.3 || >= 2.0, < 2.1", []string{"1.0", "2.0.5"}, []string{"1.5", "2.1"}},
		{"1.35.4", []string{"1.34.3", "1.35.4"}, []string{"1.35.5"}},
		{"= 1.35.4", []string{"1.35.4"}, []string{"1.34.3"}},
		{"≤ 3.1", []string{"3.1"}, []string{"3.2"}},
	}
	for _, tc := range cases {
		intervals := Intervals(tc.raw)
		if intervals == nil {
			t.Errorf("%q: didn't parse", tc.raw)
			continue
		}
		contains := func(raw string) bool {
			for _, iv := range intervals {
				if iv.Contains(version(t, raw)) {
					return true
				}
			}
			return false
		}
		for _, raw := range tc.inside {
			if !contains(raw) {
				t.Errorf("%q should contain %s", tc.raw, raw)
			}
		}
		for _, raw := range tc.outside {
			if contains(raw) {
				t.Errorf("%q shouldn't contain %s", tc.raw, raw)
			}
		}
	}
}

func TestIntervalsRefusesProse(t *testing.T) {
	for _, raw := range []string{"<= v2.7.5 (current release)", "> main@4ffa26c9", "<=latest", ""} {
		if got := Intervals(raw); got != nil {
			t.Errorf("%q parsed as %v, wanted nothing", raw, got)
		}
	}
}

func TestPatchedIgnoresCommitHashes(t *testing.T) {
	if got := Patched("> main@4eb1003"); got != nil {
		t.Errorf("got %v from a commit hash", got)
	}
	got := Patched(">= 2.43.3, v3.0.1")
	if len(got) != 2 || got[1].Raw != "v3.0.1" {
		t.Errorf("got %v", got)
	}
}

func TestCheckFlagsAnAffectedVersionWithTheFixToMoveTo(t *testing.T) {
	result := Check(version(t, "2.5.6"), []Advisory{
		advisory("GHSA-low", "low", Affected{Range: ">= 2.1.0, <= 2.5.8", Patched: "2.5.9"}),
		advisory("GHSA-crit", "critical", Affected{Range: "<=2.5.6", Patched: "2.5.7"}),
		advisory("GHSA-old", "high", Affected{Range: "< 2.5.0", Patched: "2.5.0"}),
	}, Scope{})
	if len(result.Hits) != 2 || result.Hits[0].ID != "GHSA-crit" {
		t.Fatalf("hits = %+v", result.Hits)
	}
	if result.MoveTo != "2.5.9" {
		t.Errorf("move to %q, want 2.5.9", result.MoveTo)
	}
}

func TestCheckCapsAnOpenRangeWithThePatchedVersion(t *testing.T) {
	result := Check(version(t, "2.3.0"), []Advisory{
		advisory("GHSA-open", "high", Affected{Range: ">= 1.23.0", Patched: "2.2.1"}),
	}, Scope{})
	if len(result.Hits) != 0 {
		t.Errorf("2.3.0 is past the fix, got %+v", result.Hits)
	}
}

func TestCheckTrustsAFixAlreadyInYourMajorLine(t *testing.T) {
	result := Check(version(t, "2.46.4"), []Advisory{
		advisory("GHSA-n8n", "high",
			Affected{Range: "< 2.43.3", Patched: "2.43.3"},
			Affected{Range: "< 3.0.1", Patched: "3.0.1"}),
	}, Scope{})
	if len(result.Hits)+len(result.Unfixed) != 0 {
		t.Errorf("2.46.4 already has the 2.x fix, got %+v", result)
	}
}

func TestCheckStillFlagsAnOlderMajorLine(t *testing.T) {
	result := Check(version(t, "2.40.0"), []Advisory{
		advisory("GHSA-n8n", "high",
			Affected{Range: "< 2.43.3", Patched: "2.43.3"},
			Affected{Range: "< 3.0.1", Patched: "3.0.1"}),
	}, Scope{})
	if len(result.Hits) != 1 || result.Hits[0].Fix != "2.43.3" {
		t.Errorf("want one hit fixed by 2.43.3, got %+v", result.Hits)
	}
}

func TestCheckKeepsUnfixedAndUnreadableOutOfHits(t *testing.T) {
	result := Check(version(t, "2.7.0"), []Advisory{
		advisory("GHSA-nofix", "high", Affected{Range: "<= 2.7.0"}),
		advisory("GHSA-prose", "high", Affected{Range: "<= v2.7.5 (current release)", Patched: "v3.0.0"}),
		advisory("GHSA-prose-fixed", "high", Affected{Range: "anything before May", Patched: "2.6.0"}),
	}, Scope{})
	if len(result.Hits) != 0 {
		t.Errorf("no hits expected, got %+v", result.Hits)
	}
	if len(result.Unfixed) != 1 || result.Unfixed[0].ID != "GHSA-nofix" {
		t.Errorf("unfixed = %+v", result.Unfixed)
	}
	if len(result.Unreadable) != 1 || result.Unreadable[0].Fix != "v3.0.0" {
		t.Errorf("unreadable = %+v", result.Unreadable)
	}
}

func TestCheckSkipsSiblingComponents(t *testing.T) {
	result := Check(version(t, "2025.10.4"), []Advisory{
		advisory("GHSA-supervisor", "high",
			Affected{Package: "Home Assistant Supervisor", Range: "< 2026.1", Patched: "2026.1"}),
		advisory("GHSA-core", "high",
			Affected{Package: "Home Assistant Core", Range: "< 2026.2", Patched: "2026.2"}),
	}, Scope{Skip: []string{"supervisor"}})
	if len(result.Hits) != 1 || result.Hits[0].ID != "GHSA-core" {
		t.Errorf("want only the core advisory, got %+v", result.Hits)
	}
}

func TestCheckKeepsOnlyTheScopedPackage(t *testing.T) {
	result := Check(version(t, "33.0.2"), []Advisory{
		advisory("GHSA-deck", "high", Affected{Package: "Deck", Range: "< 40.0", Patched: "40.0"}),
		advisory("GHSA-server", "high", Affected{Package: "Server",
			Range: ">= 32.0.0, >= 33.0.0, >= 34.0.0", Patched: "32.0.12, 33.0.6, 34.0.1"}),
	}, Scope{Only: []string{"server"}})
	if len(result.Hits) != 1 || result.Hits[0].ID != "GHSA-server" {
		t.Fatalf("want only the server advisory, got %+v", result.Hits)
	}
	if result.MoveTo != "33.0.6" {
		t.Errorf("move to %q, want the fix on your own line, 33.0.6", result.MoveTo)
	}
}

func TestCheckReadsOneLowerBoundPerReleaseLine(t *testing.T) {
	advisories := []Advisory{advisory("GHSA-lines", "high", Affected{
		Range: ">= 32.0.0, >= 33.0.0", Patched: "32.0.12, 33.0.6"})}
	for _, fixed := range []string{"32.0.12", "33.0.6", "33.1.0"} {
		if hits := Check(version(t, fixed), advisories, Scope{}).Hits; len(hits) != 0 {
			t.Errorf("%s is fixed, got %+v", fixed, hits)
		}
	}
	if hits := Check(version(t, "32.0.3"), advisories, Scope{}).Hits; len(hits) != 1 {
		t.Errorf("32.0.3 is affected, got %+v", hits)
	}
}
