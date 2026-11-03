package check

import (
	"cmp"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/NotAFlightRisk/patchcall/internal/match"
	"github.com/NotAFlightRisk/patchcall/internal/notify"
	"github.com/NotAFlightRisk/patchcall/internal/source"
)

type Status string

const (
	Affected    Status = "affected"
	Unavailable Status = "unavailable"
	Unknown     Status = "unknown"
	Unmapped    Status = "unmapped"
	Stale       Status = "stale"
	Watch       Status = "watch"
	Clear       Status = "clear"
	Quiet       Status = "quiet"
	Untracked   Status = "untracked"
)

var urgency = map[Status]int{Affected: 0, Unavailable: 1, Unmapped: 2, Unknown: 2, Stale: 3,
	Watch: 4, Clear: 5, Quiet: 6, Untracked: 7}

type App struct {
	source.Resolved
	Status Status `json:"status"`
	OnFile int    `json:"advisories_on_file"`
	Stale  bool   `json:"stale,omitempty"`
	match.Result
}

type Report struct {
	Checked  time.Time  `json:"checked"`
	Next     time.Time  `json:"next"`
	Source   string     `json:"source"`
	Problems []string   `json:"problems,omitempty"`
	Apps     []App      `json:"apps"`
	Channels []string   `json:"channels"`
	Feed     []FeedItem `json:"-"`
}

func (r Report) Count(statuses ...Status) int {
	count := 0
	for _, app := range r.Apps {
		for _, status := range statuses {
			if app.Status == status {
				count++
			}
		}
	}
	return count
}

// Blind is true when something is stopping an honest all-clear
func (r Report) Blind() bool {
	return len(r.Problems) > 0 || r.Count(Unavailable, Unknown, Unmapped, Stale) > 0
}

// Worst is the highest severity among an app's hits
func (a App) Worst() string {
	if len(a.Hits) == 0 {
		return ""
	}
	return a.Hits[0].Severity
}

func byUrgency(a, b App) int {
	return cmp.Or(urgency[a.Status]-urgency[b.Status],
		match.Rank(b.Worst())-match.Rank(a.Worst()),
		cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)))
}

func (c *Checker) message(app App, fresh []match.Hit) notify.Message {
	urgent := false
	lines := []string{fmt.Sprintf("%d new advisor%s. Move to %s.", len(fresh),
		plural(len(fresh), "y", "ies"), app.MoveTo), ""}
	for _, hit := range fresh {
		line := fmt.Sprintf("%s %s: %s", strings.ToUpper(hit.Severity), hit.ID, hit.Summary)
		if hit.KEV {
			line += " (actively exploited)"
		}
		lines = append(lines, line)
		urgent = urgent || hit.KEV || match.Rank(hit.Severity) >= match.Rank("high")
	}
	return notify.Message{
		Title:      fmt.Sprintf("%s %s needs patching", app.Name, app.Version),
		Body:       strings.Join(lines, "\n"),
		URL:        cmp.Or(c.opts.PublicURL, fresh[0].URL),
		Urgent:     urgent,
		App:        app.Name,
		Version:    app.Version,
		MoveTo:     app.MoveTo,
		Advisories: fresh,
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Print writes the report as plain text, for --once
func (r Report) Print(out io.Writer) {
	table := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(table, "Checked %d apps from %s\n", len(r.Apps), r.Source)
	for _, problem := range r.Problems {
		fmt.Fprintf(table, "! %s\n", problem)
	}
	for _, app := range r.Apps {
		switch app.Status {
		case Affected:
			fmt.Fprintf(table, "\nPATCH\t%s %s\tmove to %s\n", app.Name, app.Version, app.MoveTo)
			for _, hit := range app.Hits {
				fmt.Fprintf(table, "\t  %s %s\t%s\n", hit.Severity, hit.ID, hit.Summary)
			}
		case Untracked:
			fmt.Fprintf(table, "--\t%s\t%s\n", app.Name, app.Untracked)
		case Watch:
			fmt.Fprintf(table, "??\t%s %s\t%d to check by hand\n", app.Name, app.Version, len(app.Unreadable))
		case Clear, Quiet:
			fmt.Fprintf(table, "ok\t%s %s\t%d %s on file, none hit you\n",
				app.Name, app.Version, app.OnFile, plural(app.OnFile, "advisory", "advisories"))
		default:
			fmt.Fprintf(table, "??\t%s %s\t%s\n", app.Name, app.Version, app.Problem)
		}
	}
	table.Flush()
}
