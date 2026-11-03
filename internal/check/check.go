// Package check runs one full pass: find what's running, fetch advisories, match, alert.
package check

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/NotAFlightRisk/patchcall/internal/feed"
	"github.com/NotAFlightRisk/patchcall/internal/match"
	"github.com/NotAFlightRisk/patchcall/internal/notify"
	"github.com/NotAFlightRisk/patchcall/internal/source"
)

type Options struct {
	Interval  time.Duration
	StateFile string
	Overrides string
	Inventory string
	DockerURL string
	PublicURL string
	Token     string
	UserAgent string
	Notify    notify.Config
	Client    *http.Client
}

type Checker struct {
	opts     Options
	state    State
	docker   *source.Docker
	fetcher  *feed.Fetcher
	registry *source.Registry
	notifier *notify.Notifier
	mu       sync.RWMutex
	report   Report
}

func New(opts Options) (*Checker, error) {
	state, err := loadState(opts.StateFile)
	if err != nil {
		slog.Warn("state file unreadable, starting afresh", "file", opts.StateFile, "err", err)
	}
	c := &Checker{
		opts:     opts,
		state:    state,
		fetcher:  feed.NewFetcher(opts.Client, opts.UserAgent, opts.Token, state.Pages, state.KEV),
		registry: &source.Registry{Client: opts.Client, UserAgent: opts.UserAgent},
		notifier: notify.New(opts.Notify, opts.Client),
	}
	if opts.Inventory == "" {
		if c.docker, err = source.NewDocker(opts.DockerURL); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Checker) Notifier() *notify.Notifier { return c.notifier }

// Report is the latest finished run, or an empty one while the first is still going
func (c *Checker) Report() Report {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.report
}

// Loop checks now and then every interval, until the context ends
func (c *Checker) Loop(ctx context.Context) {
	for {
		report := c.Run(ctx, true)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(report.Next)):
		}
	}
}

// Run does one full check, alerting on new matches when alert is set
func (c *Checker) Run(ctx context.Context, alert bool) Report {
	report := Report{Checked: time.Now(), Next: time.Now().Add(c.opts.Interval),
		Source: cmp.Or(filepath.Base(c.opts.Inventory), "Docker"), Channels: c.notifier.Names()}
	defer func() {
		c.mu.Lock()
		c.report = report
		c.mu.Unlock()
	}()
	problem := func(text string, err error) {
		report.Problems = append(report.Problems, text+": "+err.Error())
		slog.Warn(text, "err", err)
	}
	appMap, err := source.LoadMap(c.opts.Overrides)
	if err != nil {
		problem("Your overrides file didn't load, so only the bundled map is in use", err)
	}
	workloads, err := c.workloads(ctx)
	if err != nil {
		problem("Couldn't list what's running", err)
		return report
	}
	exploited, err := c.fetcher.Exploited(ctx)
	if err != nil {
		problem("Couldn't fetch CISA's exploited list, so those badges are missing", err)
	}
	resolver := source.Resolver{Map: appMap, Registry: c.registry, Digests: c.state.Digests}
	var resolved []source.Resolved
	for _, w := range workloads {
		resolved = append(resolved, resolver.Resolve(ctx, w))
	}
	var limited *feed.RateLimited
	for _, r := range group(resolved) {
		app := c.assess(ctx, r, exploited, &limited)
		report.Apps = append(report.Apps, app)
	}
	slices.SortStableFunc(report.Apps, byUrgency)
	if limited != nil {
		if retry := limited.Reset.Add(time.Minute); retry.Before(report.Next) {
			report.Next = retry
		}
	} else {
		c.fetcher.Forget()
	}
	if alert {
		for _, err := range c.alert(ctx, report.Apps) {
			problem("A notification didn't go out, it'll be retried next check", err)
		}
	}
	report.Feed = c.state.Feed
	c.state.Pages, c.state.KEV = c.fetcher.Pages, c.fetcher.KEV
	if err := c.state.save(c.opts.StateFile); err != nil {
		problem("Couldn't save state", err)
	}
	slog.Info("checked", "apps", len(report.Apps), "affected", report.Count(Affected),
		"next", report.Next.Format(time.DateTime))
	return report
}

func (c *Checker) workloads(ctx context.Context) ([]source.Workload, error) {
	if c.docker == nil {
		return source.Inventory(c.opts.Inventory)
	}
	return c.docker.Workloads(ctx)
}

// group folds containers running the same app at the same version into one row
func group(resolved []source.Resolved) []source.Resolved {
	var out []source.Resolved
	index := map[string]int{}
	for _, r := range resolved {
		key := cmp.Or(r.Repo, r.Image) + " " + r.Version
		if i, ok := index[key]; ok && r.Problem == "" {
			out[i].Containers = append(out[i].Containers, r.Containers...)
			continue
		}
		index[key] = len(out)
		out = append(out, r)
	}
	return out
}

func (c *Checker) assess(ctx context.Context, r source.Resolved, exploited map[string]bool,
	limited **feed.RateLimited) App {
	app := App{Resolved: r, Status: Unknown}
	if r.Untracked != "" {
		app.Status = Untracked
		return app
	}
	if r.Problem != "" {
		return app
	}
	version, ok := match.Parse(r.Version)
	if !ok {
		app.Problem = fmt.Sprintf("%q doesn't look like a version number.", r.Version)
		return app
	}
	var advisories []match.Advisory
	var err error
	if *limited != nil {
		err = **limited
	} else {
		advisories, err = c.fetcher.Advisories(ctx, r.Repo)
	}
	if err != nil {
		var hitLimit feed.RateLimited
		if errors.As(err, &hitLimit) {
			*limited = &hitLimit
		}
		cached, ok := c.fetcher.Cached(r.Repo)
		app.Problem = fetchProblem(err, ok)
		if !ok {
			app.Status = Unavailable
			return app
		}
		advisories, app.Stale = cached, true
	}
	app.OnFile = len(advisories)
	app.Result = match.Check(version, advisories, r.Scope)
	for _, hits := range [][]match.Hit{app.Hits, app.Unfixed, app.Unreadable} {
		for i := range hits {
			hits[i].KEV = hits[i].CVE != "" && exploited[hits[i].CVE]
		}
	}
	switch {
	case len(app.Hits) > 0:
		app.Status = Affected
	case app.Stale:
		app.Status = Stale
	case app.OnFile == 0:
		app.Status = Quiet
	default:
		app.Status = Clear
	}
	return app
}

func fetchProblem(err error, cached bool) string {
	var limited feed.RateLimited
	text := "Couldn't fetch its advisories (" + err.Error() + ")."
	switch {
	case errors.As(err, &limited):
		text = "GitHub's rate limit ran out, so it'll try again at " +
			limited.Reset.Format("15:04") + ". A GITHUB_TOKEN lifts the limit."
	case errors.Is(err, feed.ErrNotFound):
		text = "GitHub has no repo called that, or it's private. Fix it in your overrides file."
	}
	if cached {
		text += " Showing the last good fetch."
	}
	return text
}

func (c *Checker) alert(ctx context.Context, apps []App) []error {
	var errs []error
	for _, app := range apps {
		var fresh []match.Hit
		for _, hit := range app.Hits {
			if _, done := c.state.Alerted[app.Repo+" "+hit.ID]; !done {
				fresh = append(fresh, hit)
			}
		}
		if len(fresh) == 0 {
			continue
		}
		if err := c.notifier.Send(ctx, c.message(app, fresh)); err != nil {
			errs = append(errs, err)
			continue
		}
		now := time.Now()
		for _, hit := range fresh {
			c.state.Alerted[app.Repo+" "+hit.ID] = now
			c.state.Feed = append(c.state.Feed, FeedItem{App: app.Name, Version: app.Version,
				Hit: hit, Seen: now})
		}
		c.state.Feed = c.state.Feed[max(0, len(c.state.Feed)-feedLength):]
	}
	return errs
}
