// Package feed fetches security advisories from GitHub and the CISA KEV catalogue, politely.
package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/NotAFlightRisk/patchcall/internal/match"
)

// Page is one cached page of a repo's advisories, kept with its ETag so a repeat is a free 304
type Page struct {
	ETag       string           `json:"etag"`
	Next       string           `json:"next,omitempty"`
	Advisories []match.Advisory `json:"advisories"`
}

// NewFetcher picks up where the last run's cache left off
func NewFetcher(client *http.Client, userAgent, token string, pages map[string]Page, kev KEVCache) *Fetcher {
	if pages == nil {
		pages = map[string]Page{}
	}
	return &Fetcher{Client: client, UserAgent: userAgent, Token: token, API: "https://api.github.com",
		KEVURL: KEVURL, Pages: pages, KEV: kev, touched: map[string]bool{}}
}

type Fetcher struct {
	Client    *http.Client
	UserAgent string
	Token     string
	API       string
	KEVURL    string
	Pages     map[string]Page
	KEV       KEVCache
	touched   map[string]bool
}

// RateLimited means GitHub wants us to back off until Reset
type RateLimited struct{ Reset time.Time }

func (e RateLimited) Error() string {
	return "GitHub's rate limit is spent until " + e.Reset.Format(time.Kitchen)
}

// ErrNotFound means the repo is missing, private or renamed
var ErrNotFound = errors.New("GitHub has no such repo, or it's private")

var nextLink = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// Advisories lists a repo's published advisories, minus withdrawn ones. Pages only replace
// the cache once every page has come back, so a half-finished fetch never sticks
func (f *Fetcher) Advisories(ctx context.Context, repo string) ([]match.Advisory, error) {
	var all []match.Advisory
	fetched := map[string]Page{}
	for next := f.firstPage(repo); next != ""; {
		page, err := f.page(ctx, next)
		if err != nil {
			return nil, err
		}
		fetched[next] = page
		all, next = append(all, page.Advisories...), page.Next
	}
	for url, page := range fetched {
		f.Pages[url], f.touched[url] = page, true
	}
	return all, nil
}

func (f *Fetcher) firstPage(repo string) string {
	return f.API + "/repos/" + repo + "/security-advisories?per_page=100&state=published"
}

func (f *Fetcher) page(ctx context.Context, url string) (Page, error) {
	cached, known := f.Pages[url]
	res, err := f.get(ctx, url, cached.ETag, "application/vnd.github+json")
	if err != nil {
		return Page{}, err
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusNotModified && known:
		return cached, nil
	case res.StatusCode == http.StatusNotFound:
		return Page{}, ErrNotFound
	case res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusTooManyRequests:
		if reset, limited := rateLimit(res); limited {
			return Page{}, RateLimited{reset}
		}
	}
	if res.StatusCode != http.StatusOK {
		return Page{}, fmt.Errorf("GitHub said %s", res.Status)
	}
	var raw []struct {
		GHSA            string     `json:"ghsa_id"`
		CVE             string     `json:"cve_id"`
		URL             string     `json:"html_url"`
		Summary         string     `json:"summary"`
		Severity        string     `json:"severity"`
		Published       time.Time  `json:"published_at"`
		Withdrawn       *time.Time `json:"withdrawn_at"`
		Vulnerabilities []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Range   string `json:"vulnerable_version_range"`
			Patched string `json:"patched_versions"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return Page{}, fmt.Errorf("reading GitHub's answer: %w", err)
	}
	page := Page{ETag: res.Header.Get("ETag")}
	if found := nextLink.FindStringSubmatch(res.Header.Get("Link")); found != nil {
		page.Next = found[1]
	}
	for _, a := range raw {
		if a.Withdrawn != nil {
			continue
		}
		advisory := match.Advisory{ID: a.GHSA, CVE: a.CVE, URL: a.URL, Summary: a.Summary,
			Severity: a.Severity, Published: a.Published}
		for _, v := range a.Vulnerabilities {
			advisory.Affected = append(advisory.Affected,
				match.Affected{Package: v.Package.Name, Range: v.Range, Patched: v.Patched})
		}
		page.Advisories = append(page.Advisories, advisory)
	}
	return page, nil
}

// Cached rebuilds a repo's advisories from the last good fetch, if there was one
func (f *Fetcher) Cached(repo string) ([]match.Advisory, bool) {
	var all []match.Advisory
	next := f.firstPage(repo)
	for next != "" {
		page, ok := f.Pages[next]
		if !ok {
			return nil, false
		}
		f.touched[next] = true
		all, next = append(all, page.Advisories...), page.Next
	}
	return all, true
}

// Forget drops cached pages this run didn't ask for, like repos nobody runs any more
func (f *Fetcher) Forget() {
	for url := range f.Pages {
		if !f.touched[url] {
			delete(f.Pages, url)
		}
	}
	f.touched = map[string]bool{}
}

func (f *Fetcher) get(ctx context.Context, url, etag, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", f.UserAgent)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if f.Token != "" && strings.HasPrefix(url, f.API) {
		req.Header.Set("Authorization", "Bearer "+f.Token)
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	res, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 400 {
		io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
	}
	return res, nil
}

// rateLimit works out when to try again, falling back to an hour when GitHub doesn't say
func rateLimit(res *http.Response) (time.Time, bool) {
	now := time.Now()
	if seconds, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && seconds > 0 {
		return now.Add(time.Duration(seconds) * time.Second), true
	}
	if res.StatusCode != http.StatusTooManyRequests && res.Header.Get("X-RateLimit-Remaining") != "0" {
		return time.Time{}, false
	}
	reset, _ := strconv.ParseInt(res.Header.Get("X-RateLimit-Reset"), 10, 64)
	if at := time.Unix(reset, 0); at.After(now) {
		return at, true
	}
	return now.Add(time.Hour), true
}
