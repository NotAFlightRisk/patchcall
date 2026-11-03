package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NotAFlightRisk/patchcall/internal/check"
	"github.com/NotAFlightRisk/patchcall/internal/match"
	"github.com/NotAFlightRisk/patchcall/internal/source"
)

func TestGuardTurnsAwayUnknownHostnames(t *testing.T) {
	server := Server{Allowed: []string{"patchcall.home.lan"}}
	handler := server.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	cases := map[string]int{
		"localhost:7282":          http.StatusOK,
		"192.168.1.20:7282":       http.StatusOK,
		"[::1]:7282":              http.StatusOK,
		"patchcall.home.lan":      http.StatusOK,
		"PATCHCALL.home.lan.:443": http.StatusOK,
		"evil.example.com":        http.StatusForbidden,
	}
	for host, want := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != want {
			t.Errorf("%s: got %d, want %d", host, res.Code, want)
		}
	}
}

func TestViewNeverCallsABlindRunAllClear(t *testing.T) {
	app := func(status check.Status) check.App {
		return check.App{Resolved: source.Resolved{Name: string(status)}, Status: status}
	}
	cases := []struct {
		apps []check.App
		tone string
	}{
		{[]check.App{app(check.Clear), app(check.Quiet), app(check.Untracked)}, "ok"},
		{[]check.App{app(check.Clear), app(check.Stale)}, "blind"},
		{[]check.App{app(check.Clear), app(check.Unknown)}, "blind"},
		{[]check.App{app(check.Untracked)}, "blind"},
		{[]check.App{app(check.Clear), app(check.Watch)}, "blind"},
		{[]check.App{{Status: check.Affected, Result: match.Result{Hits: []match.Hit{{}}}}}, "affected"},
	}
	for _, tc := range cases {
		report := check.Report{Checked: time.Now(), Apps: tc.apps}
		if got := newView(report, "test", false).Tone; got != tc.tone {
			t.Errorf("%v: tone %q, want %q", tc.apps, got, tc.tone)
		}
	}
}

func TestPageRendersEveryState(t *testing.T) {
	page, _, err := parse("")
	if err != nil {
		t.Fatal(err)
	}
	report := check.Report{Checked: time.Now(), Source: "Docker", Apps: []check.App{
		{Resolved: source.Resolved{Name: "Vaultwarden", Version: "1.35.3"}, Status: check.Affected,
			Result: match.Result{MoveTo: "1.36.0", Hits: []match.Hit{{Advisory: match.Advisory{
				ID: "GHSA-1", Severity: "high", Summary: "<script>"}, Fix: "1.36.0", KEV: true}}}},
		{Resolved: source.Resolved{Name: "Open WebUI", Problem: "No version"}, Status: check.Unknown},
		{Resolved: source.Resolved{Name: "postgres", Untracked: "No advisories"}, Status: check.Untracked},
		{Resolved: source.Resolved{Name: "Immich", Version: "2.7.0"}, Status: check.Watch,
			Result: match.Result{Unreadable: []match.Hit{{Advisory: match.Advisory{ID: "GHSA-2"}, Fix: "3.0"}},
				Unfixed: []match.Hit{{Advisory: match.Advisory{ID: "GHSA-3"}}}}},
	}}
	var out strings.Builder
	if err := page.Execute(&out, newView(report, "test", false)); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, want := range []string{"1 app to patch", "1.36.0", "Exploited in the wild", "No version",
		"Not covered", "&lt;script&gt;", "Worth a look by hand", "1 to check by hand", "No fix out yet"} {
		if !strings.Contains(html, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

func TestHandlerServesThePageAndItsFiles(t *testing.T) {
	checker, err := check.New(check.Options{Inventory: "unused.yaml", StateFile: t.TempDir() + "/state.json"})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := (&Server{Checker: checker, Version: "test"}).Handler()
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"/": "First check is running", "/style.css": "--surface",
		"/favicon-affected.svg": "#ff7f6b", "/feed.xml": "<rss", "/api/status": `"apps"`, "/healthz": "ok"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "localhost:7282"
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), want) {
			t.Errorf("%s: %d, body missing %q", path, res.Code, want)
		}
	}
}
