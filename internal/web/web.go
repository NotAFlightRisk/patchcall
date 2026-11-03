// Package web serves the status page, its RSS feed and a JSON copy of the report.
package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/NotAFlightRisk/patchcall/internal/check"
)

//go:embed page.html style.css favicon.svg
var files embed.FS

var tones = map[string]string{"ok": "#62d394", "affected": "#ff7f6b", "blind": "#f2b84f",
	"pending": "#f2b84f"}

var funcs = template.FuncMap{
	"join":  strings.Join,
	"sub":   func(a, b int) int { return a - b },
	"lower": strings.ToLower,
	"iso":   func(t time.Time) string { return t.Format(time.RFC3339) },
	"clock": func(t time.Time) string { return t.Local().Format("Mon 15:04") },
	"plural": func(n int, one, many string) string {
		if n == 1 {
			return one
		}
		return many
	},
	"stateLabel": func(s check.Status) string {
		return map[check.Status]string{check.Unknown: "Version unknown", check.Unmapped: "Unmapped",
			check.Unavailable: "Source unavailable", check.Stale: "Stale data"}[s]
	},
}

// view is the report shaped for the page
type view struct {
	Report     check.Report
	Version    string
	Static     bool
	Pending    bool
	Tone       string
	Title      string
	Subtitle   string
	Affected   []check.App
	Blind      []check.App
	Clear      []check.App
	Untracked  []untracked
	Unfixed    []check.App
	Unreadable []check.App
}

func newView(report check.Report, version string, static bool) view {
	v := view{Report: report, Version: version, Static: static, Pending: report.Checked.IsZero()}
	for _, app := range report.Apps {
		switch app.Status {
		case check.Affected:
			v.Affected = append(v.Affected, app)
		case check.Clear, check.Quiet, check.Watch:
			v.Clear = append(v.Clear, app)
		case check.Untracked:
			v.Untracked = addUntracked(v.Untracked, app)
		default:
			v.Blind = append(v.Blind, app)
		}
		if len(app.Unfixed) > 0 {
			v.Unfixed = append(v.Unfixed, app)
		}
		if len(app.Unreadable) > 0 {
			v.Unreadable = append(v.Unreadable, app)
		}
	}
	blind, watch := len(v.Blind), report.Count(check.Watch)
	switch {
	case v.Pending:
		v.Tone, v.Title = "pending", "First check is running"
		v.Subtitle = "It reads your containers, then fetches each app's advisories. " +
			"This page refreshes itself until it's done."
	case len(report.Apps) == 0 && len(report.Problems) > 0:
		v.Tone, v.Title = "blind", "Can't see what's running"
	case len(v.Affected) > 0:
		v.Tone = "affected"
		v.Title = fmt.Sprintf("%d %s to patch", len(v.Affected), plural(len(v.Affected), "app", "apps"))
		if blind > 0 {
			v.Subtitle = fmt.Sprintf("And %d more it can't check, listed below.", blind)
		}
	case blind > 0 || len(report.Problems) > 0:
		v.Tone, v.Title = "blind", "Nothing caught, but it can't see everything"
		v.Subtitle = "Something got in the way, so this isn't an all-clear yet."
		if blind > 0 {
			v.Subtitle = fmt.Sprintf("%d %s couldn't be checked, so this isn't an all-clear yet.",
				blind, plural(blind, "app", "apps"))
		}
	case watch > 0:
		v.Tone, v.Title = "blind", "Nothing to patch, but some need a look"
		v.Subtitle = fmt.Sprintf("%d %s an advisory written in words rather than versions, "+
			"with a fix newer than what you run. They're listed below.", watch, plural(watch, "has", "have"))
	case len(v.Clear) == 0:
		v.Tone, v.Title = "blind", "Nothing running to check"
	default:
		v.Tone, v.Title = "ok", "All clear"
		v.Subtitle = "Nothing you run is caught by an advisory that has a fix out."
		if n := len(v.Unfixed); n > 0 {
			v.Subtitle += fmt.Sprintf(" %d %s caught by advisories with no fix yet, listed below.",
				n, plural(n, "app is", "apps are"))
		}
		if n := report.Count(check.Untracked); n > 0 {
			v.Subtitle += fmt.Sprintf(" %d %s covered at all, see the bottom.",
				n, plural(n, "app isn't", "apps aren't"))
		}
	}
	return v
}

// untracked folds apps that aren't covered for the same reason into one line
type untracked struct {
	Names  []string
	Reason string
}

func addUntracked(list []untracked, app check.App) []untracked {
	for i := range list {
		if list[i].Reason == app.Untracked {
			list[i].Names = append(list[i].Names, app.Name)
			return list
		}
	}
	return append(list, untracked{[]string{app.Name}, app.Untracked})
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

type Server struct {
	Checker *check.Checker
	Version string
	Allowed []string
	page    *template.Template
	favicon *texttemplate.Template
}

func parse(extra string) (*template.Template, *texttemplate.Template, error) {
	page, err := template.New("page.html").Funcs(funcs).ParseFS(files, "page.html")
	if err == nil && extra != "" {
		page, err = page.ParseFiles(extra)
	}
	if err != nil {
		return nil, nil, err
	}
	favicon, err := texttemplate.ParseFS(files, "favicon.svg")
	return page, favicon, err
}

func (s *Server) Handler() (http.Handler, error) {
	var err error
	if s.page, s.favicon, err = parse(""); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "text/html; charset=utf-8", func(buf *bytes.Buffer) error {
			return s.page.Execute(buf, newView(s.Checker.Report(), s.Version, false))
		})
	})
	mux.HandleFunc("GET /style.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, files, "style.css")
	})
	for tone, color := range tones {
		mux.HandleFunc("GET /favicon-"+tone+".svg", func(w http.ResponseWriter, r *http.Request) {
			s.render(w, "image/svg+xml", func(buf *bytes.Buffer) error { return s.favicon.Execute(buf, color) })
		})
	}
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "favicon-ok.svg", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /feed.xml", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "application/rss+xml; charset=utf-8", func(buf *bytes.Buffer) error {
			return writeFeed(buf, s.Checker.Report().Feed, "http://"+r.Host+"/")
		})
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "application/json", func(buf *bytes.Buffer) error {
			return json.NewEncoder(buf).Encode(s.Checker.Report())
		})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	return s.guard(mux), nil
}

func (s *Server) render(w http.ResponseWriter, kind string, write func(*bytes.Buffer) error) {
	var buf bytes.Buffer
	if err := write(&buf); err != nil {
		http.Error(w, "Couldn't render this page: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", kind)
	w.Write(buf.Bytes())
}

// guard turns away other hostnames, so a page on the internet can't DNS-rebind its way in
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; "+
			"form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if r.URL.Path != "/healthz" && !s.allowed(r.Host) {
			http.Error(w, fmt.Sprintf("Patchcall doesn't answer to %q. Add it to "+
				"PATCHCALL_ALLOWED_HOSTS if that's how you reach it.", r.Host), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowed(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	return net.ParseIP(host) != nil || host == "localhost" ||
		slices.Contains(s.Allowed, "*") || slices.Contains(s.Allowed, host)
}

// Render writes the page as static files, with an optional template file filling its
// head and banner blocks
func Render(dir string, report check.Report, version, extra string) error {
	page, favicon, err := parse(extra)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var html bytes.Buffer
	if err := page.Execute(&html, newView(report, version, true)); err != nil {
		return err
	}
	css, _ := files.ReadFile("style.css")
	out := map[string][]byte{"index.html": html.Bytes(), "style.css": css}
	for tone, color := range tones {
		var svg bytes.Buffer
		if err := favicon.Execute(&svg, color); err != nil {
			return err
		}
		out["favicon-"+tone+".svg"] = svg.Bytes()
	}
	for name, body := range out {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func writeFeed(buf *bytes.Buffer, items []check.FeedItem, link string) error {
	type guid struct {
		Value     string `xml:",chardata"`
		Permalink bool   `xml:"isPermaLink,attr"`
	}
	type item struct {
		Title   string `xml:"title"`
		Link    string `xml:"link"`
		GUID    guid   `xml:"guid"`
		PubDate string `xml:"pubDate"`
		Desc    string `xml:"description"`
	}
	feed := struct {
		XMLName xml.Name `xml:"rss"`
		Version string   `xml:"version,attr"`
		Title   string   `xml:"channel>title"`
		Link    string   `xml:"channel>link"`
		Desc    string   `xml:"channel>description"`
		Items   []item   `xml:"channel>item"`
	}{Version: "2.0", Title: "Patchcall alerts", Link: link,
		Desc: "Advisories that catch an app you run, with a fix out"}
	for i := len(items) - 1; i >= 0; i-- {
		it := items[i]
		feed.Items = append(feed.Items, item{
			Title:   fmt.Sprintf("%s %s: %s (%s)", it.App, it.Version, it.Hit.ID, it.Hit.Severity),
			Link:    it.Hit.URL,
			GUID:    guid{Value: it.App + " " + it.Hit.ID},
			PubDate: it.Seen.Format(time.RFC1123Z),
			Desc:    fmt.Sprintf("%s. Fixed in %s.", it.Hit.Summary, it.Hit.Fix),
		})
	}
	buf.WriteString(xml.Header)
	return xml.NewEncoder(buf).Encode(feed)
}
