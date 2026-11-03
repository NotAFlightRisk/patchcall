package check

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NotAFlightRisk/patchcall/internal/notify"
)

type fixture struct {
	checker  *Checker
	hook     string
	messages []notify.Message
	refuse   bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	fx := &fixture{}
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/dani-garcia/vaultwarden/security-advisories":
			w.Write([]byte(`[{"ghsa_id":"GHSA-vw","severity":"high","cve_id":"CVE-1",
				"vulnerabilities":[{"vulnerable_version_range":"< 1.36.0","patched_versions":"1.36.0"}]}]`))
		case "/repos/jellyfin/jellyfin/security-advisories":
			w.Write([]byte(`[]`))
		case "/kev":
			w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-1"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fx.refuse {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var m notify.Message
		json.NewDecoder(r.Body).Decode(&m)
		fx.messages = append(fx.messages, m)
	}))
	t.Cleanup(github.Close)
	t.Cleanup(hook.Close)

	dir := t.TempDir()
	inventory := filepath.Join(dir, "inventory.yaml")
	os.WriteFile(inventory, []byte(`
- {image: vaultwarden/server, version: 1.35.3}
- {image: jellyfin/jellyfin, version: 10.11.2}
- {name: Mystery, image: example.org/mystery:1.0}
`), 0o644)
	checker, err := New(Options{Interval: time.Hour, StateFile: filepath.Join(dir, "state.json"),
		Inventory: inventory, Client: http.DefaultClient, Notify: notify.Config{WebhookURL: hook.URL}})
	if err != nil {
		t.Fatal(err)
	}
	checker.fetcher.API, checker.fetcher.KEVURL = github.URL, github.URL+"/kev"
	fx.checker, fx.hook = checker, hook.URL
	return fx
}

func TestRunSortsAppsByWhatNeedsDoing(t *testing.T) {
	report := newFixture(t).checker.Run(context.Background(), false)
	var got []Status
	for _, app := range report.Apps {
		got = append(got, app.Status)
	}
	want := []Status{Affected, Unmapped, Quiet}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("statuses = %v, want %v", got, want)
	}
	if hit := report.Apps[0].Hits[0]; !hit.KEV || hit.Fix != "1.36.0" {
		t.Errorf("hit = %+v, want KEV and a 1.36.0 fix", hit)
	}
	if !report.Blind() {
		t.Error("an unmapped app should stop the all-clear")
	}
}

func TestRunAlertsOncePerAdvisory(t *testing.T) {
	fx := newFixture(t)
	fx.checker.Run(context.Background(), true)
	fx.checker.Run(context.Background(), true)
	if len(fx.messages) != 1 || fx.messages[0].MoveTo != "1.36.0" || !fx.messages[0].Urgent {
		t.Fatalf("messages = %+v", fx.messages)
	}
	if feed := fx.checker.Report().Feed; len(feed) != 1 || feed[0].Hit.ID != "GHSA-vw" {
		t.Errorf("feed = %+v", feed)
	}
}

func TestRunRetriesAnAlertThatDidntGoOut(t *testing.T) {
	fx := newFixture(t)
	fx.refuse = true
	if report := fx.checker.Run(context.Background(), true); len(report.Problems) == 0 {
		t.Error("a failed alert should show up as a problem")
	}
	fx.refuse = false
	fx.checker.Run(context.Background(), true)
	if len(fx.messages) != 1 {
		t.Errorf("messages = %d, want the retried one", len(fx.messages))
	}
}

func TestRunRetriesSoonWhenItCantListWhatsRunning(t *testing.T) {
	checker, err := New(Options{Interval: 6 * time.Hour, StateFile: filepath.Join(t.TempDir(), "s.json"),
		DockerURL: "tcp://127.0.0.1:1", Client: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	report := checker.Run(context.Background(), false)
	if len(report.Problems) == 0 || time.Until(report.Next) > 2*time.Minute {
		t.Errorf("next check in %s, want about a minute", time.Until(report.Next).Round(time.Second))
	}
	if report.Source != "Docker" {
		t.Errorf("source = %q", report.Source)
	}
}

func TestStateSurvivesARestart(t *testing.T) {
	fx := newFixture(t)
	fx.checker.Run(context.Background(), true)
	again, err := New(fx.checker.opts)
	if err != nil {
		t.Fatal(err)
	}
	again.fetcher.API, again.fetcher.KEVURL = fx.checker.fetcher.API, fx.checker.fetcher.KEVURL
	again.Run(context.Background(), true)
	if len(fx.messages) != 1 {
		t.Errorf("messages = %d, a restart shouldn't re-alert", len(fx.messages))
	}
}

func TestRunOnlyRetriesTheChannelThatFailed(t *testing.T) {
	fx := newFixture(t)
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer broken.Close()
	fx.checker.notifier = notify.New(notify.Config{WebhookURL: fx.hook, NtfyURL: broken.URL + "/topic"},
		http.DefaultClient)
	fx.checker.Run(context.Background(), true)
	fx.checker.Run(context.Background(), true)
	if len(fx.messages) != 1 {
		t.Errorf("webhook got %d messages, want 1 however often ntfy fails", len(fx.messages))
	}
}

func TestANewChannelGetsWhatsAlreadyOpen(t *testing.T) {
	fx := newFixture(t)
	fx.checker.notifier = notify.New(notify.Config{}, http.DefaultClient)
	fx.checker.Run(context.Background(), true)
	fx.checker.notifier = notify.New(notify.Config{WebhookURL: fx.hook}, http.DefaultClient)
	fx.checker.Run(context.Background(), true)
	if len(fx.messages) != 1 {
		t.Errorf("messages = %d, the open match should reach the new channel", len(fx.messages))
	}
	if len(fx.checker.Report().Feed) != 1 {
		t.Error("the feed should have the match from the first run")
	}
}

func TestACorruptStateFileIsKeptNotOverwritten(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(file, []byte(`{"alerted": {"trunc`), 0o600)
	if _, err := New(Options{Inventory: "x.yaml", StateFile: file}); err != nil {
		t.Fatal(err)
	}
	kept, _ := filepath.Glob(file + ".broken-*")
	if len(kept) != 1 {
		t.Errorf("want the broken file kept aside, found %v", kept)
	}
}
