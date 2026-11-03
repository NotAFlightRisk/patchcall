package feed

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func fakeGitHub(t *testing.T, handler http.HandlerFunc) *Fetcher {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	f := NewFetcher(server.Client(), "test", "", nil, KEVCache{})
	f.API = server.URL
	return f
}

func TestAdvisoriesFollowsPagesAndDropsWithdrawnOnes(t *testing.T) {
	f := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "" {
			w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?after=x>; rel="next"`, r.Host, r.URL.Path))
			w.Write([]byte(`[{"ghsa_id":"GHSA-1","vulnerabilities":[{"vulnerable_version_range":"< 2"}]},
				{"ghsa_id":"GHSA-gone","withdrawn_at":"2026-01-01T00:00:00Z"}]`))
			return
		}
		w.Write([]byte(`[{"ghsa_id":"GHSA-2"}]`))
	})
	got, err := f.Advisories(context.Background(), "a/b")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "GHSA-1" || got[1].ID != "GHSA-2" || got[0].Affected[0].Range != "< 2" {
		t.Errorf("got %+v", got)
	}
}

func TestAdvisoriesReusesTheCacheOnANotModified(t *testing.T) {
	calls := 0
	f := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte(`[{"ghsa_id":"GHSA-1"}]`))
	})
	for range 2 {
		got, err := f.Advisories(context.Background(), "a/b")
		if err != nil || len(got) != 1 {
			t.Fatalf("got %+v, %v", got, err)
		}
	}
	if calls != 2 {
		t.Errorf("%d calls, want 2", calls)
	}
}

func TestAdvisoriesReportsTheRateLimit(t *testing.T) {
	f := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "2000000000")
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := f.Advisories(context.Background(), "a/b")
	var limited RateLimited
	if !errors.As(err, &limited) || limited.Reset.Unix() != 2000000000 {
		t.Errorf("got %v", err)
	}
}

func TestCachedServesTheLastGoodFetch(t *testing.T) {
	healthy := true
	f := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		if !healthy {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte(`[{"ghsa_id":"GHSA-1"}]`))
	})
	if _, err := f.Advisories(context.Background(), "a/b"); err != nil {
		t.Fatal(err)
	}
	healthy = false
	if _, err := f.Advisories(context.Background(), "a/b"); err == nil {
		t.Fatal("want an error from the broken fetch")
	}
	if got, ok := f.Cached("a/b"); !ok || len(got) != 1 {
		t.Errorf("cached = %+v, %v", got, ok)
	}
	if _, ok := f.Cached("never/fetched"); ok {
		t.Error("a repo never fetched has nothing cached")
	}
}

func TestAHalfFinishedFetchKeepsTheLastWholeOne(t *testing.T) {
	round := 1
	f := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		after := r.URL.Query().Get("after")
		switch {
		case after == "" && round == 1:
			w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?after=x>; rel="next"`, r.Host, r.URL.Path))
			w.Write([]byte(`[{"ghsa_id":"GHSA-1"}]`))
		case after == "":
			w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?after=y>; rel="next"`, r.Host, r.URL.Path))
			w.Write([]byte(`[{"ghsa_id":"GHSA-new"}]`))
		case after == "x":
			w.Write([]byte(`[{"ghsa_id":"GHSA-2"}]`))
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	})
	if _, err := f.Advisories(context.Background(), "a/b"); err != nil {
		t.Fatal(err)
	}
	round = 2
	if _, err := f.Advisories(context.Background(), "a/b"); err == nil {
		t.Fatal("want the second page's failure")
	}
	got, ok := f.Cached("a/b")
	if !ok || len(got) != 2 || got[0].ID != "GHSA-1" || got[1].ID != "GHSA-2" {
		t.Errorf("cached = %+v, want the whole first fetch", got)
	}
}

func TestATooManyRequestsWithNoHeadersStillBacksOff(t *testing.T) {
	f := fakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := f.Advisories(context.Background(), "a/b")
	var limited RateLimited
	if !errors.As(err, &limited) || time.Until(limited.Reset) < 30*time.Minute {
		t.Errorf("got %v, want a back-off of about an hour", err)
	}
}
