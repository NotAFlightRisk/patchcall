package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestParseRefFillsInDockerDefaults(t *testing.T) {
	cases := map[string]string{
		"nginx":                                      "docker.io/library/nginx:latest",
		"jellyfin/jellyfin:10.11.2":                  "docker.io/jellyfin/jellyfin:10.11.2",
		"ghcr.io/Immich-App/immich-server:v3":        "ghcr.io/immich-app/immich-server:v3",
		"localhost:5000/thing":                       "localhost:5000/thing:latest",
		"index.docker.io/library/redis:7@sha256:abc": "docker.io/library/redis:7",
	}
	for raw, want := range cases {
		if got := ParseRef(raw).String(); got != want {
			t.Errorf("ParseRef(%q) = %q, want %q", raw, got, want)
		}
	}
}

func resolver(t *testing.T) *Resolver {
	t.Helper()
	m, err := LoadMap("")
	if err != nil {
		t.Fatal(err)
	}
	return &Resolver{Map: m, Digests: map[string]string{}}
}

func TestResolvePrefersTheMapOverAWrapperLabel(t *testing.T) {
	got := resolver(t).Resolve(context.Background(), Workload{
		Image:  "lscr.io/linuxserver/sonarr:latest",
		Labels: map[string]string{"org.opencontainers.image.source": "https://github.com/linuxserver/docker-sonarr", "org.opencontainers.image.version": "4.0.20.3014-ls2"},
	})
	if got.Repo != "Sonarr/Sonarr" || got.Version != "4.0.20.3014" {
		t.Errorf("got %s at %s", got.Repo, got.Version)
	}
}

func TestResolveReadsTheSourceLabelForUnmappedImages(t *testing.T) {
	got := resolver(t).Resolve(context.Background(), Workload{
		Image:  "ghcr.io/someone/thing:1.2.3",
		Labels: map[string]string{"org.opencontainers.image.source": "https://github.com/someone/thing.git"},
	})
	if got.Repo != "someone/thing" || got.Version != "1.2.3" || got.VersionFrom != "tag" {
		t.Errorf("got %+v", got)
	}
}

func TestResolveSkipsAVersionLabelThatIsntTheApps(t *testing.T) {
	got := resolver(t).Resolve(context.Background(), Workload{
		Image:  "ollama/ollama:0.40.14",
		Labels: map[string]string{"org.opencontainers.image.version": "24.04"},
	})
	if got.Version != "0.40.14" {
		t.Errorf("version = %q, want the tag's 0.40.14 rather than Ubuntu's 24.04", got.Version)
	}
}

func TestResolveOwnsUpToAnUnknownVersion(t *testing.T) {
	got := resolver(t).Resolve(context.Background(), Workload{Image: "ghcr.io/open-webui/open-webui:main"})
	if got.Version != "" || got.Problem == "" {
		t.Errorf("want a problem and no version, got %+v", got)
	}
}

func TestOverridesWinOverTheBundledMap(t *testing.T) {
	file := t.TempDir() + "/overrides.yaml"
	writeFile(t, file, "- images: [jellyfin/jellyfin]\n  repo: me/my-jellyfin\n")
	m, err := LoadMap(file)
	if err != nil {
		t.Fatal(err)
	}
	if got := m["docker.io/jellyfin/jellyfin"]; got.Repo != "me/my-jellyfin" || !got.fromFile {
		t.Errorf("got %+v", got)
	}
}

func TestVersionFromDigestMatchesWithHeadRequestsOnly(t *testing.T) {
	var gets int
	registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			w.Write([]byte(`{"token":"anon"}`))
		case r.Header.Get("Authorization") != "Bearer anon":
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://`+r.Host+`/token",service="test",scope="repository:app/thing:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
		case strings.HasSuffix(r.URL.Path, "/tags/list"):
			gets++
			w.Write([]byte(`{"tags":["latest","1.9.0","2.0.0","2.1.0","nightly"]}`))
		case r.Method == http.MethodHead:
			digest := "sha256:old"
			if strings.HasSuffix(r.URL.Path, "/2.0.0") {
				digest = "sha256:running"
			}
			w.Header().Set("Docker-Content-Digest", digest)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer registry.Close()
	host := strings.TrimPrefix(registry.URL, "https://")
	reg := &Registry{Client: registry.Client(), UserAgent: "test"}
	tag, err := reg.VersionFromDigest(context.Background(), ParseRef(host+"/app/thing:latest"),
		[]string{host + "/app/thing@sha256:running"})
	if err != nil || tag != "2.0.0" {
		t.Fatalf("got %q, %v", tag, err)
	}
	if gets != 1 {
		t.Errorf("%d GETs, want just the tag list", gets)
	}
}

func TestNewDockerRefusesAddressesItCantDial(t *testing.T) {
	if _, err := NewDocker("ssh://box"); err == nil {
		t.Error("ssh:// should be refused")
	}
	if _, err := NewDocker((&url.URL{Scheme: "tcp", Host: "proxy:2375"}).String()); err != nil {
		t.Error(err)
	}
}

func writeFile(t *testing.T, file, body string) {
	t.Helper()
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
