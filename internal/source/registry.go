package source

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/NotAFlightRisk/patchcall/internal/match"
)

const manifestTypes = "application/vnd.oci.image.index.v1+json," +
	"application/vnd.docker.distribution.manifest.list.v2+json," +
	"application/vnd.oci.image.manifest.v1+json," +
	"application/vnd.docker.distribution.manifest.v2+json"

var (
	versionTag = regexp.MustCompile(`^[vV]?\d+(\.\d+){1,3}(-ls\d+)?$`)
	challenge  = regexp.MustCompile(`(\w+)="([^"]*)"`)
	nextPage   = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)
)

// Registry asks image registries which versioned tag a floating tag points at, using
// HEAD requests, which Docker Hub doesn't count against its pull limit
type Registry struct {
	Client    *http.Client
	UserAgent string
	tokens    map[string]string
}

// candidates is how many of the newest version tags get a HEAD before giving up
const candidates = 50

// VersionFromDigest finds the version tag that shares a digest with the running image
func (r *Registry) VersionFromDigest(ctx context.Context, ref Ref, digests []string) (string, error) {
	want := runningDigest(ref, digests)
	if want == "" {
		return "", nil
	}
	tags, err := r.tags(ctx, ref)
	if err != nil {
		return "", err
	}
	tags = slices.DeleteFunc(tags, func(tag string) bool { return !versionTag.MatchString(tag) })
	slices.SortFunc(tags, func(a, b string) int {
		va, _ := match.Parse(a)
		vb, _ := match.Parse(b)
		return vb.Compare(va)
	})
	for _, tag := range tags[:min(len(tags), candidates)] {
		res, err := r.do(ctx, http.MethodHead, ref, "/manifests/"+tag)
		if err != nil {
			return "", err
		}
		res.Body.Close()
		if res.Header.Get("Docker-Content-Digest") == want {
			return tag, nil
		}
	}
	return "", nil
}

func runningDigest(ref Ref, digests []string) string {
	for _, raw := range digests {
		name, digest, _ := strings.Cut(raw, "@")
		if ParseRef(name).Name() == ref.Name() {
			return digest
		}
	}
	return ""
}

func (r *Registry) tags(ctx context.Context, ref Ref) ([]string, error) {
	var all []string
	for path := "/tags/list?n=1000"; path != ""; {
		res, err := r.do(ctx, http.MethodGet, ref, path)
		if err != nil {
			return nil, err
		}
		var page struct{ Tags []string }
		err = json.NewDecoder(res.Body).Decode(&page)
		res.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading tags for %s: %w", ref.Name(), err)
		}
		all = append(all, page.Tags...)
		path = ""
		if found := nextPage.FindStringSubmatch(res.Header.Get("Link")); found != nil {
			next, err := url.Parse(found[1])
			if err != nil || (next.Host != "" && next.Host != ref.api()) {
				return nil, fmt.Errorf("%s sent a next page somewhere else", ref.api())
			}
			path = strings.TrimPrefix(next.RequestURI(), "/v2/"+ref.Path)
		}
	}
	return all, nil
}

// do sends one registry request, answering a Bearer challenge once if it gets one
func (r *Registry) do(ctx context.Context, method string, ref Ref, path string) (*http.Response, error) {
	key := ref.api() + "/" + ref.Path
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, "https://"+key+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", manifestTypes)
		req.Header.Set("User-Agent", r.UserAgent)
		if token := r.tokens[key]; token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := r.Client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("asking %s: %w", ref.api(), err)
		}
		if res.StatusCode == http.StatusUnauthorized && attempt == 0 {
			res.Body.Close()
			if err := r.authenticate(ctx, key, res.Header.Get("WWW-Authenticate")); err != nil {
				return nil, err
			}
			continue
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			return nil, fmt.Errorf("%s said %s for %s", ref.api(), res.Status, ref.Name())
		}
		return res, nil
	}
}

func (r *Registry) authenticate(ctx context.Context, key, header string) error {
	params := map[string]string{}
	for _, found := range challenge.FindAllStringSubmatch(header, -1) {
		params[found[1]] = found[2]
	}
	if params["realm"] == "" {
		return fmt.Errorf("%s wants a login patchcall can't do", key)
	}
	query := url.Values{"service": {params["service"]}, "scope": {params["scope"]}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, params["realm"]+"?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", r.UserAgent)
	res, err := r.Client.Do(req)
	if err != nil {
		return fmt.Errorf("getting a registry token: %w", err)
	}
	defer res.Body.Close()
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil || res.StatusCode != http.StatusOK {
		return fmt.Errorf("no anonymous token for %s (%s)", key, res.Status)
	}
	if r.tokens == nil {
		r.tokens = map[string]string{}
	}
	r.tokens[key] = cmp.Or(body.Token, body.AccessToken)
	return nil
}
