package source

import (
	"cmp"
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/NotAFlightRisk/patchcall/internal/match"
)

// Resolved is what a workload turned out to be, or why it couldn't be pinned down
type Resolved struct {
	Name        string      `json:"name"`
	Image       string      `json:"image,omitempty"`
	Containers  []string    `json:"containers,omitempty"`
	Repo        string      `json:"repo,omitempty"`
	RepoFrom    string      `json:"repo_from,omitempty"`
	Version     string      `json:"version,omitempty"`
	VersionFrom string      `json:"version_from,omitempty"`
	Scope       match.Scope `json:"-"`
	Problem     string      `json:"problem,omitempty"`
	Untracked   string      `json:"untracked,omitempty"`
}

var (
	versionLabels = []string{"org.opencontainers.image.version", "org.label-schema.version"}
	versionEnvs   = []string{"VERSION", "APP_VERSION", "VERSION_TAG"}
	githubRepo    = regexp.MustCompile(`^(?:https?://|git@)github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/.*)?$`)
	lsSuffix      = regexp.MustCompile(`-ls\d+$`)
)

type Resolver struct {
	Map      Map
	Registry *Registry
	// Digests remembers which tag each image digest matched, since a digest never changes
	Digests map[string]string
}

func (r *Resolver) Resolve(ctx context.Context, w Workload) Resolved {
	ref := ParseRef(w.Image)
	app, mapped := r.Map[ref.Name()]
	out := Resolved{Image: w.Image, Containers: w.Containers,
		Scope: match.Scope{Only: app.Only, Skip: app.Skip}}
	out.Repo, out.RepoFrom = repoFor(w, app, mapped)
	out.Untracked = app.Untracked
	out.Name = cmp.Or(w.Name, app.Name, w.Labels["org.opencontainers.image.title"],
		strings.TrimPrefix(path.Base("/"+out.Repo), "/"), path.Base(ref.Path))
	if out.Untracked != "" {
		return out
	}
	if out.Repo == "" {
		out.Problem = "Not in the app map, and the image doesn't name a GitHub repo. " +
			"Add it to your overrides file."
		return out
	}
	if app.Unversioned != "" && w.Version == "" {
		out.Problem = app.Unversioned
		return out
	}
	out.Version, out.VersionFrom = r.version(ctx, w, ref, app)
	if out.Version == "" {
		out.Problem = fmt.Sprintf("No version label, and the :%s tag doesn't match a "+
			"version tag on the registry.", ref.Tag)
		if strings.HasPrefix(out.VersionFrom, "registry") {
			out.Problem, out.VersionFrom = out.VersionFrom, ""
		}
	}
	return out
}

func repoFor(w Workload, app App, mapped bool) (string, string) {
	switch {
	case w.Repo != "":
		return w.Repo, "inventory"
	case mapped && app.fromFile:
		return app.Repo, "overrides"
	case mapped:
		return app.Repo, "app map"
	}
	if found := githubRepo.FindStringSubmatch(w.Labels["org.opencontainers.image.source"]); found != nil {
		return found[1] + "/" + found[2], "image label"
	}
	return "", ""
}

func (r *Resolver) version(ctx context.Context, w Workload, ref Ref, app App) (string, string) {
	if w.Version != "" {
		return w.Version, "inventory"
	}
	if found := envVersion(w.Env, app.Env); found != "" {
		return found, "env " + app.Env
	}
	if !app.IgnoreLabel {
		for _, label := range versionLabels {
			if found := match.Clean(lsSuffix.ReplaceAllString(w.Labels[label], "")); found != "" {
				return found, "label"
			}
		}
	}
	for _, key := range versionEnvs {
		if found := envVersion(w.Env, key); found != "" {
			return found, "env " + key
		}
	}
	if tag := lsSuffix.ReplaceAllString(ref.Tag, ""); match.Parts(tag) >= 2 {
		return match.Clean(tag), "tag"
	}
	digest := runningDigest(ref, w.Digests)
	if digest == "" || r.Registry == nil {
		return "", ""
	}
	tag, known := r.Digests[digest]
	if !known {
		var err error
		if tag, err = r.Registry.VersionFromDigest(ctx, ref, w.Digests); err != nil {
			return "", "registry lookup failed: " + err.Error()
		}
		r.Digests[digest] = tag
	}
	if tag == "" {
		return "", ""
	}
	return match.Clean(lsSuffix.ReplaceAllString(tag, "")), "digest"
}

func envVersion(env []string, key string) string {
	for _, pair := range env {
		if name, value, _ := strings.Cut(pair, "="); key != "" && name == key {
			return match.Clean(value)
		}
	}
	return ""
}
