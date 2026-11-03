// Package source finds what's running and works out which upstream app and version each one is.
package source

import "strings"

// Ref is an image reference split into the bits that matter, like docker.io/library/nginx:1.27
type Ref struct {
	Registry string
	Path     string
	Tag      string
}

// ParseRef reads an image reference the way Docker does, filling in docker.io and library/
func ParseRef(raw string) Ref {
	name, _, _ := strings.Cut(raw, "@")
	ref := Ref{Registry: "docker.io", Tag: "latest"}
	if slash := strings.LastIndex(name, "/"); strings.LastIndex(name, ":") > slash {
		colon := strings.LastIndex(name, ":")
		name, ref.Tag = name[:colon], name[colon+1:]
	}
	if first, rest, found := strings.Cut(name, "/"); found &&
		(strings.ContainsAny(first, ".:") || first == "localhost") {
		ref.Registry, name = first, rest
	}
	if ref.Registry == "index.docker.io" {
		ref.Registry = "docker.io"
	}
	if ref.Registry == "docker.io" && !strings.Contains(name, "/") {
		name = "library/" + name
	}
	ref.Path = strings.ToLower(name)
	return ref
}

// Name is the reference without its tag, which is what the app map keys on
func (r Ref) Name() string { return r.Registry + "/" + r.Path }

func (r Ref) String() string { return r.Name() + ":" + r.Tag }

// api is the host that actually answers the registry API for this reference
func (r Ref) api() string {
	switch r.Registry {
	case "docker.io":
		return "registry-1.docker.io"
	case "lscr.io":
		return "ghcr.io"
	}
	return r.Registry
}
