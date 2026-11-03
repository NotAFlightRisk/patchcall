package source

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Workload is one image that's running, or one line of an inventory file
type Workload struct {
	Containers []string
	Image      string
	Labels     map[string]string
	Env        []string
	Digests    []string
	Name       string
	Repo       string
	Version    string
}

type Docker struct {
	client *http.Client
	base   string
}

// NewDocker talks to the Docker API at a DOCKER_HOST style address, unix:// or tcp://
func NewDocker(host string) (*Docker, error) {
	addr, err := url.Parse(cmp.Or(host, "unix:///var/run/docker.sock"))
	if err != nil {
		return nil, fmt.Errorf("reading DOCKER_HOST: %w", err)
	}
	transport := &http.Transport{}
	base := "http://" + addr.Host
	switch addr.Scheme {
	case "unix":
		var dialer net.Dialer
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", addr.Path)
		}
		base = "http://docker"
	case "tcp", "http":
	default:
		return nil, fmt.Errorf("DOCKER_HOST %q isn't unix:// or tcp://", host)
	}
	return &Docker{client: &http.Client{Transport: transport, Timeout: 30 * time.Second}, base: base}, nil
}

func (d *Docker) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+path, nil)
	if err != nil {
		return err
	}
	res, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach Docker: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("docker said %s to %s", res.Status, path)
	}
	return json.NewDecoder(res.Body).Decode(out)
}

// Workloads lists running containers, one entry per image however many run it
func (d *Docker) Workloads(ctx context.Context) ([]Workload, error) {
	var containers []struct {
		ID      string `json:"Id"`
		Names   []string
		Image   string
		ImageID string
	}
	if err := d.get(ctx, "/containers/json", &containers); err != nil {
		return nil, err
	}
	var out []Workload
	seen := map[string]int{}
	for _, c := range containers {
		name := c.ID[:min(12, len(c.ID))]
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		if i, ok := seen[c.ImageID]; ok {
			out[i].Containers = append(out[i].Containers, name)
			continue
		}
		var image struct {
			RepoTags    []string
			RepoDigests []string
			Config      struct {
				Labels map[string]string
				Env    []string
			}
		}
		if err := d.get(ctx, "/images/"+url.PathEscape(c.ImageID)+"/json", &image); err != nil {
			return nil, err
		}
		ref := c.Image
		if strings.HasPrefix(ref, "sha256:") && len(image.RepoTags) > 0 {
			ref = image.RepoTags[0]
		}
		seen[c.ImageID] = len(out)
		out = append(out, Workload{
			Containers: []string{name},
			Image:      ref,
			Labels:     image.Config.Labels,
			Env:        image.Config.Env,
			Digests:    image.RepoDigests,
		})
	}
	return out, nil
}
