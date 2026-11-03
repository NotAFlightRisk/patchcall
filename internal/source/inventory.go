package source

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

// Inventory reads a hand-written list of apps, for things that don't run in Docker
func Inventory(file string) ([]Workload, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		Name    string `yaml:"name"`
		Image   string `yaml:"image"`
		Repo    string `yaml:"repo"`
		Version string `yaml:"version"`
	}
	if err := yaml.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	out := make([]Workload, 0, len(entries))
	for _, e := range entries {
		if e.Image == "" && e.Repo == "" {
			return nil, fmt.Errorf("%s: %q needs an image or a repo", file, e.Name)
		}
		out = append(out, Workload{Name: e.Name, Image: e.Image, Repo: e.Repo, Version: e.Version})
	}
	return out, nil
}
