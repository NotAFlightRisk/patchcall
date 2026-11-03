package source

import (
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"

	"go.yaml.in/yaml/v3"
)

// App is one entry in the image map, tying images to the repo that publishes their advisories
type App struct {
	Images      []string `yaml:"images"`
	Repo        string   `yaml:"repo"`
	Name        string   `yaml:"name,omitempty"`
	Env         string   `yaml:"env,omitempty"`
	IgnoreLabel bool     `yaml:"ignore_label,omitempty"`
	Only        []string `yaml:"only,omitempty"`
	Skip        []string `yaml:"skip,omitempty"`
	Unversioned string   `yaml:"unversioned,omitempty"`
	Untracked   string   `yaml:"untracked,omitempty"`
	fromFile    bool
}

//go:embed apps.yaml
var bundled []byte

type Map map[string]App

// LoadMap reads the bundled map, then lays the overrides file over it, image by image
func LoadMap(overrides string) (Map, error) {
	m := Map{}
	if err := m.add(bundled, false); err != nil {
		return nil, fmt.Errorf("bundled app map: %w", err)
	}
	if overrides == "" {
		return m, nil
	}
	raw, err := os.ReadFile(overrides)
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	yours := Map{}
	if err == nil {
		err = yours.add(raw, true)
	}
	if err != nil {
		return m, fmt.Errorf("%s: %w", overrides, err)
	}
	maps.Copy(m, yours)
	return m, nil
}

func (m Map) add(raw []byte, fromFile bool) error {
	var apps []App
	if err := yaml.Unmarshal(raw, &apps); err != nil {
		return err
	}
	for _, app := range apps {
		if len(app.Images) == 0 {
			return fmt.Errorf("an entry for %q has no images", app.Repo)
		}
		app.fromFile = fromFile
		for _, image := range app.Images {
			m[ParseRef(image).Name()] = app
		}
	}
	return nil
}
