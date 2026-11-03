package check

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/NotAFlightRisk/patchcall/internal/feed"
	"github.com/NotAFlightRisk/patchcall/internal/match"
)

// State is everything kept between runs: HTTP caches, digest lookups and what's been alerted
type State struct {
	Pages   map[string]feed.Page `json:"pages"`
	KEV     feed.KEVCache        `json:"kev"`
	Digests map[string]string    `json:"digests"`
	Alerted map[string]time.Time `json:"alerted"`
	Seen    map[string]time.Time `json:"seen"`
	Feed    []FeedItem           `json:"feed"`
}

// FeedItem is one alert, as it goes out on the RSS feed
type FeedItem struct {
	App     string    `json:"app"`
	Version string    `json:"version"`
	Hit     match.Hit `json:"hit"`
	Seen    time.Time `json:"seen"`
}

const feedLength = 200

func loadState(file string) (State, error) {
	var state State
	raw, err := os.ReadFile(file)
	if err == nil {
		err = json.Unmarshal(raw, &state)
	} else if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	if err != nil {
		state = State{}
	}
	if state.Digests == nil {
		state.Digests = map[string]string{}
	}
	if state.Alerted == nil {
		state.Alerted = map[string]time.Time{}
	}
	if state.Seen == nil {
		state.Seen = map[string]time.Time{}
	}
	return state, err
}

func (s State) save(file string) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".state-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(raw)
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), file); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(file))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
