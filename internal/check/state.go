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
	state := State{Digests: map[string]string{}, Alerted: map[string]time.Time{}}
	raw, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return state, nil
	}
	if err == nil {
		err = json.Unmarshal(raw, &state)
	}
	if state.Digests == nil {
		state.Digests = map[string]string{}
	}
	if state.Alerted == nil {
		state.Alerted = map[string]time.Time{}
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
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}
