// Package notify sends the "patch this" message wherever you've asked for it.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/NotAFlightRisk/patchcall/internal/match"
)

type Config struct {
	NtfyURL     string
	NtfyToken   string
	GotifyURL   string
	GotifyToken string
	WebhookURL  string
	AppriseURL  string
	SMTPURL     string
	EmailFrom   string
	EmailTo     string
}

// Message is one app that needs patching, with the advisories that caught it
type Message struct {
	Title      string      `json:"title"`
	Body       string      `json:"body"`
	URL        string      `json:"url,omitempty"`
	Urgent     bool        `json:"urgent"`
	App        string      `json:"app"`
	Version    string      `json:"version"`
	MoveTo     string      `json:"move_to"`
	Advisories []match.Hit `json:"advisories"`
}

type channel struct {
	name string
	send func(context.Context, Message) error
}

type Notifier struct {
	client   *http.Client
	channels []channel
}

func New(cfg Config, client *http.Client) *Notifier {
	n := &Notifier{client: client}
	add := func(name, setting string, send func(context.Context, Message) error) {
		if setting != "" {
			n.channels = append(n.channels, channel{name, send})
		}
	}
	add("ntfy", cfg.NtfyURL, func(ctx context.Context, m Message) error {
		topic, err := url.Parse(cfg.NtfyURL)
		if err != nil {
			return err
		}
		base := *topic
		base.Path = path.Dir(topic.Path)
		priority := 3
		if m.Urgent {
			priority = 5
		}
		return n.post(ctx, base.String(), cfg.NtfyToken, "", map[string]any{
			"topic": path.Base(topic.Path), "title": m.Title, "message": m.Body,
			"priority": priority, "tags": []string{"rotating_light"}, "click": m.URL,
		})
	})
	add("Gotify", cfg.GotifyURL, func(ctx context.Context, m Message) error {
		priority := 5
		if m.Urgent {
			priority = 8
		}
		return n.post(ctx, strings.TrimSuffix(cfg.GotifyURL, "/")+"/message", "", cfg.GotifyToken,
			map[string]any{"title": m.Title, "message": m.Body, "priority": priority,
				"extras": map[string]any{"client::notification": map[string]any{
					"click": map[string]string{"url": m.URL}}}})
	})
	add("webhook", cfg.WebhookURL, func(ctx context.Context, m Message) error {
		return n.post(ctx, cfg.WebhookURL, "", "", m)
	})
	add("Apprise", cfg.AppriseURL, func(ctx context.Context, m Message) error {
		return n.post(ctx, cfg.AppriseURL, "", "",
			map[string]string{"title": m.Title, "body": m.Body, "type": "warning"})
	})
	add("email", cfg.SMTPURL, func(_ context.Context, m Message) error {
		return mail(cfg, m)
	})
	return n
}

// Names lists the channels that are switched on
func (n *Notifier) Names() []string {
	names := make([]string, len(n.channels))
	for i, c := range n.channels {
		names[i] = c.name
	}
	return names
}

// Send tries every channel, so one broken one doesn't silence the rest
func (n *Notifier) Send(ctx context.Context, m Message) error {
	var errs []error
	for _, c := range n.channels {
		if err := c.send(ctx, m); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.name, err))
		}
	}
	return errors.Join(errs...)
}

// SendTo sends to one channel by name
func (n *Notifier) SendTo(ctx context.Context, name string, m Message) error {
	for _, c := range n.channels {
		if c.name == name {
			return c.send(ctx, m)
		}
	}
	return fmt.Errorf("no channel called %s", name)
}

func (n *Notifier) post(ctx context.Context, target, bearer, gotifyKey string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if gotifyKey != "" {
		req.Header.Set("X-Gotify-Key", gotifyKey)
	}
	res, err := n.client.Do(req)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("got %s", res.Status)
	}
	return nil
}
