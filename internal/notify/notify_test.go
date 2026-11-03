package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type captured struct {
	path, auth, gotify string
	body               map[string]any
}

func TestSendShapesEachChannelsPayload(t *testing.T) {
	var got []captured
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := captured{path: r.URL.Path, auth: r.Header.Get("Authorization"), gotify: r.Header.Get("X-Gotify-Key")}
		json.NewDecoder(r.Body).Decode(&c.body)
		got = append(got, c)
	}))
	defer server.Close()
	n := New(Config{NtfyURL: server.URL + "/alerts", NtfyToken: "tk", GotifyURL: server.URL + "/gotify/",
		GotifyToken: "gk", AppriseURL: server.URL + "/notify/home"}, server.Client())
	if err := n.Send(context.Background(), Message{Title: "Immich needs patching", Body: "Move to 3", Urgent: true}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d posts, want 3", len(got))
	}
	ntfy, gotify, apprise := got[0], got[1], got[2]
	if ntfy.path != "/" || ntfy.body["topic"] != "alerts" || ntfy.auth != "Bearer tk" || ntfy.body["priority"] != 5.0 {
		t.Errorf("ntfy got %+v", ntfy)
	}
	if gotify.path != "/gotify/message" || gotify.gotify != "gk" || gotify.body["message"] != "Move to 3" {
		t.Errorf("gotify got %+v", gotify)
	}
	if apprise.path != "/notify/home" || apprise.body["title"] != "Immich needs patching" {
		t.Errorf("apprise got %+v", apprise)
	}
}

func TestSendKeepsGoingPastABrokenChannel(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer server.Close()
	n := New(Config{NtfyURL: "http://127.0.0.1:1/nope", WebhookURL: server.URL}, server.Client())
	if err := n.Send(context.Background(), Message{}); err == nil {
		t.Error("want the ntfy failure reported")
	}
	if hits != 1 {
		t.Error("the webhook should still have been sent")
	}
}
