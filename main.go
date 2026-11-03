// Patchcall tells you when an app you run in Docker has a security advisory your version is
// caught by, and a fix is out.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/NotAFlightRisk/patchcall/internal/check"
	"github.com/NotAFlightRisk/patchcall/internal/notify"
	"github.com/NotAFlightRisk/patchcall/internal/web"
)

var version = "dev"

func main() {
	once := flag.Bool("once", false, "check once, print what it found and exit (1 if anything needs patching)")
	render := flag.String("render", "", "check once and write the page as static files into this directory")
	extra := flag.String("extra", "", "with --render, a template file that fills the page's head and banner blocks")
	testNotify := flag.Bool("test-notify", false, "send a test alert to every channel and exit")
	healthcheck := flag.Bool("healthcheck", false, "exit 0 if the server on PATCHCALL_PORT answers")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	level := slog.LevelInfo
	level.UnmarshalText([]byte(env("PATCHCALL_LOG_LEVEL", "info")))
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	addr := net.JoinHostPort(env("PATCHCALL_HOST", "127.0.0.1"), env("PATCHCALL_PORT", "7282"))
	switch {
	case *showVersion:
		fmt.Println(version)
		return
	case *healthcheck:
		os.Exit(probe(addr))
	}

	interval, err := time.ParseDuration(env("PATCHCALL_INTERVAL", "6h"))
	if err != nil || interval < time.Minute {
		fail("PATCHCALL_INTERVAL wants a duration of at least 1m, like 6h", err)
	}
	data := env("PATCHCALL_DATA", "data")
	checker, err := check.New(check.Options{
		Interval:  interval,
		StateFile: filepath.Join(data, "state.json"),
		Overrides: env("PATCHCALL_OVERRIDES", filepath.Join(data, "overrides.yaml")),
		Inventory: os.Getenv("PATCHCALL_INVENTORY"),
		DockerURL: os.Getenv("DOCKER_HOST"),
		PublicURL: os.Getenv("PATCHCALL_URL"),
		Token:     os.Getenv("GITHUB_TOKEN"),
		UserAgent: "patchcall/" + version + " (+https://github.com/NotAFlightRisk/patchcall)",
		Client:    &http.Client{Timeout: 30 * time.Second},
		Notify: notify.Config{
			NtfyURL:     os.Getenv("PATCHCALL_NTFY_URL"),
			NtfyToken:   os.Getenv("PATCHCALL_NTFY_TOKEN"),
			GotifyURL:   os.Getenv("PATCHCALL_GOTIFY_URL"),
			GotifyToken: os.Getenv("PATCHCALL_GOTIFY_TOKEN"),
			WebhookURL:  os.Getenv("PATCHCALL_WEBHOOK_URL"),
			AppriseURL:  os.Getenv("PATCHCALL_APPRISE_URL"),
			SMTPURL:     os.Getenv("PATCHCALL_SMTP_URL"),
			EmailFrom:   os.Getenv("PATCHCALL_EMAIL_FROM"),
			EmailTo:     os.Getenv("PATCHCALL_EMAIL_TO"),
		},
	})
	if err != nil {
		fail("can't start", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch {
	case *testNotify:
		testAlert(ctx, checker.Notifier())
	case *once:
		report := checker.Run(ctx, true)
		report.Print(os.Stdout)
		if report.Count(check.Affected) > 0 {
			os.Exit(1)
		}
	case *render != "":
		if err := web.Render(*render, checker.Run(ctx, false), version, *extra); err != nil {
			fail("couldn't write the page", err)
		}
	default:
		serve(ctx, addr, checker)
	}
}

func serve(ctx context.Context, addr string, checker *check.Checker) {
	server := web.Server{Checker: checker, Version: version,
		Allowed: strings.Split(strings.ToLower(os.Getenv("PATCHCALL_ALLOWED_HOSTS")), ",")}
	handler, err := server.Handler()
	if err != nil {
		fail("page templates are broken", err)
	}
	httpServer := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go checker.Loop(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdown)
	}()
	slog.Info("patchcall is up", "version", version, "addr", "http://"+addr)
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		fail("server stopped", err)
	}
}

func testAlert(ctx context.Context, notifier *notify.Notifier) {
	if len(notifier.Names()) == 0 {
		fail("no alert channels are set up", errors.New("see PATCHCALL_NTFY_URL and friends"))
	}
	err := notifier.Send(ctx, notify.Message{Title: "Patchcall test alert", App: "Patchcall",
		Body: "If you can read this, alerts work. Nothing needs patching."})
	if err != nil {
		fail("test alert failed", err)
	}
	fmt.Println("Sent to", strings.Join(notifier.Names(), ", "))
}

func probe(addr string) int {
	host, port, _ := net.SplitHostPort(addr)
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := http.Client{Timeout: 3 * time.Second}
	res, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil || res.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func env(key, fallback string) string { return cmp.Or(os.Getenv(key), fallback) }

func fail(what string, err error) {
	slog.Error(what, "err", err)
	os.Exit(1)
}
