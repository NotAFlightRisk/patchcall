<h1 align="center">Patchcall</h1>
<p align="center">
<i>Tells you when something you self-host has a security fix you actually need</i>
<br />
<b>🌐 <a href="https://patchcall.peng.ly/">Live demo</a></b> · <b>📦 <a href="https://github.com/NotAFlightRisk/patchcall/releases/latest">Latest release</a></b><br />
</p>

<p align="center">
<img src="./screenshot.png" alt="Patchcall's status page: a headline saying 4 apps to patch, then a row each for Jellyfin and Nextcloud, with the version running, the version to move to and the advisories that caught it" width="800" />
</p>

<details>
  <summary>Contents</summary>

- [About](#about)
- [Install](#install)
  - [Docker Compose](#docker-compose)
  - [Docker run](#docker-run)
  - [From a release](#from-a-release)
  - [Building from source](#building-from-source)
- [Configuration](#configuration)
  - [Alerts](#alerts)
  - [Fixing a wrong match](#fixing-a-wrong-match)
  - [Apps that aren't in Docker](#apps-that-arent-in-docker)
- [Usage](#usage)

</details>

## About

Patchcall reads your Docker host, works out which app each container is and what version it's on, and checks that app's own security advisories on GitHub. When one catches your version and there's a fixed release out, you get one alert saying what to move to. The rest of the time it keeps quiet, so it's the one alert you won't end up muting.

That's different from an image scanner, which buries you in base-image CVEs and only ever sees an app's own advisory if it happens to ship as an npm, pip or Go package (so Jellyfin, Immich or authentik advisories never turn up). And update checkers can't tell a security fix from a new emoji picker.

A few things it does to keep the noise down, and to stay honest:

- It only alerts when a fix exists. Advisories with no fix yet sit on the page, greyed out, until there is one.
- If it can't tell what version you're on, or the app isn't one it knows, it says so rather than calling it clear. Green means it checked.
- Ranges written in words ("anything before May") don't get guessed at. If the fix is newer than you, they're listed for you to look at by hand.
- Exploited-in-the-wild advisories (from [CISA's KEV list](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)) get a badge.

It knows the 50-odd most popular self-hosted images out of the box, and reads the `org.opencontainers.image.source` label for everything else. Nothing leaves your box apart from the requests to GitHub and the image registries.

---

## Install

### Docker Compose

This is the one to go for. Grab [`docker/compose.yaml`](../docker/compose.yaml) and start it:

```bash
curl -fsSLO https://raw.githubusercontent.com/NotAFlightRisk/patchcall/main/docker/compose.yaml
docker compose up -d
```

Then open [localhost:7282](http://localhost:7282). The first check takes a minute or so.

It puts [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) in front of the Docker socket, so Patchcall can list containers and images and nothing else. Mounting the socket straight in, even read-only, hands over the whole Docker API, which is root on your host.

It works without a GitHub token, but then GitHub allows 60 requests an hour and each check spends one or two per app, so with more than 40-odd apps a check finishes in two goes, an hour apart. A [fine-grained token](https://github.com/settings/personal-access-tokens/new) with public repo access and no permissions at all lifts that to 5,000, and with one, asking about advisories that haven't changed doesn't count at all. Put it in `GITHUB_TOKEN`.

### Docker run

Quicker, but this hands Patchcall the raw socket:

```bash
docker run -d --name patchcall -p 127.0.0.1:7282:7282 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --group-add "$(stat -c %g /var/run/docker.sock)" \
  -v patchcall:/data \
  ghcr.io/notaflightrisk/patchcall
```

The image runs as an unprivileged user, so the `--group-add` is what lets it read the socket. It's on GHCR and DockerHub ([`notaflightrisk/patchcall`](https://hub.docker.com/r/notaflightrisk/patchcall)), for `amd64`, `arm64` and `arm/v7`. Podman should work through its Docker-compatible socket too, though I haven't tried it.

### From a release

Every [release](https://github.com/NotAFlightRisk/patchcall/releases) has a binary for Linux and macOS, plus `checksums.txt`, a [Sigstore](https://www.sigstore.dev/) signature for it and an SBOM per archive. To check a download is ours:

```bash
sha256sum --ignore-missing -c checksums.txt
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/NotAFlightRisk/patchcall/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Then unpack it and run `./patchcall`. It reads `/var/run/docker.sock` by default (set `DOCKER_HOST` for anything else), and keeps its state in `./data`.

### Building from source

You'll need [Go](https://go.dev/dl/) 1.26 or newer.

```bash
git clone https://github.com/NotAFlightRisk/patchcall.git
cd patchcall
make build
./patchcall
```

`make test` and `make lint` do what you'd expect, and `make run` does a single check and prints it. Or build the image with `docker build -t patchcall .`

---

## Configuration

Everything's an environment variable.

| Variable | Default | What it does |
| --- | --- | --- |
| `GITHUB_TOKEN` | | Lifts GitHub's rate limit from 60 to 5,000 requests an hour |
| `DOCKER_HOST` | `unix:///var/run/docker.sock` | Where Docker is, `unix://` or `tcp://` |
| `PATCHCALL_INTERVAL` | `6h` | How often to check, `1m` at the quickest |
| `PATCHCALL_HOST` | `127.0.0.1` | Address to listen on. The image sets `0.0.0.0` |
| `PATCHCALL_PORT` | `7282` | Port to listen on |
| `PATCHCALL_ALLOWED_HOSTS` | | Extra hostnames it'll answer to, comma separated, or `*` for any |
| `PATCHCALL_DATA` | `./data` | Where it keeps its state. The image sets `/data` |
| `PATCHCALL_OVERRIDES` | `<data>/overrides.yaml` | Your own app map, see below |
| `PATCHCALL_INVENTORY` | | A list of apps to check instead of reading Docker, see below |
| `PATCHCALL_URL` | | Your Patchcall's address, so alerts link back to it |
| `PATCHCALL_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `TZ` | `UTC` | Time zone for the times on the page |

Out of the box it only answers to `localhost` and IP addresses, which stops a dodgy website reaching it through your browser. If you put it behind a reverse proxy or a name like `patchcall.home.lan`, add that to `PATCHCALL_ALLOWED_HOSTS`. There's no login, so don't put it on the open internet.

### Alerts

Set up as many as you like. Each one gets a message per app, the first time a fixed advisory catches it.

| Channel | Variables |
| --- | --- |
| [ntfy](https://ntfy.sh/) | `PATCHCALL_NTFY_URL` (the whole topic URL, like `https://ntfy.sh/my-topic`), plus `PATCHCALL_NTFY_TOKEN` if it needs one |
| [Gotify](https://gotify.net/) | `PATCHCALL_GOTIFY_URL` and `PATCHCALL_GOTIFY_TOKEN` (an app token) |
| [Apprise](https://github.com/caronc/apprise-api) | `PATCHCALL_APPRISE_URL`, your Apprise API's notify URL, like `http://apprise:8000/notify/patchcall` |
| Email | `PATCHCALL_SMTP_URL` (`smtp://user:pass@host:587`, or `smtps://` for port 465), `PATCHCALL_EMAIL_FROM` and `PATCHCALL_EMAIL_TO` |
| Webhook | `PATCHCALL_WEBHOOK_URL`, which gets a JSON `POST` with the app, versions and advisories |

There's also an RSS feed of every alert at `/feed.xml`. To check it's all wired up, `docker exec patchcall /patchcall --test-notify` sends a test message to each one.

### Fixing a wrong match

If it maps an image to the wrong repo, can't find one, or picks up advisories for a different part of the project, drop an `overrides.yaml` in its data folder (with Compose, the commented-out line in the compose file mounts one). It's read fresh on every check, and an entry there replaces the bundled one for the same image.

```yaml
- images: [ghcr.io/me/my-app]
  repo: me/my-app

- images: [lscr.io/linuxserver/bookstack]
  repo: BookStackApp/BookStack
  name: BookStack

- images: [ghcr.io/home-assistant/home-assistant]
  repo: home-assistant/core
  skip: [supervisor, companion]

- images: [my/internal-thing]
  untracked: Patched by hand, leave it out
```

| Key | What it does |
| --- | --- |
| `images` | The images this covers, without a tag |
| `repo` | The GitHub repo whose security advisories apply |
| `name` | What to call it on the page |
| `env` | An env var baked into the image that holds the version, like `NEXTCLOUD_VERSION` |
| `ignore_label` | `true` when the image's version label belongs to something else (Ollama's is Ubuntu's) |
| `only` / `skip` | Only keep, or drop, advisories whose package name contains one of these |
| `unversioned` | A reason it can't be matched, shown instead of guessing |
| `untracked` | A reason it isn't watched at all, which keeps it out of the way at the bottom |

The version comes from, in order, the `env` above, the image's version label, a plain `VERSION` env var, the tag, and finally which version tag on the registry has the same digest as yours (so `:latest` works for most images). If an app you run should be in the bundled map, an issue or PR adding it to [`apps.yaml`](../internal/source/apps.yaml) would be really handy.

### Apps that aren't in Docker

Point `PATCHCALL_INVENTORY` at a list and it checks that instead of reading Docker:

```yaml
- {name: Nextcloud, image: nextcloud, version: 33.0.2}
- {name: Home Assistant, repo: home-assistant/core, version: 2026.10.4}
```

Give it an `image` to pick up the bundled map's settings, or a `repo` to go straight to GitHub.

---

## Usage

The page at [localhost:7282](http://localhost:7282) is the whole thing. Patch-now rows come first, each with the version to move to, then anything it can't check and why, then everything that's clear. `/api/status` has the same as JSON, if you'd like it on a dashboard.

A few one-off commands, handy for cron or a quick look:

```bash
patchcall --once          # check now, print it, exit 1 if anything needs patching
patchcall --render out/   # check now and write the page out as static files
patchcall --test-notify   # send a test alert everywhere that's set up
```

---

## Credits

##### Contributors

[![contributors badge](https://readme-contribs.as93.net/contributors/NotAFlightRisk/patchcall?shape=squircle)](https://github.com/NotAFlightRisk/patchcall/graphs/contributors)

---

<!-- License + Copyright -->
<p  align="center">
  <a href="https://github.com/NotAFlightRisk"><img width="64" src="https://pixelflare.cc/iain/gif/penguin-dance.gif" /></a><br>
  <sup>
    <i>Licensed under <a href="../LICENSE">MIT</a>, © <a href="https://peng.ly">NotAFlightRisk</a> 2026</i>
  </sup>
</p>

<!--
oooh, hello there! hope you're having a nice day :)
   |\__      |\___
 (:> __)X  (:o ___(
   |/        |/
-->
