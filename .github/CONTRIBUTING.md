# Contributing

Thanks for taking the time 🎉<br />
Bug reports, typo fixes and whole features are all welcome. By joining in, you agree to our [Code of Conduct](./CODE_OF_CONDUCT.md).

---

## Ways to contribute

- 🐛 **Report a bug** - open a [bug report](https://github.com/NotAFlightRisk/patchcall/issues/new?template=bug_report.yml)
- 💡 **Suggest a feature** - open a [feature request](https://github.com/NotAFlightRisk/patchcall/issues/new?template=feature_request.yml)
- 🗺️ **Add an app** - if Patchcall gets an image wrong, a fix to [`apps.yaml`](../internal/source/apps.yaml) helps everyone running it
- 📖 **Improve the docs** - typos, unclear wording and missing examples are all fair game
- 🔧 **Submit a fix** - see below
- 🔒 **Report a vulnerability** - please *don't* open a public issue, see [SECURITY.md](./SECURITY.md)

---

## Getting started

You'll need [Go](https://go.dev/dl/) 1.26 or newer.

```bash
git clone git@github.com:NotAFlightRisk/patchcall.git
cd patchcall
make run
```

That does one check against your local Docker and prints it. `go run .` starts the server on [localhost:7282](http://localhost:7282), and `PATCHCALL_INVENTORY=.github/site/inventory.yaml make run` checks the demo homelab instead of your own.

There's more on the options in the [README](./README.md#configuration).

---

## Pull requests

1. **Open an issue first** for anything non-trivial. Saves you writing code we might not merge.
2. **Fork it**, and branch off `main`. Name it something descriptive, like `fix/timeout-handling`.
3. **Keep it focused.** One logical change per PR, please.
4. **Add tests** covering the new behaviour.
5. **Run `make lint` and `make test`** before you push.
6. **Open the PR**, fill in the template, and link the issue it closes.

Don't worry about getting it perfect first time, we're happy to help get it over the line.

---

### Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/), and the release notes are generated from them, so it does matter:

```
feat: add support for custom timeouts
fix: handle empty response from upstream
docs: clarify the deployment steps
```

Types are `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `build`, `ci` and `chore`. Breaking changes get a `!` (like `feat!:`) plus a `BREAKING CHANGE:` footer.

---

### What we look for

- The change does one thing, and does it clearly
- Tests pass, and new behaviour has new tests
- Docs updated if public behaviour changed
- No unrelated reformatting mixed into the diff

---

## Licensing

By contributing, you agree that your work is licensed under the [MIT License](../LICENSE) that covers this project.
