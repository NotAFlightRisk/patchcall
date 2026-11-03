# Security policy

Thanks for helping keep this project and the people using it safe 💛

---

## Supported versions

Our version history is linear, and we use semantic versioning. Only the latest release gets patched, so check you're on it before reporting anything.

---

## What's in scope

Patchcall talks to the Docker API, so anything that lets someone reach that through it, or reach its page from somewhere it shouldn't answer, is the big one. So is anything in an advisory, registry or GitHub response that ends up as markup on the page or in an alert. A wrong match (an advisory it should have flagged and didn't) isn't a vulnerability in Patchcall, but it is a bug worth reporting, so please open an issue for it.

---

## Reporting a vulnerability

> [!IMPORTANT]
> Please don't report anything publicly (issues, PRs, discussions) without giving us at least 30 days to respond and handle it.

Acceptable channels:

1. **GitHub** (preferred) - open an [advisory](https://github.com/NotAFlightRisk/patchcall/security/advisories/new) from the Security tab
2. **Email** - [security@peng.ly](mailto:security@peng.ly) (PGP: [`A8431F9F332FB0CD`](https://github.com/NotAFlightRisk.gpg))

Include the type of issue, the affected version and file paths, steps to reproduce, a PoC if you've got one, and what an attacker could actually achieve with it.

Keep it short, and don't over-state the impact - it's not helpful. Using AI is fine, just say that you have.

### What happens next

I'll try to acknowledge and triage within 48 hours. If it's valid, I'll get a fix out within 2 weeks and publish the advisory, and I'll keep you updated throughout.

---

## Disclosure

Coordinated, so give us a fair chance to ship a fix before going public. Happy to credit you in the advisory and release notes, or leave you out of it - your call.

---

## Safe harbour

Report in good faith, stick to this policy, and steer clear of privacy violations, data destruction and service disruption, and I won't pursue or support legal action against you.
