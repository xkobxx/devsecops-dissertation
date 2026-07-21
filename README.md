# DevSecOps Trust Gate

A GitHub Action that runs Bandit, Semgrep, pip-audit, Trivy and Gitleaks against your repo, aggregates their findings into one gate, and — on the paid tier — tells you which findings are worth acting on and which are noise.

> **In plain English:** it's a metal detector that also tells you which alarms are real. Most SAST tools bury real vulnerabilities under a pile of false positives; this scores every finding against measured, disclosed accuracy data instead of asking you to trust it blindly.

---

## What you get

| | Free | Paid |
|---|---|---|
| Bandit / Semgrep / pip-audit / Trivy / Gitleaks scan + aggregation | ✅ | ✅ |
| Unified severity gate (fails the build on HIGH+, configurable) | ✅ | ✅ |
| HTML dashboard | ✅ | ✅ |
| Confidence score per finding (empirical precision, not a guess) | — | ✅ |
| "Act on these first" ranked triage list | — | ✅ |

**$19/month flat, not per-seat** — one price regardless of team size.

### [→ Subscribe here](https://buy.stripe.com/3cIfZgaf2eTrb627pBb7y00)

Your license key is emailed to you automatically right after checkout.

---

## Quick Start

```yaml
# .github/workflows/security.yml
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest   # required: Trivy/Gitleaks run as Docker container actions (Linux only)
    steps:
      - uses: actions/checkout@v4
      - uses: xkobxx/devsecops-dissertation@v1.0.0
        with:
          target: .
          fail-on: high
          # license-key: ${{ secrets.TRUST_GATE_LICENSE }}   # paid tier only
```

That's it — no separate install step, no manual scanner invocations. The dashboard is uploaded as a build artifact (`security-dashboard`) on every run.

---

## How it works

Five free scanners run against your code. Their findings get merged into one gate that fails the build on anything serious. On the paid tier, every finding also gets scored against real, measured accuracy data, so you know which ones to fix first instead of triaging a wall of alerts by hand.

---

## Is this legit?

- **Not another scanner.** It aggregates the free ones you already trust — Bandit, Semgrep, pip-audit, Trivy, Gitleaks — rather than replacing them with a black box.
- **The accuracy numbers are disclosed, not marketing.** Every confidence score ships with its own sample size, so you can see how much to trust it. Full methodology: [docs/RESEARCH.md](docs/RESEARCH.md).
- **No server holds your code or your findings.** Scanning runs entirely in your own CI. License verification is a local signature check, not a network call.
- **MIT-licensed core, source-available paid layer.** See [License](#license) below.

---

## Docs

- [Local development & running it yourself](docs/DEVELOPMENT.md)
- [Research methodology & precision/recall results](docs/RESEARCH.md)
- [Architecture, licensing internals, and project structure](docs/ARCHITECTURE.md)

---

## License

MIT — see [LICENSE](LICENSE) — for everything except the confidence-scoring engine (`scripts/score_findings.py`, `scripts/build_confidence_table.py`, `confidence_table.json`), which is source-available but proprietary; see [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL). Scanning, aggregation, and the gate are free and open; confidence scoring requires an active paid subscription.

## GitHub Repository

**https://github.com/xkobxx/devsecops-dissertation**
