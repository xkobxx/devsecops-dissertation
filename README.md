# DevSecOps Trust Gate

A GitHub Action that runs Bandit, Semgrep, pip-audit, Trivy and Gitleaks against your repo, aggregates their findings into one gate, and — on the paid tier — tells you which findings are worth acting on and which are noise.

> **In simple words:** think of it as a metal detector at an airport that also tells you which alarms are real. Most SAST tools bury real vulnerabilities under a pile of false positives; this scores every finding against measured, disclosed accuracy data instead of asking you to trust it blindly.

---

## Why

Free scanners already exist. What's missing is trust: every vendor sells you a scan, but nobody publishes how often their own tool is wrong. Meanwhile per-seat pricing on the incumbents (Snyk, Semgrep Team, ...) stacks up fast for a small team running more than one product.

This tool doesn't replace your scanners — it aggregates the free ones you already trust, and adds a confidence score per finding based on empirically measured precision, not vendor marketing.

| | Free | Paid |
|---|---|---|
| Bandit / Semgrep / pip-audit / Trivy / Gitleaks scan + aggregation | ✅ | ✅ |
| Unified severity gate (fails the build on HIGH+, configurable) | ✅ | ✅ |
| HTML dashboard | ✅ | ✅ |
| Confidence score per finding (empirical precision, not a guess) | — | ✅ |
| "Act on these first" ranked triage list | — | ✅ |

**$19/month flat, not per-seat** — one price regardless of team size. [Subscribe here](https://buy.stripe.com/3cIfZgaf2eTrb627pBb7y00) — your license key is emailed to you automatically right after checkout.

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

## How It Works

```
checkout → Bandit/Semgrep/pip-audit/Trivy/Gitleaks (each best-effort, never blocks the run)
         → aggregate_results.py   normalises everything → findings.json, evaluates the gate
         → verify_license.py      offline signature check, no server call
         → score_findings.py      (paid only) joins findings against confidence_table.json
         → generate_report.py     → dashboard.html, uploaded as a build artifact
```

The gate fails the build on any finding at or above `fail-on` severity (default `high`), across **all** scanners — not just the SAST tools, a bug in an early version of this pipeline that's since been fixed.

### The confidence layer

`confidence_table.json` is built from `scripts/build_confidence_table.py`, which matches historical scanner findings against a hand-seeded, fully-enumerated vulnerability fixture (`test_app/`) and computes real precision per `(tool, rule)`. Tools with no ground-truth coverage for their finding type (today: pip-audit, Trivy, Gitleaks) are excluded rather than scored — an empty ground truth would otherwise produce a fake 0% precision, and that's exactly the kind of unearned confidence number this project exists to avoid.

**Honesty, up front:** today's corpus is one small fixture with 6 seeded vulnerabilities. Per-rule sample sizes are tiny (often 1-3) — every table entry carries its own `sample_size` so this is visible rather than hidden. Treat published numbers as directional until the corpus grows. The matching method (±5-line proximity) can also spuriously match an unrelated finding to a nearby seeded vuln in dense files — a known, disclosed limitation, not a hidden one.

### Licensing (paid tier)

License keys are self-contained and verified offline (Ed25519 signature + expiry check, no database, no server to run). `scripts/issue_license.py` is the seller-side tool that generates keys; it never runs inside the Action. A missing, invalid, or expired key just falls back to the free tier silently — it never fails your build.

Enforcement is defense in depth, not just orchestration: `action.yml` only invokes `score_findings.py` after a successful license check, *and* `score_findings.py` independently verifies the license key itself before scoring anything. Running it directly, outside the Action, without a valid key does nothing.

---

## Local Development

```bash
pip install -r requirements.txt
brew install trivy        # macOS; see trivy docs for other platforms

# Run the pipeline against test_app/ manually
bandit -r test_app/ -f json -o reports/bandit_report.json
semgrep --config=p/python --json --output reports/semgrep_report.json test_app/
pip-audit -r test_app/requirements.txt --format json -o reports/pip_audit_report.json
trivy config . --format json --output reports/trivy_report.json
docker run --rm -v "$PWD":/repo ghcr.io/gitleaks/gitleaks:latest \
  detect --source /repo --report-format json \
  --report-path /repo/reports/gitleaks_report.json --exit-code 0

python scripts/aggregate_results.py            # → reports/findings.json, runs the gate
python scripts/build_confidence_table.py       # → confidence_table.json (rebuild after changing the fixture)
python scripts/score_findings.py               # → adds confidence fields to findings.json (paid-tier logic)
python scripts/generate_report.py              # → reports/dashboard.html
```

Open `reports/dashboard.html` in a browser to see the results.

### CLI reference for `aggregate_results.py`

```
--target PATH          What was scanned, recorded in findings.json (default: .)
--reports-dir DIR       Where to read the raw per-tool reports from (default: reports)
--output PATH           Where to write findings.json (default: <reports-dir>/findings.json)
--fail-on LEVEL         critical | high | medium | low | none (default: high)
```

---

## Tool Versions

| Tool | Version |
|------|---------|
| Python | 3.11.x |
| Flask | 3.1.1 |
| Bandit | 1.9.4 |
| Semgrep | 1.156.0 |
| pip-audit | latest |
| Trivy | latest |
| Gitleaks | latest |
| Docker | latest |

---

## Project Structure

```
devsecops-dissertation/
├── action.yml                       # The reusable composite GitHub Action
├── test_app/
│   ├── app.py                       # Vulnerable Flask app (6 seeded vulnerabilities)
│   ├── seeded_vulnerabilities.json  # Ground truth — ships as the confidence-table corpus
│   └── requirements.txt
├── scripts/
│   ├── aggregate_results.py         # Merges all reports → findings.json + security gate
│   ├── build_confidence_table.py    # Build-time: computes empirical precision per rule
│   ├── score_findings.py            # Runtime: joins findings against confidence_table.json
│   ├── issue_license.py             # Seller-side: generate keypair / issue license keys
│   ├── verify_license.py            # Runtime: offline license verification
│   ├── generate_report.py           # Builds the HTML dashboard
│   ├── calculate_metrics.py         # Precision / recall / F1 across 5 runs
│   └── visualise_results.py         # Generates 4 metric charts
├── confidence_table.json            # Generated by build_confidence_table.py
├── reports/                         # All scan output lives here
├── results/run_1 … run_5/           # findings.json per experiment run
├── docs/                            # Screenshots and pipeline diagram
├── .github/workflows/devsecops.yml  # This repo's own CI (dogfoods the scanners directly)
└── docker-compose.yml               # Vulnerable apps for DAST testing
```

---

## The Seeded Vulnerability Fixture

`test_app/app.py` has 6 deliberately seeded vulnerabilities — a fully-enumerated ground truth used both for the dissertation's precision/recall research and as the corpus behind `confidence_table.json`.

| ID | Vulnerability | CWE | Severity | Expected Tool |
|----|--------------|-----|----------|---------------|
| VULN-001 | Hardcoded Credentials | CWE-798 | HIGH | Bandit |
| VULN-002 | SQL Injection | CWE-89 | HIGH | Bandit / Semgrep |
| VULN-003 | OS Command Injection | CWE-78 | HIGH | Bandit / Semgrep |
| VULN-004 | Code Injection (eval) | CWE-94 | HIGH | Bandit / Semgrep |
| VULN-005 | Unvalidated Redirect | CWE-601 | MEDIUM | Semgrep |
| VULN-006 | Path Traversal | CWE-22 | HIGH | Bandit / Semgrep |

---

## Measuring Effectiveness (Research Methodology)

The pipeline runs **5 times** against the same app and results are compared to the ground truth.

```bash
cp reports/findings.json results/run_1/findings.json   # repeat for run_2 … run_5
python scripts/calculate_metrics.py       # → results/metrics_summary.json
python scripts/visualise_results.py       # → reports/charts/ (4 PNG charts)
```

### Results Summary

| Tool | Precision | Recall | F1 |
|------|-----------|--------|----|
| Bandit | 0.571 | 0.800 | 0.666 |
| Semgrep | 0.625 | 1.000 | 0.769 |

---

## DAST Test Apps

Three well-known vulnerable apps for dynamic testing — run locally via Docker (not wired into the Action or CI; manual/local use only):

```bash
docker-compose up -d    # start
docker-compose down     # stop
```

| App | URL | Notes |
|-----|-----|-------|
| DVWA | http://localhost:8081 | Click **Setup / Reset DB** on first visit. Login: `admin` / `password` |
| Juice Shop | http://localhost:3000 | No login needed. Visit `/score-board` to see all challenges |
| WebGoat | http://localhost:8080/WebGoat | Register a local account, then work through the lessons |

---

## This Repo's Own CI

`.github/workflows/devsecops.yml` runs the scanners directly against `test_app/` on every push to `main` — this is the dissertation's original research pipeline, kept separate from `action.yml` (the reusable product) so the two can evolve independently.

```
sast-bandit ──────────────┐
sast-semgrep ─────────────┤
dast-zap ─────────────────┤──→ security-gate ──→ generate-dashboard
sca-pip-audit ────────────┤
container-scan-trivy ─────┤
secrets-scan-gitleaks ────┘
```

The security gate fails the build on any HIGH/CRITICAL finding across every scanner it aggregates. All scan reports are downloadable as artifacts from the GitHub Actions run summary.

---

## License

MIT — see [LICENSE](LICENSE) — for everything except the confidence-scoring engine (`scripts/score_findings.py`, `scripts/build_confidence_table.py`, `confidence_table.json`), which is source-available but proprietary; see [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL). The scanning, aggregation, and gate logic are free and open; the confidence scoring requires an active paid subscription.

## GitHub Repository

**https://github.com/xkobxx/devsecops-dissertation**
