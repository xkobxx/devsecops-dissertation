# Local Development

Running the pipeline directly, without the Action, for anyone hacking on this repo.

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

## CLI reference for `aggregate_results.py`

```
--target PATH          What was scanned, recorded in findings.json (default: .)
--reports-dir DIR       Where to read the raw per-tool reports from (default: reports)
--output PATH           Where to write findings.json (default: <reports-dir>/findings.json)
--fail-on LEVEL         critical | high | medium | low | none (default: high)
```

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
