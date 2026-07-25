# Local Development

Running the pipeline directly, without the Action, for anyone hacking on this repo.

Install the Trust Gate package in editable mode and verify the CLI:

```bash
python -m pip install --require-hashes -r requirements/runtime.lock
python -m pip install --editable . --no-deps
trustgate --help
```

The package uses a `src/` layout, so the installed CLI and imports do not depend
on running commands from the repository root.

```bash
python -m pip install --require-hashes -r requirements/development.lock
python -m pip install --require-hashes -r requirements/scanners.lock
brew install trivy        # macOS; see trivy docs for other platforms

# Run the pipeline against the deliberately vulnerable benchmark fixture manually
bandit -r benchmarks/fixtures/python/flask_vulnerable/ -f json -o reports/bandit_report.json
semgrep --config=p/python --json --output reports/semgrep_report.json benchmarks/fixtures/python/flask_vulnerable/
pip-audit -r benchmarks/fixtures/python/flask_vulnerable/requirements.txt --format json -o reports/pip_audit_report.json
trivy config . --format json --output reports/trivy_report.json
docker run --rm -v "$PWD":/repo \
  ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f \
  detect --source /repo --report-format json \
  --report-path /repo/reports/gitleaks_report.json --exit-code 3

python scripts/aggregate_results.py            # → validated findings.json + policy-result.json
trustgate benchmark --write                    # → canonical metrics, confidence data, and generated docs
trustgate benchmark --check                    # fail if any published consumer is inconsistent
python scripts/score_findings.py               # → adds confidence fields to findings.json (paid-tier logic)
python scripts/generate_report.py              # → reports/dashboard.html
```

Open `reports/dashboard.html` in a browser to see the results.

The packaged equivalent of the aggregation command is:

```bash
trustgate aggregate --reports-dir reports --output reports/findings.json --fail-on high
trustgate report --input reports/findings.json --output reports/dashboard.html
```

The report reads benchmark accuracy only from
`benchmarks/reports/flask-vulnerable-v1.metrics.json`; it never derives
precision or false negatives from confidence tiers. See
`docs/BENCHMARK_METHODOLOGY.md`.

Run an individual scanner through the health-aware execution boundary:

```bash
trustgate scanner-run \
  --scanner bandit \
  --report reports/bandit_report.json \
  --timeout 300 \
  -- bandit -r src -f json -o reports/bandit_report.json
```

This writes `reports/bandit_execution.json` plus separate standard-output and
standard-error logs under `reports/logs/`. Pass
`--require-execution-metadata` to `trustgate aggregate` when the reports must
have been produced by this boundary. For Gitleaks, pass both
`--finding-exit-code 3` to the wrapper and `--exit-code 3` to Gitleaks; its
default exit code `1` is ambiguous between leaks and execution errors.

The composite Action validates its environment inputs before scanner
installation. The same boundary can be exercised locally:

```bash
GITHUB_WORKSPACE="$PWD" \
GITHUB_OUTPUT=/tmp/trustgate-validated-inputs \
TRUSTGATE_TARGET=. \
TRUSTGATE_FAIL_ON=high \
TRUSTGATE_SCANNER_FAILURE_POLICY=fail \
TRUSTGATE_OPTIONAL_SCANNERS= \
TRUSTGATE_SCANNER_TIMEOUT=300 \
TRUSTGATE_ARTIFACT_NAME=security-dashboard \
TRUSTGATE_LICENSE_KEY= \
python scripts/validate_inputs.py action
```

The legacy `scripts/aggregate_results.py` path remains available for the composite
Action and existing users.

`findings.json` now contains the canonical scan-run envelope while retaining its
historical filename and `findings` array. See `docs/SCHEMAS.md` for validation,
versioning, and migration details.

Seller-side licence tooling also accepts an explicit key path, so it does not
depend on the repository working directory:

```bash
python scripts/issue_license.py generate-keypair \
  --private-key-path /secure/location/trustgate-signing-key.pem
```

## CLI reference for `aggregate_results.py`

```
--target PATH          What was scanned, recorded in findings.json (default: .)
--reports-dir DIR       Where to read the raw per-tool reports from (default: reports)
--output PATH           Where to write findings.json (default: <reports-dir>/findings.json)
--policy-output PATH    Where to write policy-result JSON (default: beside --output)
--fail-on LEVEL         critical | high | medium | low | none (default: high)
--required-scanner NAME require only this scanner; repeat as needed
--optional-scanner NAME allow this scanner to be absent; repeat as needed
--scanner-failure-policy fail | warn | ignore (default: fail)
--severity-basis normalised | original (default: normalised)
--require-execution-metadata require authoritative scanner-run metadata
--redact-sensitive-content create safe scanner-report views while retaining originals
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

`.github/workflows/devsecops.yml` runs separate informational scans against
`benchmarks/fixtures/python/flask_vulnerable/` on every push to `main`. This is
the dissertation's research fixture, kept separate from `action.yml` (the
reusable product) so the two can evolve independently.

```
sast-bandit ──────────────┐
sast-semgrep ─────────────┤
dast-zap ─────────────────┤──→ security-gate ──→ generate-dashboard
sca-pip-audit ────────────┤
container-scan-trivy ─────┤
secrets-scan-gitleaks ────┘
```

The security gate fails the build on any HIGH/CRITICAL finding across every scanner it aggregates. All scan reports are downloadable as artifacts from the GitHub Actions run summary.
