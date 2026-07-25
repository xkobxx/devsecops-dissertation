# Architecture

## How It Works

```
checkout → Bandit/Semgrep/pip-audit/Trivy/Gitleaks (health-aware execution)
         → aggregate_results.py   validates adapters and publishes canonical scan-run/policy JSON
         → verify_license.py      offline signature check, no server call
         → score_findings.py      (paid only) scores and revalidates the canonical scan run
         → generate_report.py     → dashboard.html, uploaded as a build artifact
```

The gate fails the build on any finding at or above `fail-on` severity (default `high`), across **all** scanners — not just the SAST tools, a bug in an early version of this pipeline that's since been fixed.

The aggregator publishes a versioned scan run containing a `scanners` record for
every configured scanner, a schema-valid `findings` array, summary counts, and
structured errors. It also publishes a versioned, explainable policy result.
Missing, malformed, and schema-invalid reports are not treated as clean scans.
Required scanner failures block by default; callers can separately declare
optional scanners or select a documented `warn`/`ignore` transition policy.

The composite Action and repository workflow run command-based scanners through
`trustgate scanner-run`. That boundary records real start/end timestamps, exit codes,
timeouts, installed versions, report presence, and separate stdout/stderr log
references. Trivy runs as a pinned external Action and its step outcome is
converted into the same model. Aggregation preserves failed execution state even
when a scanner leaves behind parseable output.

## Licensing (paid tier)

License keys are self-contained and verified offline (Ed25519 signature + expiry check, no database, no server to run). `scripts/issue_license.py` is the seller-side tool that generates keys; it never runs inside the Action. A missing, invalid, or expired key just falls back to the free tier silently — it never fails your build.

Enforcement is defense in depth, not just orchestration: `action.yml` only invokes `score_findings.py` after a successful license check, *and* `score_findings.py` independently verifies the license key itself before scoring anything. Running it directly, outside the Action, without a valid key does nothing.

## Tool Versions

| Tool | Version |
|------|---------|
| Python | 3.11.x |
| Flask | 3.1.1 |
| Bandit | 1.9.4 |
| Semgrep | 1.165.0 |
| pip-audit | 2.10.1 |
| Trivy Action | 0.36.0 |
| Trivy scanner | 0.69.3 |
| Gitleaks | 8.30.1 |
| ZAP Baseline Action | 0.12.0 |

Python and scanner transitive dependencies are hash-locked under
`requirements/`. GitHub Actions use immutable commit SHAs and container images
use registry digests. See `docs/SCANNER_COMPATIBILITY.md` for the support
contract.

## Project Structure

```
devsecops-dissertation/
├── action.yml                       # The reusable composite GitHub Action
├── pyproject.toml                   # Installable package and `trustgate` CLI metadata
├── src/trustgate/
│   ├── __main__.py                  # `python -m trustgate`
│   ├── aggregation/                 # Scanner report parsing and legacy severity gate
│   ├── benchmarks/                  # Versioned matching, metrics, and publication checks
│   ├── cli/                         # Product command-line interface
│   ├── confidence.py                # Separate non-circular confidence concepts
│   ├── licensing/                   # Offline licence verification and seller tooling
│   ├── reporting/                   # Static dashboard generation
│   ├── schema/                      # Schema validation, builders and migrations
│   ├── security/                    # Workflow input, path and URL validation
│   └── scoring/                     # Proprietary source layer, excluded from community wheel
├── tests/
│   └── unit/cli/                    # CLI acceptance tests
├── benchmarks/
│   ├── configurations/              # Versioned scanner configurations and rules
│   ├── datasets/                    # Versioned dataset descriptions
│   ├── fixtures/python/flask_vulnerable/
│   │   ├── app.py                   # Vulnerable Flask app (6 seeded vulnerabilities)
│   │   └── requirements.txt
│   ├── ground_truth/                # Labels and manual adjudications
│   ├── manifests/                   # Hashed source of truth for publication
│   ├── reports/                     # Generated metrics and confidence data
│   └── results/                     # Immutable historical run evidence
├── scripts/
│   ├── aggregate_results.py         # Merges all reports → findings.json + security gate
│   ├── build_confidence_table.py    # Compatibility wrapper for canonical generation
│   ├── score_findings.py            # Runtime: joins versioned posterior confidence data
│   ├── issue_license.py             # Seller-side: generate keypair / issue license keys
│   ├── validate_inputs.py           # Reject unsafe Action and DAST inputs before use
│   ├── verify_license.py            # Runtime: offline license verification
│   ├── generate_report.py           # Builds the HTML dashboard
│   ├── calculate_metrics.py         # Compatibility wrapper for canonical generation
│   ├── verify_benchmark_publication.py # Fails on inconsistent published metrics
│   └── visualise_results.py         # Charts generated only from canonical metrics
├── schemas/                         # Finding, scan-run and policy contracts
├── reports/                         # All scan output lives here
├── docs/                            # Screenshots, pipeline diagram, and these docs
├── .github/workflows/devsecops.yml  # This repo's own CI (dogfoods the scanners directly)
└── docker-compose.yml               # Vulnerable apps for DAST testing
```

`scripts/aggregate_results.py`, `scripts/generate_report.py`,
`scripts/issue_license.py`, and `scripts/verify_license.py` are compatibility
wrappers. Their reusable logic lives in `src/trustgate/`, and the wrappers locate
that package relative to their own file rather than the caller's working directory.

See `docs/SCHEMAS.md` for the canonical JSON contract and migration API,
`docs/BENCHMARK_METHODOLOGY.md` for the benchmark source of truth, and
`docs/CONFIDENCE_METHODOLOGY.md` for the confidence dependency model.
