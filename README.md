# Trust Gate

Trust Gate is a Python-first, local-first application-security decision platform
under active development. It runs several established scanners, aggregates their
reports, applies a severity gate, and generates a static HTML report.

The current `0.1.x` release is an early prototype. It is useful for evaluation and
research, but it is not yet a production-grade security control.

## Current safety status

The existing Action runs Bandit, Semgrep, pip-audit, Trivy, and Gitleaks. Its
command-based scanners now record timestamps, exit codes, timeouts, versions,
report presence, and separate output logs. Trivy's external Action outcome is
recorded alongside the same health model. Missing, malformed, timed-out, or
crashed required scanners fail the gate by default.

The repository's historical research workflow still contains best-effort
scanner commands while it is migrated through Phase 1.3. Do not treat that
workflow's green result as equivalent to the composite Action's health-aware
gate.

Do not use the current green gate as the sole basis for a release decision. The
ordered implementation work and acceptance status are tracked in
[docs/ROADMAP_STATUS.md](docs/ROADMAP_STATUS.md).

Other important limitations:

- SAST and dependency discovery are Python-first.
- Finding fingerprints currently use a transitional legacy algorithm; stable,
  line-change-resistant fingerprints are scheduled for Phase 2.4.
- SARIF, SBOM, VEX, differential gating, and policy-as-code are not implemented.
- Confidence data comes from one small, deliberately vulnerable fixture and is
  experimental rather than statistically suitable for gating.
- The Stripe licence webhook is an undeployed design sketch.

See [docs/audits/REPOSITORY_AUDIT.md](docs/audits/REPOSITORY_AUDIT.md) for the
complete baseline.

## What works today

- A reusable composite GitHub Action for Linux runners.
- Bandit and Semgrep Python scanning.
- `requirements.txt` auditing with pip-audit.
- Trivy configuration scanning.
- Gitleaks secret scanning.
- Versioned canonical finding, scan-run, and policy-result JSON contracts.
- Schema validation before atomic JSON publication.
- Backward-compatible migration for historical unversioned findings and scan runs.
- Explicit scanner health for missing and malformed reports.
- Health-aware scanner execution with configurable timeouts and separate logs.
- Configurable severity threshold gating.
- A static, filterable HTML report.
- Offline Ed25519 licence verification.
- An installable `trustgate` CLI with aggregation and reporting commands.

Severity handling, including unknown defaults and the audited Trivy CVSS
fallback, is documented in `docs/SEVERITY_NORMALISATION.md`.
Stable finding identity and cross-scanner dependency correlation are documented
in `docs/FINGERPRINTS.md`.

## Install the CLI

From a checkout:

```bash
python -m pip install --require-hashes -r requirements/runtime.lock
python -m pip install --editable . --no-deps
trustgate --help
```

Aggregate existing scanner reports:

```bash
trustgate aggregate \
  --reports-dir reports \
  --output reports/findings.json \
  --fail-on high
```

Generate a product report without research benchmark metrics:

```bash
trustgate report \
  --input reports/findings.json \
  --output reports/dashboard.html \
  --no-benchmark-ground-truth
```

## Evaluate the GitHub Action

The repository slug remains `xkobxx/devsecops-dissertation` during the migration.
For evaluation:

```yaml
name: Trust Gate evaluation

on:
  pull_request:
  push:

permissions:
  contents: read

jobs:
  trust-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: xkobxx/devsecops-dissertation@v1.0.0
        with:
          target: .
          fail-on: high
```

This example uses the repository's current release tag for compatibility. The
roadmap requires immutable commit pins before production readiness.

### Action inputs

| Input | Default | Description |
|---|---|---|
| `target` | `.` | Path to scan, relative to the checked-out workspace |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, or `none` |
| `scanner-failure-policy` | `fail` | `fail`, `warn`, or `ignore` for required scanner failures |
| `severity-basis` | `normalised` | Gate on canonical severity or mapped scanner-native `original` severity |
| `optional-scanners` | empty | Comma-separated scanners allowed to be absent or unhealthy |
| `scanner-timeout-seconds` | `300` | Maximum duration for each command-based scanner |
| `redact-sensitive-content` | `false` | Publish content-addressed redacted report views while retaining originals as separate sensitive audit evidence |
| `license-key` | empty | Optional key for the experimental proprietary scoring layer |

### Action outputs

| Output | Description |
|---|---|
| `findings-path` | Path to the validated canonical scan-run JSON |
| `policy-result-path` | Path to the validated policy-result JSON |

The current Action supports one invocation per job because its dashboard artifact
name is fixed.

## Privacy and network behaviour

Customer source is scanned in the caller's CI workspace. Trust Gate does not
implement a source-code upload service. However, the current workflow downloads
Actions, Python packages, container images, and Semgrep rules. The generated
dashboard also references Google Fonts unless opened offline with that request
blocked.

The optional licence check is local. The undeployed commercial webhook would send
customer identity, email address, licence token, and expiry metadata through
Stripe, Vercel, and Resend; it does not receive repository source.

## Research is not a production benchmark

The dissertation experiment, labelled fixture, historical run data, and known
methodological limitations are documented separately in
[docs/research/README.md](docs/research/README.md).

Published historical precision figures must not be interpreted as general scanner
accuracy or current production confidence. The five recorded runs are
byte-identical, and most rule-level confidence samples contain only one finding.

## Repository map

```text
src/trustgate/       installable community package
scripts/             compatibility wrappers and research utilities
benchmarks/          deliberately vulnerable fixtures and benchmark material
tests/               unit and integration tests
docs/                product, security, migration, and research documentation
action.yml           reusable composite Action
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Local development](docs/DEVELOPMENT.md)
- [Scanner compatibility](docs/SCANNER_COMPATIBILITY.md)
- [Dependency update process](docs/DEPENDENCY_UPDATES.md)
- [Implementation roadmap status](docs/ROADMAP_STATUS.md)
- [Migration guide](docs/MIGRATION.md)
- [Versioning policy](docs/VERSIONING.md)
- [Research methodology](docs/research/README.md)
- [Repository audit](docs/audits/REPOSITORY_AUDIT.md)

## Licensing

The community package and core scanning/aggregation code are MIT licensed. The
confidence-scoring source under `src/trustgate/scoring/`,
`scripts/build_confidence_table.py`, and `confidence_table.json` are
source-available under [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL) and are excluded
from the community wheel.

Commercial terms require legal review before production reliance.
