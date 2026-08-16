# Trust Gate

**Automatically find security problems in your code before they reach production.**

Trust Gate runs security scanners on every pull request, filters out the noise,
and tells you exactly which issues need fixing — right inside GitHub. It works
locally in your CI pipeline, so your source code never leaves your environment.

## Quick start — GitHub Action

Add this to `.github/workflows/security.yml` in your repository:

```yaml
name: Security scan

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

That's it. Every pull request now gets a security check. If a high or critical
issue is found, the build fails and a comment appears on the PR explaining what
was found and how to fix it.

### What you can configure

| Input | Default | What it does |
|---|---|---|
| `target` | `.` | Which folder to scan |
| `fail-on` | `high` | Minimum severity that blocks the PR: `critical`, `high`, `medium`, `low`, or `none` |
| `scanner-failure-policy` | `fail` | What happens if a scanner crashes: `fail`, `warn`, or `ignore` |
| `optional-scanners` | _(none)_ | Scanners that are allowed to be missing (comma-separated) |
| `scanner-timeout-seconds` | `300` | How long each scanner can run before timing out |
| `dast-enabled` | `false` | Also run a live web-application scan (see [DAST safety](docs/DAST_SAFETY.md)) |

### What you get back

| Output | What it is |
|---|---|
| `findings-path` | The full scan results as JSON |
| `sarif-path` | Findings in GitHub's security format (shows up in the Security tab) |
| `check-summary-path` | A pass/fail summary shown on the PR check |
| `pr-comment-path` | The PR comment body with findings and fix suggestions |

## How it works

```
Your code
  ↓
1. Detect what technologies you use (Python, Node, Docker, Terraform, etc.)
  ↓
2. Pick the right scanners (Bandit, Semgrep, pip-audit, Trivy, Gitleaks, etc.)
  ↓
3. Run them and check they actually succeeded (no silent failures)
  ↓
4. Merge duplicate findings from different scanners
  ↓
5. Look up known exploits and threat intelligence
  ↓
6. Check if the vulnerable code is actually reachable
  ↓
7. Apply your security policy to decide: block, warn, or allow
  ↓
8. Post results to your PR, GitHub Security tab, and audit reports
```

Trust Gate doesn't just dump scanner output. It answers the question:
**"Given everything we know, should this code ship?"**

## Install the CLI

If you want to run Trust Gate locally instead of (or alongside) the GitHub Action:

```bash
pip install --require-hashes -r requirements/runtime.lock
pip install --editable . --no-deps
trustgate --help
```

### Common commands

**Scan and aggregate results:**

```bash
trustgate aggregate \
  --reports-dir reports \
  --output reports/findings.json \
  --fail-on high
```

**Generate a security report for GitHub:**

```bash
trustgate sarif \
  --input reports/findings.json \
  --output reports/trustgate.sarif
```

**Check findings against your security policy:**

```bash
trustgate decide \
  --input reports/findings.json \
  --output reports/decisions.json
```

**Create a baseline so only new issues block PRs:**

```bash
trustgate baseline create \
  --input reports/findings.json \
  --output reports/baseline.json \
  --default-branch main
```

See `trustgate --help` for all available commands, including `enrich`,
`reachability`, `dast`, `policy`, `sbom`, `vex`, `evidence`, `remediate`,
and `report`.

## What's included

### Scanners (17 built-in adapters)

Bandit, Semgrep, pip-audit, Trivy, Gitleaks, OWASP ZAP, OSV-Scanner, Syft,
Grype, Checkov, Hadolint, Gosec, Brakeman, and more. Trust Gate picks the
right ones based on what's in your repository.

### Smart filtering

- **Deduplication** — if two scanners find the same issue, you see it once
  (with a note that both agree).
- **Threat intelligence** — checks OSV, GitHub Advisories, NVD, EPSS, and CISA
  KEV to see if a vulnerability is actually being exploited in the wild.
- **Reachability analysis** — a vulnerable library you never import is less
  urgent than one in your login page.
- **Baseline comparison** — only new issues block your PR, so you can adopt
  Trust Gate without fixing every legacy problem first.

### Policy as code

Write rules in YAML like "block critical SQL injection in production" or
"require a fix for anything on the CISA Known Exploited list." Ten starter
policy packs are included for common scenarios (startup, healthcare, financial
services, container security, etc.).

### Reports and artefacts

- **SARIF** — findings appear in GitHub's Security tab
- **GitHub Check** — pass/fail summary on every PR
- **PR comment** — one comment listing what was found, updated on each push
- **SBOM** — full ingredient list of your dependencies (CycloneDX + SPDX)
- **VEX** — documents which vulnerabilities are actually exploitable
- **Audit evidence** — signed proof of what was scanned and when
- **HTML dashboard** — a filterable standalone report

### Remediation help

- **Guided fixes** — explains why something is vulnerable and shows the secure
  coding pattern.
- **Auto-fix** — can automatically fix common issues (SQL injection, unsafe
  YAML, weak hashes, exposed secrets) with rollback support.
- **AI-assisted** — optionally uses an LLM to generate fix PRs, but never
  marks anything as fixed until tests pass. Requires explicit opt-in.

## Privacy

Your source code stays in your CI environment. Trust Gate does not upload it
anywhere. Threat intelligence lookups send only advisory IDs by default (e.g.
CVE numbers), never source code. You can disable network access entirely for
air-gapped environments.

See [Privacy model](docs/PRIVACY_MODEL.md) for full details.

## Working examples

The [examples/](examples/) directory has ready-to-use configurations for:

Python Flask · Python Django · Node.js · TypeScript · Java · Go · Docker ·
Terraform · Kubernetes · Monorepo · Offline mode · Custom policy ·
Authenticated DAST · Self-hosted deployment

## Project status

Trust Gate `v1.0.0` has completed 982 of 998 implementation items. The 16
remaining items require external human reviewers (independent security audit,
penetration test, and benchmark labelling review) and cannot be automated.

See [Roadmap status](docs/ROADMAP_STATUS.md) for details and
[Known limitations](docs/KNOWN_LIMITATIONS.md) for current boundaries.

<!-- trustgate:benchmark-metrics:start -->
> Generated from the versioned benchmark manifest. Do not edit this block.

| Tool | Precision | Recall | F1 | Posterior precision | 95% credible interval | Conservative bound | Maturity | n |
|---|---:|---:|---:|---:|---:|---:|---|---:|
| Bandit | 0.714 | 0.800 | 0.755 | 0.667 | 0.349–0.915 | 0.349 | Directional | 7 |
| Semgrep | 0.875 | 0.800 | 0.836 | 0.800 | 0.518–0.972 | 0.518 | Directional | 8 |

Methodology `1.0.0` uses a Beta(1, 1) prior. Displayed confidence is the posterior mean; decisions use the 95% lower credible bound.
4 byte-identical repeat run(s) are retained for provenance but excluded as independent statistical samples.
<!-- trustgate:benchmark-metrics:end -->

## Repository layout

```text
src/trustgate/       the main Python package
schemas/             JSON schemas for findings, policies, and reports
policies/            ready-to-use security policy packs
benchmarks/          test fixtures and benchmark data
tests/               unit, integration, security, and end-to-end tests
examples/            working examples for different project types
docs/                all documentation
action.yml           the GitHub Action
```

## Documentation

<details>
<summary>Getting started</summary>

- [Quick start](docs/QUICKSTART.md)
- [CLI installation](docs/CLI_INSTALLATION.md)
- [GitHub Action setup](docs/GITHUB_ACTION.md)
- [Configuration reference](docs/CONFIGURATION_REFERENCE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
</details>

<details>
<summary>Core concepts</summary>

- [Architecture](docs/ARCHITECTURE.md)
- [Schemas](docs/SCHEMAS.md)
- [Severity normalisation](docs/SEVERITY_NORMALISATION.md)
- [Stable fingerprints](docs/FINGERPRINTS.md)
- [Scanner compatibility](docs/SCANNER_COMPATIBILITY.md)
- [Compatibility matrix](docs/COMPATIBILITY_MATRIX.md)
- [Adapter SDK](docs/ADAPTER_SDK.md)
- [Scan planning](docs/SCAN_PLANNING.md)
- [Correlation](docs/CORRELATION.md)
</details>

<details>
<summary>Enrichment and analysis</summary>

- [Threat-intelligence enrichment](docs/THREAT_INTELLIGENCE.md)
- [Reachability analysis](docs/REACHABILITY_ANALYSIS.md)
- [DAST safety](docs/DAST_SAFETY.md)
- [Contextual decision scoring](docs/DECISION_SCORING.md)
</details>

<details>
<summary>Policy and gating</summary>

- [Policy as code](docs/POLICY_AS_CODE.md)
- [Policy reference](docs/POLICY_REFERENCE.md)
- [Baseline and differential comparison](docs/BASELINES.md)
- [Baseline setup](docs/BASELINE_SETUP.md)
- [Finding lifecycle](docs/FINDING_LIFECYCLE.md)
- [Suppression workflow](docs/SUPPRESSION_WORKFLOW.md)
</details>

<details>
<summary>Reporting and artefacts</summary>

- [SARIF](docs/SARIF.md)
- [GitHub Checks](docs/GITHUB_CHECKS.md)
- [Pull-request comments](docs/PR_COMMENTS.md)
- [Software bills of materials](docs/SBOM.md)
- [Vulnerability Exploitability eXchange](docs/VEX.md)
- [Audit evidence](docs/AUDIT_EVIDENCE.md)
</details>

<details>
<summary>Remediation</summary>

- [Remediation workflow](docs/REMEDIATION_WORKFLOW.md)
- [Deterministic remediation](docs/DETERMINISTIC_REMEDIATION.md)
- [Guided remediation](docs/GUIDED_REMEDIATION.md)
- [AI-assisted remediation](docs/AI_REMEDIATION.md)
</details>

<details>
<summary>Benchmarks and confidence</summary>

- [Benchmark methodology](docs/BENCHMARK_METHODOLOGY.md)
- [Multilingual benchmark corpus](docs/MULTILINGUAL_BENCHMARK.md)
- [Benchmark labelling and partitions](docs/BENCHMARK_LABELLING.md)
- [Confidence methodology](docs/CONFIDENCE_METHODOLOGY.md)
</details>

<details>
<summary>Operations and deployment</summary>

- [Deployment modes](docs/DEPLOYMENT_MODES.md)
- [Offline operation](docs/OFFLINE_OPERATION.md)
- [Data processing](docs/DATA_PROCESSING.md)
- [Dependency updates](docs/DEPENDENCY_UPDATES.md)
- [Release notes](docs/RELEASE_NOTES.md)
- [Release verification](docs/RELEASE_VERIFICATION.md)
</details>

<details>
<summary>Security and privacy</summary>

- [Security model](docs/SECURITY_MODEL.md)
- [Privacy model](docs/PRIVACY_MODEL.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Workflow security](docs/security/WORKFLOW_SECURITY.md)
- [Security review](docs/SECURITY_REVIEW.md)
- [Incident response](docs/INCIDENT_RESPONSE.md)
</details>

<details>
<summary>Licensing and commercial</summary>

- [Licensing architecture](docs/LICENSING_ARCHITECTURE.md)
- [Support policy](docs/SUPPORT_POLICY.md)
</details>

<details>
<summary>Migration and versioning</summary>

- [Migration guide](docs/MIGRATION.md)
- [Migration guide (detailed)](docs/MIGRATION_GUIDE.md)
- [Upgrade guide](docs/UPGRADE_GUIDE.md)
- [Versioning policy](docs/VERSIONING.md)
- [Known limitations](docs/KNOWN_LIMITATIONS.md)
</details>

<details>
<summary>Internal</summary>

- [Local development](docs/DEVELOPMENT.md)
- [Implementation roadmap status](docs/ROADMAP_STATUS.md)
- [Research methodology](docs/research/README.md)
- [Repository audit](docs/audits/REPOSITORY_AUDIT.md)
</details>

## Licence

The core package is MIT licensed. The confidence-scoring module under
`src/trustgate/scoring/` is source-available under
[LICENSE-COMMERCIAL](LICENSE-COMMERCIAL). See
[Licensing architecture](docs/LICENSING_ARCHITECTURE.md) for details.
