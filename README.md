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
- AI-assisted remediation is explicitly opt-in and limited to reviewed context,
  isolated branches, mandatory verification, and draft pull requests. It does
  not autonomously merge changes or treat model output as proof of a fix.
- Confidence data comes from one small, deliberately vulnerable fixture and is
  Directional rather than statistically mature; decisions use its conservative
  lower credible bound.
- The Stripe licence webhook is an undeployed design sketch.

See [docs/audits/REPOSITORY_AUDIT.md](docs/audits/REPOSITORY_AUDIT.md) for the
complete baseline.

## What works today

- A reusable composite GitHub Action for Linux runners.
- Bandit and Semgrep Python scanning.
- `requirements.txt` auditing with pip-audit.
- Trivy configuration scanning.
- Gitleaks secret scanning.
- Versioned canonical finding, scan-run, decision, policy-as-code, and
  policy-result JSON contracts.
- Schema validation before atomic JSON publication.
- Backward-compatible migration for historical unversioned findings and scan runs.
- Stable, versioned finding fingerprints and cross-scanner correlation.
- Versioned benchmark manifests with generated, consistency-checked metrics.
- A versioned, hash-bound multilingual benchmark fixture corpus covering seven
  source languages, Terraform, containers, Kubernetes, vulnerable/patched
  pairs, safe lookalikes, reachability, and code/dependency scopes without
  overstating unevaluated detection quality.
- Integrity-bound independent benchmark reviews with disagreement adjudication,
  Cohen's kappa, uncertainty, public-blind and private-commitment partitions,
  label commitments, and fail-closed rule-tuning leakage controls.
- Explainable multi-signal matching and manual adjudication for ambiguous labels.
- Beta-Binomial precision intervals, calibration metrics, and separate confidence
  components.
- Explicit scanner health for missing and malformed reports.
- Health-aware scanner execution with configurable timeouts and separate logs.
- Configurable severity threshold gating.
- A static, filterable HTML report.
- Offline Ed25519 licence verification.
- An installable `trustgate` CLI with aggregation and reporting commands.
- A typed scanner-adapter SDK with registration, entry-point discovery,
  applicability planning, isolated parsing, and 17 built-in integrations.
- Deterministic repository detection and an explainable, per-package scan plan
  with safe generated/vendor exclusions and explicit privacy declarations.
- Conservative exact deduplication, multi-signal cross-scanner correlation, and
  ancestry-aware corroboration with confidence limits.
- Cache-backed OSV, GitHub advisory, NVD, EPSS, and CISA KEV enrichment with
  offline, identifier-only, and full dependency-metadata modes.
- Conservative dependency reachability, Python source-to-sink traces, and
  optional DAST correlation with explainable static and runtime evidence.
- Opt-in, digest-pinned ZAP DAST with baseline/API discovery, safe and active
  modes, authenticated headers, scope allowlists, and hard resource bounds.
- Deterministic contextual decisions across 16 evidence components, with nine
  policy-driven outcomes, full rule traces, uncertainty, and tamper detection.
- JSON/YAML policy validation, exact-version inheritance, organisation defaults,
  repository overrides, saved-finding simulation, explanations, and policy tests.
- Ten documented and tested standard policy packs spanning startup,
  high-assurance, sector, framework-aligned, container, secret, and supply-chain
  starting points.
- Content-bound default-branch baselines and deterministic pull-request
  comparisons for new, removed, worsened, reachable, exploited, expired, and
  scanner-coverage changes.
- Differential baseline gates with new-risk enforcement by default, explicit
  all-risk and worsened-risk modes, public policy evaluation, and fail-closed
  scanner coverage checks.
- Immutable finding-state transitions with actor, timestamp, reason, evidence,
  approval, expiry, integrity checks, and automatic expiry reopening.
- Content-bound, exact-fingerprint suppression records with explicit scope,
  linting, expiry warnings, and automatic revalidation for code, reachability,
  KEV, exploit-evidence, and policy changes.
- Deterministic SARIF 2.1.0 with rule metadata, remediation, precise locations,
  stable fingerprints, artifact publication, and least-privilege GitHub code
  scanning upload.
- A stable GitHub Actions `Trust Gate` check with a bounded in-product summary
  of the decision, scanner health, finding classes, policy, baseline changes,
  evidence explanations, and detailed artifact link.
- One safely updatable pull-request comment with concise counts, collapsed
  detail, exact code links, remediation availability, and no source excerpts.
- Deterministic CycloneDX 1.6 and SPDX 2.3 product SBOMs with direct and
  transitive dependency relationships, exact versions, licences, Package URLs,
  lockfile hashes, signed release assets, and a fail-closed licence inventory.
- Approval-backed CycloneDX 1.6 VEX with explicit exploitability status,
  analysis state and justification, content-bound reachability and approval
  links, versioned revisions, and optional keyless signing.
- Reproducible audit-evidence manifests binding repository and workflow
  identity, scan and policy records, baselines, suppressions, approvals, SBOM,
  VEX, provenance, attestations, exclusions, and threat-data timestamps, with
  byte-for-byte verification and separate manual compliance requirements.
- Content-bound deterministic remediation for parameterised SQLite queries,
  direct subprocess argv, safe YAML, security-purpose hashes, exact dependency
  upgrades, numeric Docker users, environment-backed secrets, and Flask
  security headers, with protected backups and verified rollback.
- Evidence-bound guided remediation explaining vulnerabilities, exploit
  scenarios, recorded source-to-sink evidence, secure framework patterns, CWE
  references, tests, regression risks, and verification steps without changing
  source or claiming a fix.
- Explicitly opt-in AI-assisted remediation with bounded context disclosure,
  secret redaction, local and remote model modes, isolated worktree branches,
  five mandatory verification classes, post-scan regression checks, and
  verified-only draft pull requests.

Severity handling, including unknown defaults and the audited Trivy CVSS
fallback, is documented in `docs/SEVERITY_NORMALISATION.md`.
Stable finding identity and cross-scanner dependency correlation are documented
in `docs/FINGERPRINTS.md`.
Adapter lifecycle and extension guidance are documented in
`docs/ADAPTER_SDK.md`.
Repository detection, overrides, dry-run behavior, and plan fields are
documented in `docs/SCAN_PLANNING.md`.
Finding consolidation, evidence ancestry, contradictions, and corroboration
limits are documented in `docs/CORRELATION.md`.
Threat-feed privacy, cache expiry, stale-data behavior, and CLI usage are
documented in `docs/THREAT_INTELLIGENCE.md`.
Reachability statuses, limitations, evidence inputs, and CLI usage are
documented in `docs/REACHABILITY_ANALYSIS.md`.
DAST authorization, acknowledgements, limits, authentication handling, and CLI
usage are documented in `docs/DAST_SAFETY.md`.
Contextual outcomes, evidence strength, reproducibility, and CLI usage are
documented in `docs/DECISION_SCORING.md`.
Policy authoring, inheritance, simulation, explanation, and test commands are
documented in `docs/POLICY_AS_CODE.md`.
SARIF mapping, validation, GitHub permissions, and fork behavior are documented
in `docs/SARIF.md`.
GitHub Check summaries and branch-protection configuration are documented in
`docs/GITHUB_CHECKS.md`.
Consolidated pull-request comments and their publication boundary are
documented in `docs/PR_COMMENTS.md`.

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

Generate validated SARIF for GitHub code scanning or another SARIF consumer:

```bash
trustgate sarif \
  --input reports/findings.json \
  --output reports/trustgate.sarif
```

Generate both standard product SBOM formats from an immutable release tag:

```bash
trustgate sbom \
  --repository . \
  --ref v0.1.0 \
  --tag v0.1.0 \
  --output-directory reports/sbom
```

Generate and optionally sign an approved CycloneDX VEX document:

```bash
trustgate vex \
  --input reports/reachability.json \
  --analyses vex-analyses.json \
  --output reports/trustgate.vex.cdx.json \
  --sign
```

Generate and verify a content-addressed audit-evidence manifest:

```bash
trustgate evidence generate \
  --root . \
  --config audit-evidence.json \
  --output reports/audit-evidence.json
trustgate evidence verify \
  --root . \
  --manifest reports/audit-evidence.json
```

List, apply, and roll back supported deterministic remediations:

```bash
trustgate remediate rules --output reports/remediation-rules.json
trustgate remediate guide \
  --input reports/findings.json \
  --guidance remediation-guidance.json \
  --output reports/remediation-guidance.json
trustgate remediate apply \
  --root . \
  --plan remediation-plan.json \
  --receipt reports/remediation-receipt.json
trustgate remediate rollback \
  --root . \
  --receipt reports/remediation-receipt.json

# Preview first; this command does not contact a model.
trustgate remediate ai-context \
  --root . \
  --input reports/findings.json \
  --request ai-context-request.json \
  --output reports/ai-remediation-context.json
```

Generate the bounded Markdown shown directly on a GitHub Actions Check Run:

```bash
trustgate checks \
  --input reports/findings.json \
  --policy-result reports/policy-result.json \
  --output reports/check-summary.md
```

Generate the bounded Markdown for one consolidated pull-request comment:

```bash
trustgate pr-comment \
  --input reports/findings.json \
  --policy-result reports/policy-result.json \
  --repository owner/repository \
  --commit "$GITHUB_SHA" \
  --output reports/pr-comment.md
```

Generate a product report without research benchmark metrics:

```bash
trustgate report \
  --input reports/findings.json \
  --output reports/dashboard.html \
  --no-benchmark-ground-truth
```

Enrich an existing scan without sending source code:

```bash
trustgate enrich \
  --input reports/findings.json \
  --output reports/enriched-findings.json \
  --network-mode metadata-only
```

Analyze dependency, Python data-flow, and optional runtime evidence:

```bash
trustgate reachability \
  --input reports/findings.json \
  --output reports/reachability.json \
  --repository-root . \
  --vulnerable-symbols vulnerable-symbols.json \
  --deployment-inventory deployment.json
```

Generate a safe, bounded DAST plan without executing it:

```bash
trustgate dast \
  --target-url https://pr-123.preview.example.test \
  --environment preview \
  --scope-host pr-123.preview.example.test \
  --public-target-acknowledged
```

Evaluate findings with explicit deployment context and a versioned policy:

```bash
trustgate decide \
  --input reports/reachability.json \
  --runtime-context deployment-context.json \
  --output reports/decisions.json
```

Validate and test a JSON or YAML policy against saved findings:

```bash
trustgate policy validate --policy policies/service.policy.yml
trustgate policy validate --policy pack:startup-baseline
trustgate policy test \
  --policy policies/service.policy.yml \
  --input reports/findings.json \
  --expectations policies/service.expectations.json
```

Create, compare, and gate against a default-branch finding baseline:

```bash
trustgate baseline create \
  --input reports/default-branch-findings.json \
  --output reports/baseline.json \
  --default-branch main
trustgate baseline compare \
  --baseline reports/baseline.json \
  --input reports/pull-request-findings.json \
  --output reports/baseline-diff.json
trustgate baseline gate \
  --baseline reports/baseline.json \
  --input reports/pull-request-findings.json \
  --output reports/baseline-gate.json \
  --gate-mode new \
  --fail-on high
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
    name: Trust Gate
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
| `dast-enabled` | `false` | Opt into bounded ZAP execution; see the DAST safety guide for the related target, mode, scope, limit, authentication, and acknowledgement inputs |
| `license-key` | empty | Optional key for the experimental proprietary scoring layer |

### Action outputs

| Output | Description |
|---|---|
| `findings-path` | Path to the validated canonical scan-run JSON |
| `policy-result-path` | Path to the validated policy-result JSON |
| `sarif-path` | Path to the validated SARIF 2.1.0 output |
| `check-summary-path` | Path to the bounded Markdown published on the Check Run |
| `pr-comment-path` | Path to the concise Markdown for a consolidated PR comment |

The current Action supports one invocation per job because its dashboard artifact
name is fixed.

## Privacy and network behaviour

Customer source is scanned in the caller's CI workspace. Trust Gate does not
implement a source-code upload service. However, the current workflow downloads
Actions, Python packages, container images, and Semgrep rules. The generated
dashboard also references Google Fonts unless opened offline with that request
blocked.

Threat enrichment defaults to `metadata-only`, which sends only existing
advisory IDs. `disabled` makes no threat-feed requests; `full` may additionally
send dependency ecosystem, name, version, and PURL to OSV. Source paths,
excerpts, and repository content are never sent. See
[docs/THREAT_INTELLIGENCE.md](docs/THREAT_INTELLIGENCE.md).

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

<!-- trustgate:benchmark-metrics:start -->
> Generated from the versioned benchmark manifest. Do not edit this block.

| Tool | Precision | Recall | F1 | Posterior precision | 95% credible interval | Conservative bound | Maturity | n |
|---|---:|---:|---:|---:|---:|---:|---|---:|
| Bandit | 0.714 | 0.800 | 0.755 | 0.667 | 0.349–0.915 | 0.349 | Directional | 7 |
| Semgrep | 0.875 | 0.800 | 0.836 | 0.800 | 0.518–0.972 | 0.518 | Directional | 8 |

Methodology `1.0.0` uses a Beta(1, 1) prior. Displayed confidence is the posterior mean; decisions use the 95% lower credible bound.
4 byte-identical repeat run(s) are retained for provenance but excluded as independent statistical samples.
<!-- trustgate:benchmark-metrics:end -->

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
- [Benchmark methodology](docs/BENCHMARK_METHODOLOGY.md)
- [Multilingual benchmark corpus](docs/MULTILINGUAL_BENCHMARK.md)
- [Benchmark labelling and partitions](docs/BENCHMARK_LABELLING.md)
- [Confidence methodology](docs/CONFIDENCE_METHODOLOGY.md)
- [Threat-intelligence enrichment](docs/THREAT_INTELLIGENCE.md)
- [Reachability analysis](docs/REACHABILITY_ANALYSIS.md)
- [DAST safety](docs/DAST_SAFETY.md)
- [Contextual decision scoring](docs/DECISION_SCORING.md)
- [Policy as code](docs/POLICY_AS_CODE.md)
- [Baseline and differential comparison](docs/BASELINES.md)
- [Finding lifecycle](docs/FINDING_LIFECYCLE.md)
- [Software bills of materials](docs/SBOM.md)
- [Vulnerability Exploitability eXchange](docs/VEX.md)
- [Audit evidence](docs/AUDIT_EVIDENCE.md)
- [Deterministic remediation](docs/DETERMINISTIC_REMEDIATION.md)
- [Guided remediation](docs/GUIDED_REMEDIATION.md)
- [AI-assisted remediation](docs/AI_REMEDIATION.md)
- [Implementation roadmap status](docs/ROADMAP_STATUS.md)
- [Migration guide](docs/MIGRATION.md)
- [Versioning policy](docs/VERSIONING.md)
- [Research methodology](docs/research/README.md)
- [Repository audit](docs/audits/REPOSITORY_AUDIT.md)

## Licensing

The community package and core scanning/aggregation code are MIT licensed. The
confidence-scoring source under `src/trustgate/scoring/`,
`scripts/build_confidence_table.py`, and the generated
`benchmarks/reports/flask-vulnerable-v1.confidence.json` artifact are
source-available under [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL) and are excluded
from the community wheel.

Commercial terms require legal review before production reliance.
