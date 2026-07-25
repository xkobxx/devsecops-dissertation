# Repository Audit

Audit date: 2026-07-24
Audited commit: `a780add`
Roadmap scope: Phase 0.1

## Executive summary

The repository is a Python-first security scanning prototype with three overlapping
identities:

1. a reusable composite GitHub Action (`action.yml`);
2. the dissertation/research pipeline and its committed experiment outputs; and
3. an undeployed commercial licence-issuance sketch (`webhook/`).

The core product path is not yet reliable enough to make a trustworthy clean-scan
claim. The most important confirmed defect is fail-open aggregation: when all five
expected scanner reports are absent, `scripts/aggregate_results.py` writes zero
findings, prints `Security gate passed.`, and exits successfully. The current
workflow and Action make this likely by suppressing scanner failures and not
validating report production.

Other foundational gaps are:

- there are no automated tests;
- production logic is a set of working-directory-dependent scripts rather than an
  installable `trustgate` package;
- dependencies, scanner images, and most Actions are not immutably pinned;
- scanner execution has no shared health model, timeout model, or parser status;
- benchmark confidence labels can be "High" with a sample size of one;
- product, research, generated artefacts, and commercial code are intermingled;
- documentation makes broader reliability claims than the implementation supports.

## Scope and method

The audit covered all 59 tracked files, all repository directories, and relevant
ignored files present in the working tree. Checks included:

- source and configuration review;
- import and dependency extraction;
- JSON parsing of every repository JSON file;
- Python byte-compilation;
- test discovery;
- content hashes for repeated benchmark runs;
- a controlled aggregation run with no scanner reports;
- GitHub Action, container image, and external-service enumeration.

Ignored AI-assistant configuration under `.agent/`, `.claude/`, and `commands/` is
developer tooling, not part of the product. `RTK.md`, referenced by the supplied
repository instructions, was not present and could not be audited.

The roadmap PDF is currently an untracked planning input. Temporary rendered PDF
pages under `tmp/` are audit working files and are not product assets.

## Repository directory inventory

| Directory | Current purpose | Classification | Disposition |
|---|---|---|---|
| `.github/workflows/` | Dogfood scanning, gate, dashboard publication, PR comment | Production CI | Retain, split scanning from publishing, harden |
| `.zap/` | ZAP rule configuration | Research/DAST config | Retain after validating the empty rules file |
| `docs/` | Product, development, research docs and screenshots | Mixed | Split product docs from `docs/research/` |
| `reports/` | Committed scanner output, dashboard and charts | Generated/research | Move representative data to test fixtures; stop treating as live product state |
| `results/` | Experiment corpus and calculated metrics | Research | Move to versioned `benchmarks/` and `docs/research/` |
| `scripts/` | Aggregation, reporting, scoring, research and licensing logic | Mixed production/research/commercial | Migrate reusable logic to `src/trustgate/`; retain thin wrappers |
| `test_app/` | Deliberately vulnerable Flask benchmark fixture | Research fixture | Move under benchmark fixtures; never scan as product code |
| `webhook/` | Undeployed Stripe/Resend licence issuance sketch | Commercial operations | Separate from security decision engine and deployment |
| `.agent/`, `.claude/`, `commands/` | Ignored local agent configuration | Developer-local | Exclude from releases |
| `tmp/` | PDF extraction and audit working data | Temporary | Exclude from releases |

## Production and operational file inventory

| File | Purpose | Ownership | Key audit result |
|---|---|---|---|
| `action.yml` | Reusable composite Action | Open-source core, except invoked paid scoring | Product entry point; suppresses scanner failures and lacks input path validation |
| `.github/workflows/devsecops.yml` | Repository dogfood CI, research DAST, gate and Pages publication | Open source | Duplicates Action orchestration; broad permissions; almost all Actions use mutable tags |
| `pyproject.toml` | Minimal package metadata and Vercel entrypoint | Open source | Product is named `devsecops-dissertation`; no build backend, package discovery, CLI, or test config |
| `requirements.txt` | Python libraries for charts and licensing | Mixed | Exact versions but no hashes; does not describe scanner or Flask runtime completely |
| `docker-compose.yml` | Local vulnerable DAST applications | Research | All images use mutable tags or implicit `latest`; not wired into product flow |
| `.zap/rules.tsv` | ZAP rule overrides | Research | Empty file supplied to ZAP; behaviour is not tested |
| `scripts/aggregate_results.py` | Parses five scanner reports and applies severity gate | Open-source core | Missing reports become empty findings; no health/schema validation; dependency and secret findings forced to `HIGH` |
| `scripts/generate_report.py` | Generates static HTML dashboard | Open-source core | Runs at import time, uses fixed cwd paths, loads Google Fonts, and calculates invalid accuracy metrics |
| `scripts/verify_license.py` | Offline Ed25519 licence verification | Open-source licensing support | Broad exception handling; public key is embedded; invalid licence safely prevents paid scoring |
| `scripts/score_findings.py` | Adds confidence scores and tiers | Proprietary | Overwrites normalised findings; labels `n=1` precision as High; no intervals or conservative bound |
| `scripts/build_confidence_table.py` | Builds confidence lookup from one run | Proprietary | Uses proximity-only matching and one six-vulnerability fixture |
| `scripts/issue_license.py` | Generates signing key and customer licences | Seller-side commercial operations | Uses cwd-relative unencrypted private-key file; no rotation or revocation |
| `webhook/api/stripe-webhook.js` | Handles Stripe invoices and emails signed licences | Commercial operations sketch | Not deployed or tested; external Stripe and Resend trust boundaries; private signing key leaves local machine |
| `webhook/package.json` | Webhook package metadata | Commercial operations sketch | `stripe` uses a caret range and there is no lockfile |
| `webhook/README.md` | Webhook deployment notes | Documentation | Correctly labels the webhook as an undeployed sketch |

## Research and benchmark file inventory

| File | Purpose | Audit result |
|---|---|---|
| `test_app/app.py` | Flask app with six deliberate vulnerabilities | Fixture only; must be isolated from product source |
| `test_app/requirements.txt` | Fixture dependency set | Exact pins, but intentionally/incidentally old packages require fixture labelling |
| `test_app/seeded_vulnerabilities.json` | Six-item SAST ground truth | Used by current confidence and metric scripts |
| `scripts/calculate_metrics.py` | Calculates metrics over five runs | Skips missing runs; proximity-only matching; repeated runs make the interval misleadingly zero |
| `scripts/record_run.py` | Appends experiment metrics | No current workflow/docs caller; uses a different line tolerance and legacy log shape |
| `scripts/visualise_results.py` | Produces four charts | Charts are generated from hard-coded values, not `metrics_summary.json`; `json` and `matplotlib.patches` imports are unused |
| `results/experiment_log.json` | Structured experiment log | Research artefact; four scenario collections |
| `results/experiment_log.md` | Human-readable experiment log | Research artefact; duplicates JSON narrative |
| `results/ground_truth.json` | Multi-application ground truth | Not referenced by current scripts, which use `test_app/seeded_vulnerabilities.json` |
| `results/metrics_summary.json` | Calculated Bandit/Semgrep metrics | Generated research result |
| `results/run_1/findings.json` through `run_5/findings.json` | Five experiment runs | All five files are byte-for-byte identical, so they are repeats rather than independent observations |
| `confidence_table.json` | Generated confidence lookup | Proprietary; fourteen rules, nearly all with sample size one |

## Generated report and visual asset inventory

The following are committed outputs, not production source:

- raw scanner reports: `reports/bandit_report.json`,
  `reports/semgrep_report.json`, `reports/pip_audit_report.json`,
  `reports/trivy_report.json`, and `reports/gitleaks_report.json`;
- normalised output and dashboard: `reports/findings.json` and
  `reports/dashboard.html`;
- generated research charts: `reports/charts/chart1_precision_recall_f1.png`,
  `chart2_confusion_matrices.png`, `chart3_per_vuln_detection.png`, and
  `chart4_false_positives.png`;
- product/research screenshots: `docs/screenshots/clickup-project-board.png`,
  `clickup-task-list.png`, `dashboard-detection-rate.png.png`,
  `dashboard-findings-table.png.png`, `dashboard-summary.png.png`,
  `full-pipeline-diagram.png`,
  `poc/Screenshot 2026-05-10 at 3.21.58 am.png`,
  `poc/poc-cmdi-server-output.png`, `poc/poc-sqli.png`, and
  `poc/poc-sqliold.png`.

Representative reports will be useful as parser fixtures, but they should be
copied into explicit, immutable test-fixture directories with provenance and
redaction notes. Generated dashboards and experiment charts should be produced
by CI rather than treated as source.

## Documentation, repository policy, and licensing inventory

| File | Purpose | Audit result |
|---|---|---|
| `README.md` | Public product page and installation guide | Product-first, but claims a trustworthy all-scanner gate despite fail-open execution; uses mutable Action references in examples |
| `docs/ARCHITECTURE.md` | Current architecture and component map | Describes scanners as "best-effort"; version table conflicts with observed reports and unpinned installs |
| `docs/DEVELOPMENT.md` | Local execution guide | Uses unpinned scanner installs and `latest` Gitleaks; says DAST feeds the gate although ZAP is not parsed or required by it |
| `docs/RESEARCH.md` | Method and limitations | Discloses tiny samples and proximity matching, but the paid product still labels tiny samples High |
| `LICENSE` | MIT terms for the core | Excludes the three named proprietary files |
| `LICENSE-COMMERCIAL` | Source-available commercial terms | Covers only `score_findings.py`, `build_confidence_table.py`, and `confidence_table.json`; legal review is explicitly outstanding |
| `.gitignore` | Excludes caches, databases, secrets and local tooling | Correctly ignores the private signing key, but does not currently exclude `tmp/` |

## Workspace-only and sensitive files

- `license_signing_key.pem` is ignored, mode `0700`, and contains a private
  signing key. It must never be read into logs, committed, packaged, or copied
  except through an explicit key-management procedure.
- `test_app/users.db` is ignored and is currently a one-byte local fixture.
- `scripts/__pycache__/` and other bytecode are ignored build artefacts.
- AppleDouble files (`._*`) are ignored filesystem metadata.
- Local agent skills and settings are ignored and are not release inputs.

## Dead, duplicated, and obsolete candidates

These are candidates for migration or removal, not deletion decisions:

1. `scripts/record_run.py` has no documented or workflow caller and uses a
   different matching tolerance from the active benchmark scripts.
2. `results/ground_truth.json` is not consumed by current metric or confidence
   code; the active ground truth is `test_app/seeded_vulnerabilities.json`.
3. The five `results/run_*` files are byte-identical and do not represent
   independent statistical samples.
4. `scripts/visualise_results.py` duplicates metrics as hard-coded constants.
5. `.github/workflows/devsecops.yml` duplicates much of `action.yml`, with
   different scanner pins and behaviour.
6. The ZAP job produces a report that `security-gate` neither downloads nor
   parses and is not listed in the gate's `needs`.
7. Committed reports and dashboards are generated outputs that overlap CI
   artefacts.

## Current product limitations

- Python-only SAST rules and `requirements.txt`-only dependency discovery.
- No repository context detection or explicit scan plan.
- No scanner applicability, timeout, cancellation, partial, or health states.
- Missing reports and many scanner failures can produce false-clean results.
- No normalised schema, stable fingerprints, deduplication, correlation, SARIF,
  SBOM, VEX, policy-as-code, baseline, suppression, or finding lifecycle.
- Severity mappings are lossy and sometimes hard-coded.
- Confidence methodology is statistically insufficient for gating.
- Reports depend on fixed relative paths and are not packaged as a CLI.
- No tests, coverage, release verification, signed artefacts, or provenance.
- PR feedback links to the latest `main` dashboard rather than publishing the
  current PR's findings.
- The Action always runs the same scanners and cannot truthfully claim support
  for arbitrary repositories.
- The HTML dashboard makes network requests to Google Fonts when opened.
- The webhook is a sketch without deployment, persistence, automated tests,
  rotation, or revocation.

## Positive findings to preserve

- Raw scanner reports are written separately from `findings.json`.
- The Action passes attacker-influenceable `target` and `fail-on` values through
  environment variables rather than interpolating them directly into shell.
- The reusable Action pins Trivy to a commit SHA and records the readable
  version beside it.
- HTML scanner-controlled fields are escaped before rendering.
- Licence verification is local and independently rechecked by the paid script.
- The research document explicitly discloses tiny samples and matching limits.
- The deliberately vulnerable fixture is clearly labelled in several places.

## Audited tracked-file manifest

This is the complete 59-file manifest at audited commit `a780add`:

```text
.github/workflows/devsecops.yml
.gitignore
.zap/rules.tsv
LICENSE
LICENSE-COMMERCIAL
README.md
action.yml
confidence_table.json
docker-compose.yml
docs/ARCHITECTURE.md
docs/DEVELOPMENT.md
docs/RESEARCH.md
docs/screenshots/clickup-project-board.png
docs/screenshots/clickup-task-list.png
docs/screenshots/dashboard-detection-rate.png.png
docs/screenshots/dashboard-findings-table.png.png
docs/screenshots/dashboard-summary.png.png
docs/screenshots/full-pipeline-diagram.png
docs/screenshots/poc/Screenshot 2026-05-10 at 3.21.58 am.png
docs/screenshots/poc/poc-cmdi-server-output.png
docs/screenshots/poc/poc-sqli.png
docs/screenshots/poc/poc-sqliold.png
pyproject.toml
reports/bandit_report.json
reports/charts/chart1_precision_recall_f1.png
reports/charts/chart2_confusion_matrices.png
reports/charts/chart3_per_vuln_detection.png
reports/charts/chart4_false_positives.png
reports/dashboard.html
reports/findings.json
reports/gitleaks_report.json
reports/pip_audit_report.json
reports/semgrep_report.json
reports/trivy_report.json
requirements.txt
results/experiment_log.json
results/experiment_log.md
results/ground_truth.json
results/metrics_summary.json
results/run_1/findings.json
results/run_2/findings.json
results/run_3/findings.json
results/run_4/findings.json
results/run_5/findings.json
scripts/aggregate_results.py
scripts/build_confidence_table.py
scripts/calculate_metrics.py
scripts/generate_report.py
scripts/issue_license.py
scripts/record_run.py
scripts/score_findings.py
scripts/verify_license.py
scripts/visualise_results.py
test_app/app.py
test_app/requirements.txt
test_app/seeded_vulnerabilities.json
webhook/README.md
webhook/api/stripe-webhook.js
webhook/package.json
```

## Phase 0.1 completion assessment

- [x] Every tracked production and operational file is accounted for.
- [x] Every current scanner dependency is inventoried.
- [x] Current data flows and trust boundaries are documented.
- [x] Every identified fail-open behaviour is registered.
- [x] Existing test assets and test gaps are documented.
- [x] Proprietary, open-source, generated, research, and local-only material are distinguished.
- [x] Current product limitations are documented.

This completes the audit deliverables, not the remediation. The first Phase 1
implementation should introduce scanner execution health states and make missing
required reports fail closed.
