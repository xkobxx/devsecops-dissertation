# Architecture

## How It Works

Scanner integrations live under `src/trustgate/adapters/`. The typed
`ScannerAdapter` lifecycle owns applicability, preparation, command execution,
health validation, native parsing, normalization, fingerprinting, and cleanup.
`AdapterRegistry` loads built-ins and the `trustgate.adapters` entry-point group;
discovery and parser failures are isolated per adapter.

Before execution, `trustgate.repository` creates a deterministic local inventory
of technologies, manifests, dependencies, infrastructure, generated paths,
vendored paths, and monorepo packages. `trustgate.planning` converts that
inventory and the adapter registry into explainable scanner decisions with
per-package targets, outputs, timeouts, override provenance, and privacy
declarations. See [SCAN_PLANNING.md](SCAN_PLANNING.md).

After parsing, `trustgate.correlation` deduplicates exact same-scanner repeats,
then performs conservative complete-link clustering across independent adapters.
It preserves every location, source finding ID, evidence object, and raw report.
Rule ancestry prevents dependent scanners from being double counted, while DAST
and human confirmation remain distinct. See
[CORRELATION.md](CORRELATION.md).

`trustgate.threat_intelligence` then adds cache-backed OSV, GitHub advisory,
NVD, EPSS, and CISA KEV evidence. Network access is explicitly disabled,
identifier-only, or full dependency-metadata mode; source code is never sent.
Every finding retains feed failures, expiry, staleness, disclosure metadata, and
the invariant that threat feeds are not complete risk context. Scan summaries
and policy results surface stale threat data. See
[THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md).

`trustgate.reachability` next adds local, conservative execution context. It
classifies dependency installation, relationship, scope, imports, configured
vulnerable-symbol calls, and deployment inclusion; builds bounded Python
source-to-sink traces across files and framework routes; and correlates optional
runtime observations. Missing evidence remains incomplete, and no static path is
ever treated as proof of non-exploitability. See
[REACHABILITY_ANALYSIS.md](REACHABILITY_ANALYSIS.md).

`trustgate.dast` validates an explicit target and hostname allowlist, publishes
a ZAP Automation Framework plan, and optionally executes it through a
digest-pinned container. A sender gate enforces outbound scope, request count,
rate, and environment-referenced authentication. Safe plans omit active scans;
public, active, private, and production behavior each requires the applicable
explicit acknowledgement. See [DAST_SAFETY.md](DAST_SAFETY.md).

`trustgate.decisions` captures 16 explicit context components and evaluates an
ordered, versioned policy into one of nine outcomes. It stores every component,
the full policy snapshot, the matched rule, all rule evaluations, evidence
strength, and unresolved uncertainty. A canonical digest makes the decision
deterministic and detects changes during reproduction. See
[DECISION_SCORING.md](DECISION_SCORING.md).

`trustgate.policy` exposes the public JSON/YAML policy contract over 17 typed
finding and runtime predicates. It safely loads an exact-version inheritance
graph, applies organisation defaults and repository-specific overrides, and
performs deterministic first-match evaluation. Validation, saved-scan
simulation, per-finding explanation, and expectation tests are available under
`trustgate policy`; invalid rules cannot become successful evaluations. See
[POLICY_AS_CODE.md](POLICY_AS_CODE.md).
Ten package-data policy packs provide versioned, documented, tested starting
points. The loader resolves `pack:<name>` aliases inside the installed resource
boundary, so callers do not depend on checkout-relative paths.

`trustgate.baselines` creates a content-bound snapshot from a declared
default-branch scan, indexing complete findings and scanner records by their
canonical identities. Pull-request comparison verifies that snapshot before
classifying fingerprint additions, removals, severity increases, reachability
and exploitation transitions, expired suppressions, and scanner coverage loss.
Differential gates then apply `new`, `worsened`, `all`, or public-policy
enforcement, defaulting to new risk while always failing on scanner coverage
regressions. All three documents are schema validated and carry canonical
digests. See [BASELINES.md](BASELINES.md).

`trustgate.lifecycle` applies immutable state transitions to canonical findings.
Each transition carries its actor, timestamp, reason, evidence, approval,
expiry, and automatic/manual provenance. It validates chronological and state
continuity before returning a new schema-valid finding, and automatically
reopens an expired current state with an auditable system transition.
Content-bound suppression records add exact fingerprint and repository scope,
optional branch/path/environment selectors, linting, and risk-context
revalidation before application and throughout the suppression lifetime. See
[FINDING_LIFECYCLE.md](FINDING_LIFECYCLE.md).

`trustgate.sarif` projects the validated canonical scan run into deterministic
SARIF 2.1.0. Rules retain security metadata and remediation; results retain
severity, precise repository-relative locations when available, and both full
and line-stable partial fingerprints. A separate write-capable workflow job
uploads the artifact without checking out or executing repository code. See
[SARIF.md](SARIF.md).

`trustgate.checks` binds the scan, policy result, and optional differential
baseline documents into a bounded Markdown view on the native GitHub Actions
Check Run. It escapes untrusted Markdown, omits raw evidence and source
expressions, and exposes the same release decision enforced by the stable
`Trust Gate` job. See [GITHUB_CHECKS.md](GITHUB_CHECKS.md).

`trustgate.comments` produces a separate concise, collapsed PR view. It emits
only identifiers, classifications, severities, rules, safe code links, and
remediation availability; source, evidence, and remediation excerpts are not
included. A checkout-free job with narrowly scoped write permission upserts
the marker-bearing bot comment. See [PR_COMMENTS.md](PR_COMMENTS.md).

`trustgate.supply_chain` generates deterministic CycloneDX 1.6 and SPDX 2.3
product SBOMs from an immutable Git commit. It reconciles direct requirements
with the full hash-locked dependency graph and an exact-version licence
inventory, then emits versions, Package URLs, distribution hashes, and
dependency relationships in both standards. Invalid or incomplete source data
fails before publication. See [SBOM.md](SBOM.md).

`trustgate.vex` consumes a canonical scan run and an explicit, versioned set of
approved analyses. It verifies the scan content binding, vulnerability and
component identity, reachability evidence, approval chronology, and consistent
exploitability/analysis states before emitting CycloneDX 1.6 VEX. Evidence and
approvals are linked by canonical digest without exposing approver identity in
the public artifact. The CLI can create a keyless Sigstore bundle. See
[VEX.md](VEX.md).

The central `trustgate.aggregation` package contains no scanner-specific parser
implementation. It resolves the catalogue and invokes adapters, retaining
compatibility exports for the original parser function names. See
[ADAPTER_SDK.md](ADAPTER_SDK.md) for the extension contract and
[SCANNER_COMPATIBILITY.md](SCANNER_COMPATIBILITY.md) for applicability.

```
checkout → Bandit/Semgrep/pip-audit/Trivy/Gitleaks (health-aware execution)
         → aggregate_results.py   validates adapters, enriches reachability, and publishes canonical scan-run/policy JSON
         → trustgate policy       validates, simulates, explains, and tests release policy
         → trustgate baseline     snapshots, compares, and gates pull-request risk
         → trustgate decide       evaluates contextual policy and persists reproducible decisions
         → verify_license.py      offline signature check, no server call
         → score_findings.py      (paid only) scores and revalidates the canonical scan run
         → trustgate sarif        → validated trustgate.sarif, uploaded by an isolated job
         → trustgate checks       → bounded release-decision summary on the Check Run
         → trustgate pr-comment   → bounded artifact upserted into one bot-owned PR comment
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
| ZAP stable container | `sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2` |

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
│   ├── baselines/                   # Default-branch snapshots and differential comparison
│   ├── cli/                         # Product command-line interface
│   ├── checks/                      # Bounded GitHub Check summary generation
│   ├── comments/                    # Safe consolidated PR comment generation
│   ├── confidence.py                # Separate non-circular confidence concepts
│   ├── correlation/                 # Deduplication and evidence corroboration
│   ├── dast/                        # Bounded ZAP planning and execution
│   ├── decisions/                   # Context snapshots, policies, outcomes, and reproduction
│   ├── licensing/                   # Offline licence verification and seller tooling
│   ├── lifecycle/                   # Auditable finding states and automatic reopening
│   ├── planning/                    # Deterministic, explainable scan plans
│   ├── policy/                      # Public policy schema, resolution, evaluation, and tooling
│   ├── reporting/                   # Static dashboard generation
│   ├── repository/                  # Technology and monorepo context detection
│   ├── reachability/                # Dependency, Python data-flow, and runtime correlation
│   ├── schema/                      # Schema validation, builders and migrations
│   ├── sarif/                       # Deterministic SARIF mapping and validation
│   ├── security/                    # Workflow input, path and URL validation
│   ├── threat_intelligence/         # Privacy-aware advisory clients and local cache
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
Threat-feed data handling and cache expiry are specified in
`docs/THREAT_INTELLIGENCE.md`.
Reachability evidence and conservative status semantics are specified in
`docs/REACHABILITY_ANALYSIS.md`.
