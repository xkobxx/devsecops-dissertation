# Trust Gate implementation roadmap status

Source of truth: `Trust Gate Product Implementation Roadmap.pdf` (43 pages).

Last updated: 2026-08-15 on branch `main`.

## Status summary

- Explicit PDF checkbox items: **998**
- Validated complete: **982**
- Remaining explicit checkbox items: **16** (all blocked on external human reviewers)
- Derived final architecture/verification checks: **34** (all complete)
- Current work: **All automatable items complete. Remaining 16 items require human reviewers (Phase 17.2: 2 items, Phase 26.2: 13 items, independent security review: 1 item).**

Only validation-backed work is checked. Existing files or partial implementations are not marked complete merely because they resemble a deliverable.

## Active implementation queue

1. Obtain two genuine independent reviews for every development-public case (Phase 17.2 — blocked on human reviewers).
2. Arrange independent external reviews (Phase 26.2 — blocked on external reviewers).
3. Independent security review (acceptance criteria — blocked on external reviewer).

## Complete ordered checklist

## Phase 0 - Repository audit and project preparation

### 0.1 Create a full repository inventory

- [x] Inspect every repository file and directory. _(PDF p. 2)_
- [x] Record the purpose of every script, workflow and configuration file. _(PDF p. 2)_
- [x] Identify dead code, duplicated workflows and obsolete research artefacts. _(PDF p. 2)_
- [x] Identify proprietary and open-source components. _(PDF p. 2)_
- [x] Identify all external dependencies and GitHub Actions. _(PDF p. 2)_
- [x] Identify all current data flows. _(PDF p. 2)_
- [x] Identify all places where errors are ignored. _(PDF p. 2)_
- [x] Identify all current security assumptions. _(PDF p. 2)_
- [x] Identify all existing tests and test gaps. _(PDF p. 2)_
- [x] docs/audits/REPOSITORY_AUDIT.md _(PDF p. 2)_
- [x] docs/audits/DEPENDENCY_INVENTORY.md _(PDF p. 2)_
- [x] docs/audits/DATA_FLOW_AUDIT.md _(PDF p. 2)_
- [x] docs/audits/TEST_GAP_ANALYSIS.md _(PDF p. 2)_
- [x] Every production file is accounted for. _(PDF p. 2)_
- [x] Every scanner dependency is documented. _(PDF p. 2)_
- [x] Every fail-open behaviour is documented. _(PDF p. 2)_
- [x] Every current product limitation is documented. _(PDF p. 2)_

### 0.2 Establish the target repository structure

- [x] Move reusable production logic into src/trustgate/. _(PDF p. 3)_
- [x] Keep thin wrapper scripts only where required. _(PDF p. 3)_
- [x] Separate benchmark fixtures from production code. _(PDF p. 3)_
- [x] Separate licensing logic from security-scoring logic. _(PDF p. 3)_
- [x] Ensure package imports work from any working directory. _(PDF p. 3)_
- [x] Add a formal Python package configuration. _(PDF p. 3)_
- [x] Add a command-line entry point named trustgate. _(PDF p. 3)_
- [x] trustgate --help runs successfully. _(PDF p. 3)_
- [x] Existing Action functionality still works. _(PDF p. 3)_
- [x] No production module relies on hard-coded working-directory paths. _(PDF p. 3)_

### 0.3 Separate the research identity from the product identity

- [x] Choose the final product name. _(PDF p. 3)_
- [x] Rename the public-facing Action. _(PDF p. 3)_
- [x] Create a new product-focused README. _(PDF p. 3)_
- [x] Move dissertation-specific material into docs/research/. _(PDF p. 3)_
- [x] Clearly distinguish experimental results from production claims. _(PDF p. 3)_
- [x] Remove unsupported phrases such as “works on any repository.” _(PDF p. 3)_
- [x] Describe the current release accurately as Python-first until broader support is finished. _(PDF p. 3)_
- [x] Define semantic versioning rules. _(PDF p. 3)_
- [x] Add a migration notice for existing users. _(PDF p. 3)_
- [x] README.md _(PDF p. 4)_
- [x] docs/research/README.md _(PDF p. 4)_
- [x] docs/MIGRATION.md _(PDF p. 4)_
- [x] docs/VERSIONING.md _(PDF p. 4)_
- [x] CHANGELOG.md _(PDF p. 4)_
- [x] Product claims match actual functionality. _(PDF p. 4)_
- [x] Research findings cannot be confused with current production benchmarks. _(PDF p. 4)_
- [x] Existing users have documented migration steps. _(PDF p. 4)_

## Phase 1 - Build a secure and reliable foundation

### 1.1 Pin all dependencies

- [x] Pin Python dependencies to exact versions. _(PDF p. 4)_
- [x] Generate hashes for Python package installations. _(PDF p. 4)_
- [x] Replace floating Docker image tags with immutable digests. _(PDF p. 4)_
- [x] Pin third-party GitHub Actions to commit SHAs. _(PDF p. 4)_
- [x] Record the human-readable version beside each pinned SHA. _(PDF p. 4)_
- [x] Add automated dependency-update tooling. _(PDF p. 4)_
- [x] Add a scanner compatibility matrix. _(PDF p. 4)_
- [x] Add a process for testing dependency upgrades before release. _(PDF p. 4)_
- [x] requirements/runtime.lock _(PDF p. 4)_
- [x] requirements/development.lock _(PDF p. 4)_
- [x] requirements/scanners.lock _(PDF p. 4)_
- [x] docs/SCANNER_COMPATIBILITY.md _(PDF p. 4)_
- [x] No production dependency uses latest, master or an unbounded version. _(PDF p. 4)_
- [x] Every third-party Action is pinned to a commit SHA. _(PDF p. 4)_
- [x] A clean environment produces the same installed dependency versions. _(PDF p. 4)_

### 1.2 Implement scanner-health states

- [x] Create a common scanner execution result model. _(PDF p. 5)_
- [x] Record scanner start and end times. _(PDF p. 5)_
- [x] Record exit code. _(PDF p. 5)_
- [x] Record timeout status. _(PDF p. 5)_
- [x] Record whether the expected report was produced. _(PDF p. 5)_
- [x] Record parser status. _(PDF p. 5)_
- [x] Record scanner version. _(PDF p. 5)_
- [x] Record execution logs or log references. _(PDF p. 5)_
- [x] Stop treating missing reports as empty reports. _(PDF p. 5)_
- [x] Add configurable scanner timeouts. _(PDF p. 5)_
- [x] Add configurable scanner failure policy. _(PDF p. 5)_
- [x] A failed scanner cannot produce a “clean” gate. _(PDF p. 5)_
- [x] A missing report produces FAILED_SCANNER. _(PDF p. 5)_
- [x] A malformed report produces FAILED_SCANNER or PARTIAL. _(PDF p. 5)_
- [x] Required scanner failures block the build by default. _(PDF p. 5)_
- [x] Optional scanners can be configured separately. _(PDF p. 5)_

### 1.3 Replace broad `|| true` handling

- [x] Remove unconditional || true from scanner execution. _(PDF p. 5)_
- [x] Capture scanner exit codes explicitly. _(PDF p. 5)_
- [x] Distinguish “findings found” from “scanner crashed.” _(PDF p. 5)_
- [x] Interpret each scanner’s exit-code contract correctly. _(PDF p. 6)_
- [x] Add per-scanner execution wrappers. _(PDF p. 6)_
- [x] Store standard output and standard error separately where practical. _(PDF p. 6)_
- [x] Ensure scanner failures remain visible in GitHub Actions. _(PDF p. 6)_
- [x] Every scanner wrapper has unit tests for success, findings, failure and timeout. _(PDF p. 6)_
- [x] No scanner crash is converted into a zero-finding result. _(PDF p. 6)_

### 1.4 Harden workflow permissions

- [x] Apply least-privilege GitHub workflow permissions. _(PDF p. 6)_
- [x] Use read-only permissions unless write access is required. _(PDF p. 6)_
- [x] Separate publishing workflows from scanning workflows. _(PDF p. 6)_
- [x] Prevent untrusted pull-request code from accessing secrets. _(PDF p. 6)_
- [x] Review all pull_request_target usage. _(PDF p. 6)_
- [x] Prevent unsafe interpolation of user-controlled inputs. _(PDF p. 6)_
- [x] Validate all Action inputs. _(PDF p. 6)_
- [x] Reject path traversal outside the workspace. _(PDF p. 6)_
- [x] Reject command-injection payloads. _(PDF p. 6)_
- [x] Sanitize artifact names. _(PDF p. 6)_
- [x] Validate URLs before DAST use. _(PDF p. 6)_
- [x] docs/security/WORKFLOW_SECURITY.md _(PDF p. 6)_
- [x] docs/security/THREAT_MODEL.md _(PDF p. 6)_
- [x] Security tests cover malicious target, fail-on, URL and file-path inputs. _(PDF p. 6)_
- [x] Untrusted pull requests cannot access licence keys or publishing credentials. _(PDF p. 6)_
- [x] Workflow permissions pass an OpenSSF Scorecard review. _(PDF p. 6)_

### 1.5 Add signed releases and provenance

- [x] Produce versioned release archives. _(PDF p. 6)_
- [x] Generate release checksums. _(PDF p. 6)_
- [x] Sign release artefacts. _(PDF p. 6)_
- [x] Generate build provenance. _(PDF p. 6)_
- [x] Generate an SBOM for the product itself. _(PDF p. 6)_
- [x] Publish release attestations. _(PDF p. 6)_
- [x] Document verification commands for users. _(PDF p. 6)_
- [x] Add a release workflow requiring protected approval. _(PDF p. 6)_
- [x] Users can verify that an artefact came from the official repository. _(PDF p. 6)_
- [x] Users can verify which commit and workflow produced the release. _(PDF p. 7)_
- [x] Every release contains an SBOM. _(PDF p. 7)_

## Phase 2 - Create a canonical finding model

### 2.1 Define the finding schema

- [x] Create schemas/finding.schema.json. _(PDF p. 8)_
- [x] Create schemas/scan-run.schema.json. _(PDF p. 8)_
- [x] Create schemas/policy-result.schema.json. _(PDF p. 8)_
- [x] Create schema validation utilities. _(PDF p. 8)_
- [x] Version all schemas. _(PDF p. 8)_
- [x] Add backward-compatible migration functions. _(PDF p. 8)_
- [x] Validate all generated output before publishing. _(PDF p. 8)_
- [x] Every finding produced by every adapter validates against the schema. _(PDF p. 8)_
- [x] Invalid findings are reported as parser errors. _(PDF p. 8)_
- [x] Schema migrations have tests. _(PDF p. 8)_

### 2.2 Preserve original scanner data

- [x] Preserve original severity. _(PDF p. 8)_
- [x] Preserve original description. _(PDF p. 8)_
- [x] Preserve original identifiers. _(PDF p. 8)_
- [x] Preserve the original scanner report. _(PDF p. 8)_
- [x] Record normalisation transformations separately. _(PDF p. 8)_
- [x] Never discard raw evidence needed for audit. _(PDF p. 8)_
- [x] Add an optional redaction layer for sensitive content. _(PDF p. 8)_
- [x] Users can trace every normalised field to its original scanner output. _(PDF p. 8)_
- [x] Severity transformations are explainable. _(PDF p. 8)_

### 2.3 Correct severity normalisation

- [x] Stop assigning all dependency findings HIGH. _(PDF p. 8)_
- [x] Stop assigning all secrets HIGH. _(PDF p. 8)_
- [x] Read CVSS data where available. _(PDF p. 8)_
- [x] Preserve scanner-provided severity. _(PDF p. 8)_
- [x] Add source-specific severity mapping. _(PDF p. 8)_
- [x] Document every mapping rule. _(PDF p. 8)_
- [x] Add a confidence indicator for severity quality. _(PDF p. 8)_
- [x] Treat unknown severity as unknown, not low. _(PDF p. 8)_
- [x] Allow policy decisions based on original and normalised severity. _(PDF p. 8)_
- [x] Each scanner has a tested severity mapping. _(PDF p. 8)_
- [x] Dependency severity reflects available advisory data. _(PDF p. 8)_
- [x] Secret severity considers type and validation status. _(PDF p. 9)_

### 2.4 Implement stable finding fingerprints

- [x] Add versioned fingerprint algorithms. _(PDF p. 9)_
- [x] Keep fingerprints stable across line-number changes. _(PDF p. 9)_
- [x] Avoid merging unrelated findings. _(PDF p. 9)_
- [x] Support fingerprint migration. _(PDF p. 9)_
- [x] Add collision tests. _(PDF p. 9)_
- [x] Add repository-relative path normalisation. _(PDF p. 9)_
- [x] The same issue remains identifiable after nearby code changes. _(PDF p. 9)_
- [x] Duplicate reports from different scanners can be correlated. _(PDF p. 9)_
- [x] Fingerprint collisions are covered by tests. _(PDF p. 9)_

## Phase 3 - Repair the confidence and evidence methodology

### 3.1 Create one source of truth for benchmarks

- [x] Remove manually duplicated metrics. _(PDF p. 9)_
- [x] Generate README metrics from benchmark artefacts. _(PDF p. 9)_
- [x] Generate documentation tables automatically. _(PDF p. 9)_
- [x] Version every benchmark dataset. _(PDF p. 9)_
- [x] Version scanner configurations. _(PDF p. 9)_
- [x] Version scanner rules. _(PDF p. 9)_
- [x] Store benchmark run metadata. _(PDF p. 9)_
- [x] Store the exact commit used for each result. _(PDF p. 9)_
- [x] Store the calculation method. _(PDF p. 9)_
- [x] Prevent publication when metrics are inconsistent. _(PDF p. 10)_
- [x] README, dashboard and research documents use the same generated metrics. _(PDF p. 10)_
- [x] Contradictory precision figures cannot be released. _(PDF p. 10)_

### 3.2 Replace proximity-only ground-truth matching

- [x] Stop relying solely on plus-or-minus-five-line matching. _(PDF p. 10)_
- [x] Match by vulnerability ID where fixtures support it. _(PDF p. 10)_
- [x] Match by file and symbol. _(PDF p. 10)_
- [x] Match by CWE. _(PDF p. 10)_
- [x] Match by source and sink. _(PDF p. 10)_
- [x] Match by code-region hash. _(PDF p. 10)_
- [x] Support manual adjudication. _(PDF p. 10)_
- [x] Record the matching reason. _(PDF p. 10)_
- [x] Record ambiguous matches. _(PDF p. 10)_
- [x] Require review before ambiguous results affect published metrics. _(PDF p. 10)_
- [x] Dense files do not produce accidental true-positive matches. _(PDF p. 10)_
- [x] Every benchmark match is explainable. _(PDF p. 10)_
- [x] Ambiguous matches are excluded until adjudicated. _(PDF p. 10)_

### 3.3 Implement statistically valid confidence

- [x] Implement posterior precision calculation. _(PDF p. 11)_
- [x] Implement confidence or credible intervals. _(PDF p. 11)_
- [x] Add sample-size maturity levels. _(PDF p. 11)_
- [x] Prevent small samples from receiving high-confidence classification. _(PDF p. 11)_
- [x] Add calibration-quality indicators. _(PDF p. 11)_
- [x] Track false negatives as well as false positives. _(PDF p. 11)_
- [x] Calculate precision, recall, F1, Brier score and calibration error. _(PDF p. 11)_
- [x] Include methodology version in every score. _(PDF p. 11)_
- [x] A rule with one true positive and zero false positives is not labelled “high confidence.” _(PDF p. 11)_
- [x] Every score includes sample size and interval. _(PDF p. 11)_
- [x] Gate decisions use the conservative bound. _(PDF p. 11)_
- [x] Statistical tests cover edge cases. _(PDF p. 11)_

### 3.4 Separate confidence concepts

- [x] Define each confidence type. _(PDF p. 11)_
- [x] Define which evidence affects each type. _(PDF p. 11)_
- [x] Prevent circular calculations. _(PDF p. 11)_
- [x] Display each component in reports. _(PDF p. 11)_
- [x] Do not hide them behind one unexplained score. _(PDF p. 11)_
- [x] Users can see why a decision was made. _(PDF p. 12)_
- [x] Scanner reliability is not presented as exploitability probability. _(PDF p. 12)_

## Phase 4 - Build the scanner adapter system

### 4.1 Define the adapter interface

- [x] Implement a base adapter class. _(PDF p. 12)_
- [x] Add typed interfaces. _(PDF p. 12)_
- [x] Add adapter registration. _(PDF p. 12)_
- [x] Add adapter discovery. _(PDF p. 12)_
- [x] Add adapter configuration. _(PDF p. 12)_
- [x] Add adapter-level tests. _(PDF p. 12)_
- [x] Add adapter failure isolation. _(PDF p. 12)_
- [x] Add an adapter SDK guide. _(PDF p. 12)_
- [x] docs/ADAPTER_SDK.md _(PDF p. 13)_
- [x] A new scanner can be added without modifying the aggregator core. _(PDF p. 13)_
- [x] Broken adapters do not corrupt other results. _(PDF p. 13)_

### 4.2 Migrate existing scanners into adapters

- [x] Bandit _(PDF p. 13)_
- [x] Semgrep _(PDF p. 13)_
- [x] pip-audit _(PDF p. 13)_
- [x] Trivy _(PDF p. 13)_
- [x] Gitleaks _(PDF p. 13)_
- [x] OWASP ZAP _(PDF p. 13)_
- [x] Applicability detection _(PDF p. 13)_
- [x] Version detection _(PDF p. 13)_
- [x] Execution wrapper _(PDF p. 13)_
- [x] Timeout handling _(PDF p. 13)_
- [x] Health validation _(PDF p. 13)_
- [x] Parser _(PDF p. 13)_
- [x] Severity mapping _(PDF p. 13)_
- [x] Fingerprinting _(PDF p. 13)_
- [x] Test fixtures _(PDF p. 13)_
- [x] Error fixtures _(PDF p. 13)_
- [x] Malformed report fixtures _(PDF p. 13)_
- [x] All existing functionality uses adapters. _(PDF p. 13)_
- [x] No scanner-specific parsing remains inside the central aggregator. _(PDF p. 13)_

### 4.3 Add additional scanner integrations

- [x] OSV-Scanner _(PDF p. 13)_
- [x] Syft _(PDF p. 13)_
- [x] Grype _(PDF p. 13)_
- [x] Checkov or KICS _(PDF p. 13)_
- [x] Hadolint _(PDF p. 13)_
- [x] Gosec _(PDF p. 13)_
- [x] Brakeman _(PDF p. 14)_
- [x] SpotBugs or equivalent Java support _(PDF p. 14)_
- [x] JavaScript and TypeScript security scanning _(PDF p. 14)_
- [x] TruffleHog as an optional secret-validation source _(PDF p. 14)_
- [x] CodeQL SARIF import _(PDF p. 14)_
- [x] Each integration has documented applicability. _(PDF p. 14)_
- [x] Unsupported repositories do not run irrelevant scanners. _(PDF p. 14)_
- [x] New adapters pass the common adapter test suite. _(PDF p. 14)_

## Phase 5 - Add intelligent repository detection

### 5.1 Build repository context detection

- [x] Languages _(PDF p. 14)_
- [x] Frameworks _(PDF p. 14)_
- [x] Package managers _(PDF p. 14)_
- [x] Lock files _(PDF p. 14)_
- [x] Build systems _(PDF p. 14)_
- [x] Container files _(PDF p. 14)_
- [x] Kubernetes files _(PDF p. 14)_
- [x] Terraform files _(PDF p. 14)_
- [x] CloudFormation files _(PDF p. 14)_
- [x] OpenAPI specifications _(PDF p. 14)_
- [x] Test directories _(PDF p. 14)_
- [x] Generated files _(PDF p. 14)_
- [x] Vendored dependencies _(PDF p. 14)_
- [x] Monorepo packages _(PDF p. 14)_
- [x] Runtime and development dependencies _(PDF p. 14)_
- [x] The scan plan accurately explains why each scanner was selected. _(PDF p. 14)_
- [x] Generated and vendored files can be excluded safely. _(PDF p. 14)_
- [x] Monorepos generate per-package scan contexts. _(PDF p. 14)_

### 5.2 Generate an explicit scan plan

- [x] Add trustgate plan. _(PDF p. 15)_
- [x] Add --dry-run. _(PDF p. 15)_
- [x] Add JSON and human-readable output. _(PDF p. 15)_
- [x] Allow users to override automatic detection. _(PDF p. 15)_
- [x] Validate conflicting configuration. _(PDF p. 15)_
- [x] Users can inspect the complete scan plan before execution. _(PDF p. 15)_
- [x] Automatic decisions are transparent. _(PDF p. 15)_

## Phase 6 - Deduplicate and correlate findings

### 6.1 Implement exact deduplication

- [x] Merge repeated findings from the same scanner. _(PDF p. 15)_
- [x] Handle repeated locations. _(PDF p. 15)_
- [x] Preserve occurrence counts. _(PDF p. 15)_
- [x] Preserve all raw evidence references. _(PDF p. 15)_

### 6.2 Implement cross-scanner correlation

- [x] CWE _(PDF p. 15)_
- [x] File _(PDF p. 15)_
- [x] Symbol _(PDF p. 15)_
- [x] Source _(PDF p. 15)_
- [x] Sink _(PDF p. 15)_
- [x] Code region _(PDF p. 15)_
- [x] Dependency _(PDF p. 15)_
- [x] CVE _(PDF p. 15)_
- [x] Infrastructure resource _(PDF p. 15)_
- [x] Secret fingerprint _(PDF p. 15)_
- [x] Bandit and Semgrep reports of the same SQL injection become one consolidated issue. _(PDF p. 16)_
- [x] Supporting evidence from both scanners remains available. _(PDF p. 16)_
- [x] Unrelated findings are not incorrectly merged. _(PDF p. 16)_

Validated derived scanner-agreement fields: `supporting_scanners`,
`contradicting_scanners`, `agreement_strength`, and `correlation_reason`.

### 6.3 Add evidence-weighted corroboration

- [x] Increase finding-validity confidence when independent scanners agree. _(PDF p. 16)_
- [x] Avoid double-counting scanners using the same rule source. _(PDF p. 16)_
- [x] Track shared rule ancestry where known. _(PDF p. 16)_
- [x] Record DAST confirmation separately. _(PDF p. 16)_
- [x] Record human confirmation separately. _(PDF p. 16)_
- [x] Add confidence limits to corroboration calculations. _(PDF p. 16)_
- [x] Corroboration logic is documented and tested. _(PDF p. 16)_
- [x] Scanner agreement does not automatically imply exploitability. _(PDF p. 16)_

## Phase 7 - Add threat-intelligence enrichment

### 7.1 Add advisory enrichment

- [x] OSV _(PDF p. 16)_
- [x] GitHub Security Advisories _(PDF p. 16)_
- [x] NVD where needed _(PDF p. 16)_
- [x] EPSS _(PDF p. 16)_
- [x] CISA KEV _(PDF p. 16)_
- [x] Enrichment failures are visible. _(PDF p. 17)_
- [x] Cached data has an expiry policy. _(PDF p. 17)_
- [x] Gate results identify stale threat data. _(PDF p. 17)_
- [x] No threat feed is treated as complete risk context. _(PDF p. 17)_

### 7.2 Add offline and privacy-preserving modes

- [x] Support local threat-data cache. _(PDF p. 17)_
- [x] Support fully offline runs. _(PDF p. 17)_
- [x] Document which identifiers are sent externally. _(PDF p. 17)_
- [x] Add network-mode: disabled. _(PDF p. 17)_
- [x] Add network-mode: metadata-only. _(PDF p. 17)_
- [x] Add network-mode: full. _(PDF p. 17)_
- [x] Default to the least invasive mode appropriate for the feature. _(PDF p. 17)_
- [x] Source code is never sent to enrichment services. _(PDF p. 17)_
- [x] Offline scans remain fully functional with cached data. _(PDF p. 17)_

## Phase 8 - Add reachability analysis

### 8.1 Implement dependency reachability

- [x] Whether a vulnerable package is installed. _(PDF p. 17)_
- [x] Whether it is a direct or transitive dependency. _(PDF p. 17)_
- [x] Whether it is imported. _(PDF p. 17)_
- [x] Whether the vulnerable symbol is called. _(PDF p. 17)_
- [x] Whether it is production or development-only. _(PDF p. 17)_
- [x] Whether it is included in the deployed artefact. _(PDF p. 17)_
- [x] Whether a call path exists. _(PDF p. 17)_
- [x] Whether analysis is incomplete. _(PDF p. 17)_
- [x] “No path found” is never described as “not exploitable.” _(PDF p. 18)_
- [x] Reachability evidence includes the analysed call path. _(PDF p. 18)_
- [x] Dynamic limitations are visible. _(PDF p. 18)_

### 8.2 Implement SAST source-to-sink analysis

- [x] Identify untrusted sources. _(PDF p. 18)_
- [x] Identify sanitizers. _(PDF p. 18)_
- [x] Identify dangerous sinks. _(PDF p. 18)_
- [x] Trace intra-file data flow. _(PDF p. 18)_
- [x] Trace cross-file data flow. _(PDF p. 18)_
- [x] Trace framework routing. _(PDF p. 18)_
- [x] Record authentication requirements. _(PDF p. 18)_
- [x] Record authorization checks where detectable. _(PDF p. 18)_
- [x] Record path confidence. _(PDF p. 18)_
- [x] Show source-to-sink evidence. _(PDF p. 18)_
- [x] Supported findings can show an explainable data-flow trace. _(PDF p. 18)_
- [x] Unsupported analysis is marked explicitly. _(PDF p. 18)_

### 8.3 Correlate static and dynamic evidence

- [x] Match DAST endpoints to source-code routes. _(PDF p. 18)_
- [x] Match DAST parameters to SAST sources. _(PDF p. 18)_
- [x] Match DAST proof to SAST sinks. _(PDF p. 18)_
- [x] Increase priority when a static issue is dynamically confirmed. _(PDF p. 18)_
- [x] Record failed reproduction attempts without marking the issue false. _(PDF p. 18)_
- [x] Distinguish blocked authentication from failed exploitation. _(PDF p. 18)_
- [x] Dynamically confirmed findings show both static and runtime evidence. _(PDF p. 18)_
- [x] Inconclusive DAST results do not automatically suppress SAST findings. _(PDF p. 18)_

## Phase 9 - Package DAST safely

### 9.1 Add reusable DAST configuration

- [x] Support baseline mode. _(PDF p. 19)_
- [x] Support API mode. _(PDF p. 19)_
- [x] Support authenticated mode. _(PDF p. 19)_
- [x] Support preview environments. _(PDF p. 19)_
- [x] Support scope allowlists. _(PDF p. 19)_
- [x] Reject non-allowlisted domains. _(PDF p. 19)_
- [x] Add rate limits. _(PDF p. 19)_
- [x] Add request limits. _(PDF p. 19)_
- [x] Add maximum scan duration. _(PDF p. 19)_
- [x] Add safe and active scan modes. _(PDF p. 19)_
- [x] Require explicit opt-in for active scans. _(PDF p. 19)_
- [x] Prevent scanning production by accident. _(PDF p. 19)_
- [x] Require acknowledgement for public targets. _(PDF p. 19)_
- [x] DAST cannot target arbitrary external domains by default. _(PDF p. 19)_
- [x] Active scanning requires explicit configuration. _(PDF p. 19)_
- [x] Authentication secrets are redacted from logs. _(PDF p. 19)_

## Phase 10 - Build contextual decision scoring

### 10.1 Define decision components

- [x] Finding-validity confidence _(PDF p. 19)_
- [x] Original severity _(PDF p. 19)_
- [x] Normalised severity _(PDF p. 19)_
- [x] Reachability _(PDF p. 19)_
- [x] EPSS _(PDF p. 19)_
- [x] CISA KEV _(PDF p. 19)_
- [x] Public exploit availability _(PDF p. 20)_
- [x] Internet exposure _(PDF p. 20)_
- [x] Authentication requirements _(PDF p. 20)_
- [x] Data sensitivity _(PDF p. 20)_
- [x] Asset criticality _(PDF p. 20)_
- [x] Runtime environment _(PDF p. 20)_
- [x] Existing controls _(PDF p. 20)_
- [x] Fix availability _(PDF p. 20)_
- [x] New versus existing status _(PDF p. 20)_
- [x] Human triage state _(PDF p. 20)_

### 10.2 Create decision outcomes

- [x] Document rules for each outcome. _(PDF p. 20)_
- [x] Make outcomes policy-driven. _(PDF p. 20)_
- [x] Show the complete explanation. _(PDF p. 20)_
- [x] Include evidence strength. _(PDF p. 20)_
- [x] Include unresolved uncertainty. _(PDF p. 20)_
- [x] Include policy version. _(PDF p. 20)_
- [x] Every decision is reproducible from stored evidence. _(PDF p. 20)_
- [x] Users can inspect which policy caused the result. _(PDF p. 20)_

## Phase 11 - Implement policy-as-code

### 11.1 Define the policy schema

- [x] Severity _(PDF p. 21)_
- [x] CWE _(PDF p. 21)_
- [x] CVE _(PDF p. 21)_
- [x] EPSS _(PDF p. 21)_
- [x] KEV _(PDF p. 21)_
- [x] Reachability _(PDF p. 21)_
- [x] Environment _(PDF p. 21)_
- [x] Repository _(PDF p. 21)_
- [x] Branch _(PDF p. 21)_
- [x] Asset criticality _(PDF p. 21)_
- [x] Confidence lower bound _(PDF p. 21)_
- [x] Finding status _(PDF p. 21)_
- [x] Introduced-in-PR status _(PDF p. 21)_
- [x] Fix availability _(PDF p. 21)_
- [x] Scanner health _(PDF p. 21)_
- [x] Secret validation status _(PDF p. 21)_
- [x] Suppression expiry _(PDF p. 21)_

### 11.2 Add policy tooling

- [x] Add policy validation. _(PDF p. 22)_
- [x] Add policy simulation. _(PDF p. 22)_
- [x] Add policy explanation. _(PDF p. 22)_
- [x] Add policy unit testing. _(PDF p. 22)_
- [x] Add policy versioning. _(PDF p. 22)_
- [x] Add policy inheritance. _(PDF p. 22)_
- [x] Add repository overrides. _(PDF p. 22)_
- [x] Add organisation defaults. _(PDF p. 22)_
- [x] Prevent invalid rules from silently passing. _(PDF p. 22)_
- [x] A policy can be tested against saved findings before deployment. _(PDF p. 22)_
- [x] Invalid policies fail clearly. _(PDF p. 22)_
- [x] Policy decisions are deterministic. _(PDF p. 22)_

### 11.3 Create standard policy packs

- [x] Startup baseline _(PDF p. 22)_
- [x] High-assurance baseline _(PDF p. 22)_
- [x] Financial services _(PDF p. 22)_
- [x] Healthcare _(PDF p. 22)_
- [x] Public-sector supplier _(PDF p. 22)_
- [x] OWASP ASVS-aligned _(PDF p. 22)_
- [x] NIST SSDF-aligned _(PDF p. 22)_
- [x] Container security _(PDF p. 22)_
- [x] Secret protection _(PDF p. 22)_
- [x] Supply-chain security _(PDF p. 22)_
- [x] Every policy pack has documentation and tests. _(PDF p. 22)_
- [x] Policy packs state that automated evidence does not guarantee compliance. _(PDF p. 22)_

## Phase 12 - Add baseline and differential scanning

### 12.1 Create baseline support

- [x] Generate a baseline from the default branch. _(PDF p. 23)_
- [x] Store baseline findings by fingerprint. _(PDF p. 23)_
- [x] Compare pull-request findings to the baseline. _(PDF p. 23)_
- [x] Detect new findings. _(PDF p. 23)_
- [x] Detect removed findings. _(PDF p. 23)_
- [x] Detect worsened findings. _(PDF p. 23)_
- [x] Detect newly reachable findings. _(PDF p. 23)_
- [x] Detect newly exploited dependencies. _(PDF p. 23)_
- [x] Detect expired suppressions. _(PDF p. 23)_
- [x] Detect scanner coverage regressions. _(PDF p. 23)_

### 12.2 Gate new risk by default

- [x] Add gate-mode: new. _(PDF p. 23)_
- [x] Add gate-mode: all. _(PDF p. 23)_
- [x] Add gate-mode: worsened. _(PDF p. 23)_
- [x] Add gate-mode: policy. _(PDF p. 23)_
- [x] Allow explicit legacy-risk enforcement. _(PDF p. 23)_
- [x] Show baseline age. _(PDF p. 23)_
- [x] Fail when the baseline is invalid or incompatible. _(PDF p. 23)_
- [x] Existing repositories can adopt the product without immediately fixing every historical finding. _(PDF p. 23)_
- [x] Newly introduced high-risk findings still block the pull request. _(PDF p. 23)_

## Phase 13 - Build the finding lifecycle

### 13.1 Implement finding states

- [x] Record state history. _(PDF p. 24)_
- [x] Record actor. _(PDF p. 24)_
- [x] Record timestamp. _(PDF p. 24)_
- [x] Record reason. _(PDF p. 24)_
- [x] Record evidence. _(PDF p. 24)_
- [x] Record approval where required. _(PDF p. 24)_
- [x] Record expiry. _(PDF p. 24)_
- [x] Support automatic reopening. _(PDF p. 24)_

### 13.2 Implement suppressions

- [x] Finding fingerprint _(PDF p. 24)_
- [x] Reason _(PDF p. 24)_
- [x] Author _(PDF p. 24)_
- [x] Creation date _(PDF p. 24)_
- [x] Expiry date _(PDF p. 24)_
- [x] Scope _(PDF p. 24)_
- [x] Approval _(PDF p. 24)_
- [x] Evidence _(PDF p. 24)_
- [x] Revalidation rule _(PDF p. 24)_
- [x] Prevent permanent suppression by default. _(PDF p. 24)_
- [x] Add suppression linting. _(PDF p. 24)_
- [x] Add suppression-expiry warnings. _(PDF p. 24)_
- [x] Reopen when code meaningfully changes. _(PDF p. 24)_
- [x] Reopen when reachability changes. _(PDF p. 24)_
- [x] Reopen when KEV status changes. _(PDF p. 24)_
- [x] Reopen when exploit evidence changes. _(PDF p. 24)_
- [x] Reopen when policy changes. _(PDF p. 24)_
- [x] Expired suppressions automatically re-enter evaluation. _(PDF p. 24)_
- [x] Every suppression is auditable. _(PDF p. 24)_
- [x] A suppression cannot silently apply to unrelated findings. _(PDF p. 25)_

## Phase 14 - Add GitHub-native integration

### 14.1 Generate SARIF

- [x] Map supported findings to SARIF 2.1.0. _(PDF p. 25)_
- [x] Validate generated SARIF. _(PDF p. 25)_
- [x] Include rule metadata. _(PDF p. 25)_
- [x] Include precise locations. _(PDF p. 25)_
- [x] Include severity. _(PDF p. 25)_
- [x] Include remediation guidance. _(PDF p. 25)_
- [x] Include fingerprints. _(PDF p. 25)_
- [x] Include partial fingerprints. _(PDF p. 25)_
- [x] Upload results to GitHub code scanning. _(PDF p. 25)_
- [x] Findings appear in GitHub’s Security tab. _(PDF p. 25)_
- [x] Findings annotate pull-request code where locations exist. _(PDF p. 25)_

### 14.2 Add GitHub Checks integration

- [x] Gate result _(PDF p. 25)_
- [x] Scanner-health summary _(PDF p. 25)_
- [x] New findings _(PDF p. 25)_
- [x] Blocking findings _(PDF p. 25)_
- [x] Suppressed findings _(PDF p. 25)_
- [x] Unscored findings _(PDF p. 25)_
- [x] Evidence explanations _(PDF p. 25)_
- [x] Links to detailed artefacts _(PDF p. 25)_
- [x] Policy information _(PDF p. 25)_
- [x] Baseline comparison _(PDF p. 25)_
- [x] Developers can understand the release decision without downloading an artefact. _(PDF p. 25)_
- [x] Branch protection can require the Trust Gate check. _(PDF p. 25)_

### 14.3 Add pull-request comments carefully

- [x] Post one consolidated comment. _(PDF p. 25)_
- [x] Update the existing comment instead of creating duplicates. _(PDF p. 25)_
- [x] Keep the summary concise. _(PDF p. 25)_
- [x] Collapse long details. _(PDF p. 26)_
- [x] Link to exact code locations. _(PDF p. 26)_
- [x] Avoid exposing secrets. _(PDF p. 26)_
- [x] Avoid posting proprietary source excerpts unnecessarily. _(PDF p. 26)_
- [x] Include remediation status. _(PDF p. 26)_
- [x] Repeated runs update one comment. _(PDF p. 26)_
- [x] Pull requests are not flooded with scanner messages. _(PDF p. 26)_

## Phase 15 - Generate standard security artefacts

### 15.1 Generate SBOMs

- [x] CycloneDX JSON _(PDF p. 26)_
- [x] SPDX JSON _(PDF p. 26)_
- [x] Direct dependencies _(PDF p. 26)_
- [x] Transitive dependencies _(PDF p. 26)_
- [x] Versions _(PDF p. 26)_
- [x] Licences _(PDF p. 26)_
- [x] Package URLs _(PDF p. 26)_
- [x] Hashes _(PDF p. 26)_
- [x] Dependency relationships _(PDF p. 26)_

### 15.2 Generate VEX

- [x] Generate CycloneDX VEX. _(PDF p. 26)_
- [x] Record exploitability status. _(PDF p. 26)_
- [x] Record justification. _(PDF p. 26)_
- [x] Record analysis state. _(PDF p. 26)_
- [x] Link VEX decisions to reachability evidence. _(PDF p. 26)_
- [x] Link VEX decisions to approvals. _(PDF p. 26)_
- [x] Version and sign VEX output. _(PDF p. 26)_

### 15.3 Generate compliance and audit evidence

- [x] Commit SHA _(PDF p. 26)_
- [x] Repository _(PDF p. 26)_
- [x] Workflow identity _(PDF p. 27)_
- [x] Timestamp _(PDF p. 27)_
- [x] Scanner versions _(PDF p. 27)_
- [x] Scanner health _(PDF p. 27)_
- [x] Scan configuration _(PDF p. 27)_
- [x] Policy version _(PDF p. 27)_
- [x] Baseline version _(PDF p. 27)_
- [x] Findings _(PDF p. 27)_
- [x] Suppressions _(PDF p. 27)_
- [x] Approvals _(PDF p. 27)_
- [x] Gate result _(PDF p. 27)_
- [x] SBOM _(PDF p. 27)_
- [x] VEX _(PDF p. 27)_
- [x] Provenance _(PDF p. 27)_
- [x] Attestation _(PDF p. 27)_
- [x] Exclusions _(PDF p. 27)_
- [x] Data-source timestamps _(PDF p. 27)_
- [x] Audit evidence is reproducible and verifiable. _(PDF p. 27)_
- [x] Reports distinguish automated evidence from manual compliance requirements. _(PDF p. 27)_

## Phase 16 - Add safe remediation

### 16.1 Implement deterministic remediation

- [x] Parameterised SQL queries _(PDF p. 27)_
- [x] Removal of shell=True _(PDF p. 27)_
- [x] Safe YAML loading _(PDF p. 27)_
- [x] Replacement of weak hashing _(PDF p. 27)_
- [x] Dependency upgrades _(PDF p. 27)_
- [x] Secure Docker user configuration _(PDF p. 27)_
- [x] Removal of exposed secrets _(PDF p. 27)_
- [x] Secure HTTP-header configuration _(PDF p. 27)_
- [x] Supported rule IDs _(PDF p. 27)_
- [x] Supported frameworks _(PDF p. 27)_
- [x] Preconditions _(PDF p. 27)_
- [x] Transformation _(PDF p. 27)_
- [x] Tests _(PDF p. 27)_
- [x] Rollback behaviour _(PDF p. 27)_
- [x] Risk notes _(PDF p. 27)_
- [x] Deterministic fixes are covered by before-and-after tests. _(PDF p. 28)_
- [x] Unsupported code is not modified. _(PDF p. 28)_

### 16.2 Implement guided remediation

- [x] Why it is vulnerable _(PDF p. 28)_
- [x] Exploit scenario _(PDF p. 28)_
- [x] Relevant source and sink _(PDF p. 28)_
- [x] Secure coding pattern _(PDF p. 28)_
- [x] Framework-specific example _(PDF p. 28)_
- [x] CWE reference _(PDF p. 28)_
- [x] Testing guidance _(PDF p. 28)_
- [x] Regression risks _(PDF p. 28)_
- [x] Verification instructions _(PDF p. 28)_

### 16.3 Add AI-assisted remediation

- [x] Require explicit opt-in. _(PDF p. 28)_
- [x] Display which code context leaves the runner. _(PDF p. 28)_
- [x] Support local-model mode. _(PDF p. 28)_
- [x] Support redaction. _(PDF p. 28)_
- [x] Generate patches on isolated branches. _(PDF p. 28)_
- [x] Run formatting. _(PDF p. 28)_
- [x] Run type checking. _(PDF p. 28)_
- [x] Run unit tests. _(PDF p. 28)_
- [x] Run integration tests. _(PDF p. 28)_
- [x] Rerun relevant security scanners. _(PDF p. 28)_
- [x] Verify the original finding disappeared. _(PDF p. 28)_
- [x] Check for new high-risk findings. _(PDF p. 28)_
- [x] Open a draft pull request. _(PDF p. 28)_
- [x] Mark the fix as unverified until all checks pass. _(PDF p. 28)_
- [x] The product never claims an issue is fixed solely because AI generated a patch. _(PDF p. 28)_
- [x] Failed verification prevents automatic fix completion. _(PDF p. 28)_

## Phase 17 - Expand the benchmark corpus

### 17.1 Build a multilingual benchmark

- [x] Python _(PDF p. 29)_
- [x] JavaScript _(PDF p. 29)_
- [x] TypeScript _(PDF p. 29)_
- [x] Java _(PDF p. 29)_
- [x] Go _(PDF p. 29)_
- [x] Ruby _(PDF p. 29)_
- [x] C# _(PDF p. 29)_
- [x] Infrastructure as Code _(PDF p. 29)_
- [x] Containers _(PDF p. 29)_
- [x] Kubernetes _(PDF p. 29)_
- [x] Multiple frameworks _(PDF p. 29)_
- [x] True vulnerabilities _(PDF p. 29)_
- [x] Patched equivalents _(PDF p. 29)_
- [x] Safe lookalikes _(PDF p. 29)_
- [x] Cross-file cases _(PDF p. 29)_
- [x] Sanitised cases _(PDF p. 29)_
- [x] Reachable cases _(PDF p. 29)_
- [x] Unreachable cases _(PDF p. 29)_
- [x] Test-only code _(PDF p. 29)_
- [x] Development-only dependencies _(PDF p. 29)_
- [x] Production dependencies _(PDF p. 29)_

### 17.2 Create robust labelling procedures

- [ ] Use two independent reviewers. _(PDF p. 29; genuine reviewer evidence required)_
- [x] Record reviewer decisions. _(PDF p. 29)_
- [x] Add adjudication for disagreements. _(PDF p. 29)_
- [x] Measure inter-rater agreement. _(PDF p. 29)_
- [x] Document labelling rules. _(PDF p. 29)_
- [x] Record uncertainty. _(PDF p. 29)_
- [x] Separate public and private benchmark partitions. _(PDF p. 29)_
- [x] Create blind evaluation sets. _(PDF p. 29)_
- [x] Prevent benchmark leakage into rule tuning. _(PDF p. 29)_
- [x] Published benchmark claims are reproducible. _(PDF p. 29)_
- [ ] Every labelled item has review evidence. _(PDF p. 29; genuine reviewer evidence required)_
- [x] Private evaluation sets remain separated from development data. _(PDF p. 29)_

### 17.3 Automate benchmark execution

- [x] Run benchmarks on supported scanner upgrades. _(PDF p. 30)_
- [x] Compare new and previous versions. _(PDF p. 30)_
- [x] Detect precision regressions. _(PDF p. 30)_
- [x] Detect recall regressions. _(PDF p. 30)_
- [x] Detect runtime regressions. _(PDF p. 30)_
- [x] Block releases when thresholds fail. _(PDF p. 30)_
- [x] Generate benchmark reports automatically. _(PDF p. 30)_
- [x] Scanner upgrades cannot silently reduce detection quality. _(PDF p. 30)_
- [x] Published metrics always identify scanner and dataset versions. _(PDF p. 30)_

## Phase 18 - Add customer-specific calibration

### 18.1 Capture customer feedback

- [x] Confirmed true positive _(PDF p. 30)_
- [x] Confirmed false positive _(PDF p. 30)_
- [x] Accepted risk _(PDF p. 30)_
- [x] Fixed _(PDF p. 30)_
- [x] Reopened _(PDF p. 30)_
- [x] Remediation accepted _(PDF p. 30)_
- [x] Remediation rejected _(PDF p. 30)_
- [x] Keep feedback local by default. _(PDF p. 30)_
- [x] Allow encrypted export. _(PDF p. 30)_
- [x] Allow deletion. _(PDF p. 30)_
- [x] Allow repository-specific calibration. _(PDF p. 30)_
- [x] Allow organisation-specific calibration. _(PDF p. 30)_
- [x] Keep global and customer-specific confidence separate. _(PDF p. 30)_

### 18.2 Build local calibration models

- [x] Calculate repository-specific rule reliability. _(PDF p. 30)_
- [x] Calculate organisation-specific rule reliability. _(PDF p. 30)_
- [x] Apply Bayesian shrinkage to avoid overfitting. _(PDF p. 30)_
- [x] Show global and local estimates together. _(PDF p. 30)_
- [x] Require minimum evidence before local overrides affect gating. _(PDF p. 30)_
- [x] Record model version. _(PDF p. 30)_
- [x] Add drift detection. _(PDF p. 30)_
- [x] Small local samples do not create extreme confidence. _(PDF p. 31)_
- [x] Customers can inspect and reset calibration data. _(PDF p. 31)_

## Phase 19 - Build deployment modes

### 19.1 Local-only mode

- [x] All scanning occurs in CI. _(PDF p. 31)_
- [x] Findings remain local. _(PDF p. 31)_
- [x] Policies remain local. _(PDF p. 31)_
- [x] Reporting remains local. _(PDF p. 31)_
- [x] Threat feeds are cached locally. _(PDF p. 31)_
- [x] No telemetry is sent without consent. _(PDF p. 31)_

### 19.2 Hybrid mode

- [x] Source code stays local. _(PDF p. 31)_
- [x] Only approved finding metadata is uploaded. _(PDF p. 31)_
- [x] Support field-level redaction. _(PDF p. 31)_
- [x] Support customer-managed encryption keys. _(PDF p. 31)_
- [x] Document exact transmitted fields. _(PDF p. 31)_
- [x] Add upload allowlists. _(PDF p. 31)_

### 19.3 Self-hosted enterprise mode

- [x] Containerised deployment. _(PDF p. 31)_
- [x] Database migration tooling. _(PDF p. 31)_
- [x] Backup and restore. _(PDF p. 31)_
- [x] SSO or SAML. _(PDF p. 31)_
- [x] SCIM. _(PDF p. 31)_
- [x] Role-based access control. _(PDF p. 31)_
- [x] Audit logging. _(PDF p. 31)_
- [x] Data-retention settings. _(PDF p. 31)_
- [x] Offline threat-data import. _(PDF p. 31)_
- [x] High-availability guidance. _(PDF p. 31)_
- [x] Security-hardening guide. _(PDF p. 31)_
- [x] Every feature documents its data-handling behaviour. _(PDF p. 31)_
- [x] Enterprise users can operate without sending data to the vendor. _(PDF p. 31)_

## Phase 20 - Build team and organisation features

### 20.1 Create the management plane

- [x] Multi-repository dashboard _(PDF p. 32)_
- [x] Organisation risk overview _(PDF p. 32)_
- [x] Repository trends _(PDF p. 32)_
- [x] Scanner health _(PDF p. 32)_
- [x] Policy compliance _(PDF p. 32)_
- [x] Mean time to remediation _(PDF p. 32)_
- [x] Finding ownership _(PDF p. 32)_
- [x] Suppression expiry _(PDF p. 32)_
- [x] Benchmark drift _(PDF p. 32)_
- [x] Threat-intelligence changes _(PDF p. 32)_

### 20.2 Add integrations

- [x] Linear _(PDF p. 32)_
- [x] Jira _(PDF p. 32)_
- [x] Slack _(PDF p. 32)_
- [x] Microsoft Teams _(PDF p. 32)_
- [x] Email _(PDF p. 32)_
- [x] Webhooks _(PDF p. 32)_
- [x] SIEM export _(PDF p. 32)_
- [x] Ticket synchronization _(PDF p. 32)_
- [x] Findings can be assigned and tracked without duplicate tickets. _(PDF p. 32)_
- [x] Closing a validated ticket updates finding state safely. _(PDF p. 32)_

## Phase 21 - Add compliance mappings

### Phase-wide Phase-wide requirements and completion criteria

- [x] OWASP Top 10 _(PDF p. 32)_
- [x] OWASP ASVS _(PDF p. 32)_
- [x] OWASP SAMM _(PDF p. 32)_
- [x] NIST SSDF _(PDF p. 32)_
- [x] CWE _(PDF p. 32)_
- [x] PCI DSS _(PDF p. 32)_
- [x] ISO 27001 _(PDF p. 32)_
- [x] SOC 2 _(PDF p. 32)_
- [x] Cyber Essentials _(PDF p. 32)_
- [x] State what automated evidence supports. _(PDF p. 33)_
- [x] State what still requires manual verification. _(PDF p. 33)_
- [x] Do not claim complete compliance. _(PDF p. 33)_
- [x] Record mapping version. _(PDF p. 33)_
- [x] Add exportable evidence reports. _(PDF p. 33)_
- [x] Reports say “evidence available” rather than automatically declaring compliance. _(PDF p. 33)_
- [x] Framework mappings are reviewed and versioned. _(PDF p. 33)_

## Phase 22 - Documentation and developer experience

### 22.1 Create complete user documentation

- [x] Five-minute quick start _(PDF p. 33)_
- [x] GitHub Action installation _(PDF p. 33)_
- [x] CLI installation _(PDF p. 33)_
- [x] Configuration reference _(PDF p. 33)_
- [x] Policy reference _(PDF p. 33)_
- [x] Scanner compatibility _(PDF p. 33)_
- [x] DAST safety guide _(PDF p. 33)_
- [x] Offline operation _(PDF p. 33)_
- [x] Baseline setup _(PDF p. 33)_
- [x] Suppression workflow _(PDF p. 33)_
- [x] Remediation workflow _(PDF p. 33)_
- [x] Troubleshooting _(PDF p. 33)_
- [x] Security model _(PDF p. 33)_
- [x] Privacy model _(PDF p. 33)_
- [x] Upgrade guide _(PDF p. 33)_
- [x] Migration guide _(PDF p. 33)_

### 22.2 Add working examples

- [x] Python Flask _(PDF p. 33)_
- [x] Python Django _(PDF p. 33)_
- [x] Node.js _(PDF p. 33)_
- [x] TypeScript _(PDF p. 33)_
- [x] Java _(PDF p. 33)_
- [x] Go _(PDF p. 33)_
- [x] Docker _(PDF p. 33)_
- [x] Terraform _(PDF p. 34)_
- [x] Kubernetes _(PDF p. 34)_
- [x] Monorepo _(PDF p. 34)_
- [x] Authenticated DAST _(PDF p. 34)_
- [x] Offline mode _(PDF p. 34)_
- [x] Custom policy _(PDF p. 34)_
- [x] Self-hosted deployment _(PDF p. 34)_
- [x] Every documented example runs in CI. _(PDF p. 34)_
- [x] Broken examples block releases. _(PDF p. 34)_

### 22.3 Improve error messages

- [x] What failed _(PDF p. 34)_
- [x] Why it likely failed _(PDF p. 34)_
- [x] Whether security coverage is incomplete _(PDF p. 34)_
- [x] Whether the gate is trustworthy _(PDF p. 34)_
- [x] How to resolve it _(PDF p. 34)_
- [x] Where logs are stored _(PDF p. 34)_
- [x] Users do not need to inspect source code to understand common failures. _(PDF p. 34)_

## Phase 23 - Testing strategy

### 23.1 Unit tests

- [x] All parsers _(PDF p. 34)_
- [x] Severity normalisation _(PDF p. 34)_
- [x] Fingerprinting _(PDF p. 34)_
- [x] Deduplication _(PDF p. 34)_
- [x] Correlation _(PDF p. 34)_
- [x] Confidence calculations _(PDF p. 34)_
- [x] Policy evaluation _(PDF p. 34)_
- [x] Suppression expiry _(PDF p. 34)_
- [x] Baseline comparison _(PDF p. 34)_
- [x] Schema validation _(PDF p. 34)_
- [x] Threat enrichment _(PDF p. 34)_
- [x] Reachability states _(PDF p. 34)_
- [x] Remediation rules _(PDF p. 34)_

### 23.2 Integration tests

- [x] Every scanner adapter _(PDF p. 35)_
- [x] Missing report _(PDF p. 35)_
- [x] Malformed report _(PDF p. 35)_
- [x] Scanner timeout _(PDF p. 35)_
- [x] Scanner crash _(PDF p. 35)_
- [x] Empty repository _(PDF p. 35)_
- [x] Unsupported repository _(PDF p. 35)_
- [x] Monorepo _(PDF p. 35)_
- [x] Offline mode _(PDF p. 35)_
- [x] Baseline comparison _(PDF p. 35)_
- [x] SARIF upload generation _(PDF p. 35)_
- [x] SBOM and VEX generation _(PDF p. 35)_

### 23.3 Security tests

- [x] Command injection _(PDF p. 35)_
- [x] Path traversal _(PDF p. 35)_
- [x] Malicious filenames _(PDF p. 35)_
- [x] Malicious scanner output _(PDF p. 35)_
- [x] HTML injection _(PDF p. 35)_
- [x] SARIF injection _(PDF p. 35)_
- [x] Secret leakage _(PDF p. 35)_
- [x] Licence bypass _(PDF p. 35)_
- [x] Policy bypass _(PDF p. 35)_
- [x] Suppression bypass _(PDF p. 35)_
- [x] Untrusted pull requests _(PDF p. 35)_
- [x] Symlink attacks _(PDF p. 35)_
- [x] Zip-slip attacks _(PDF p. 35)_
- [x] Resource exhaustion _(PDF p. 35)_
- [x] DAST target abuse _(PDF p. 35)_
- [x] Dependency confusion _(PDF p. 35)_

### 23.4 End-to-end tests

- [x] Clean repository passes. _(PDF p. 36)_
- [x] New critical vulnerability blocks. _(PDF p. 36)_
- [x] Legacy vulnerability reports but does not block in new-risk mode. _(PDF p. 36)_
- [x] Scanner failure blocks. _(PDF p. 36)_
- [x] DAST confirms a SAST issue. _(PDF p. 36)_
- [x] Suppression expires and reopens. _(PDF p. 36)_
- [x] KEV status changes and reprioritises. _(PDF p. 36)_
- [x] Deterministic fix passes verification. _(PDF p. 36)_
- [x] Failed fix remains unresolved. _(PDF p. 36)_
- [x] SARIF appears correctly. _(PDF p. 36)_
- [x] Evidence bundle verifies successfully. _(PDF p. 36)_
- [x] End-to-end tests run on every release. _(PDF p. 36)_
- [x] A release cannot proceed when critical workflows fail. _(PDF p. 36)_

## Phase 24 - Performance and reliability

### 24.1 Improve execution performance

- [x] Run independent scanners in parallel. _(PDF p. 36)_
- [x] Cache scanner installations safely. _(PDF p. 36)_
- [x] Cache threat data. _(PDF p. 36)_
- [x] Cache dependency graphs. _(PDF p. 36)_
- [x] Support changed-file scanning. _(PDF p. 36)_
- [x] Support incremental rescanning. _(PDF p. 36)_
- [x] Avoid rescanning unchanged packages. _(PDF p. 36)_
- [x] Add resource limits. _(PDF p. 36)_
- [x] Track scanner duration. _(PDF p. 36)_

### 24.2 Define reliability targets

- [x] Add performance benchmarks. _(PDF p. 36)_
- [x] Add regression thresholds. _(PDF p. 37)_
- [x] Add reliability dashboards. _(PDF p. 37)_
- [x] Add failure-rate reporting. _(PDF p. 37)_

## Phase 25 - Product packaging and licensing

### 25.1 Define editions

- [x] Core scanners _(PDF p. 37)_
- [x] SARIF _(PDF p. 37)_
- [x] Basic security gate _(PDF p. 37)_
- [x] Local reports _(PDF p. 37)_
- [x] Standard policy packs _(PDF p. 37)_
- [x] Evidence-based prioritisation _(PDF p. 37)_
- [x] EPSS and KEV enrichment _(PDF p. 37)_
- [x] Differential scanning _(PDF p. 37)_
- [x] Deduplication _(PDF p. 37)_
- [x] Expiring suppressions _(PDF p. 37)_
- [x] Guided remediation _(PDF p. 37)_
- [x] Private repositories _(PDF p. 37)_
- [x] Multi-repository dashboard _(PDF p. 37)_
- [x] Central policies _(PDF p. 37)_
- [x] Assignment _(PDF p. 37)_
- [x] Integrations _(PDF p. 37)_
- [x] Finding lifecycle _(PDF p. 37)_
- [x] Organisation calibration _(PDF p. 37)_
- [x] Audit logs _(PDF p. 37)_
- [x] Self-hosting _(PDF p. 37)_
- [x] SSO _(PDF p. 37)_
- [x] SCIM _(PDF p. 37)_
- [x] RBAC _(PDF p. 37)_
- [x] Data residency _(PDF p. 37)_
- [x] Compliance evidence _(PDF p. 37)_
- [x] Custom policy packs _(PDF p. 37)_
- [x] Enterprise SLA _(PDF p. 37)_

### 25.2 Review licensing architecture

- [x] Document which components are open source. _(PDF p. 38)_
- [x] Document which components are proprietary. _(PDF p. 38)_
- [x] Ensure proprietary functionality is not protected only through client-side orchestration. _(PDF p. 38)_
- [x] Ensure commercial terms are legally clear. _(PDF p. 38)_
- [x] Add licence compatibility review for every bundled scanner. _(PDF p. 38)_
- [x] Add a third-party notices file. _(PDF p. 38)_
- [x] Add subscription lifecycle tests. _(PDF p. 38)_
- [x] Add graceful offline validation. _(PDF p. 38)_
- [x] Add key rotation. _(PDF p. 38)_
- [x] Add revocation strategy where required. _(PDF p. 38)_
- [x] Do not allow licensing failure to corrupt security results. _(PDF p. 38)_
- [x] Users can always access their raw security findings. _(PDF p. 38)_
- [x] Paid feature failure cannot produce an incorrect clean result. _(PDF p. 38)_
- [x] Third-party licences are documented. _(PDF p. 38)_

## Phase 26 - Security review and external validation

### 26.1 Perform internal security review

- [x] Review threat model. _(PDF p. 38)_
- [x] Review cryptographic usage. _(PDF p. 38)_
- [x] Review licence verification. _(PDF p. 38)_
- [x] Review workflow security. _(PDF p. 38)_
- [x] Review parser trust boundaries. _(PDF p. 38)_
- [x] Review report rendering. _(PDF p. 38)_
- [x] Review external network calls. _(PDF p. 38)_
- [x] Review secret handling. _(PDF p. 38)_
- [x] Review update mechanisms. _(PDF p. 38)_
- [x] Review self-hosted deployment. _(PDF p. 38)_

### 26.2 Arrange independent review

- [ ] External code audit _(PDF p. 38)_ _(blocked: requires external reviewer)_
- [ ] Penetration test _(PDF p. 38)_ _(blocked: requires external reviewer)_
- [ ] Statistical methodology review _(PDF p. 38)_ _(blocked: requires external reviewer)_
- [ ] Benchmark labelling review _(PDF p. 38)_ _(blocked: requires external reviewer)_
- [ ] Privacy review _(PDF p. 38)_ _(blocked: requires external reviewer)_
- [ ] Licensing review _(PDF p. 38)_ _(blocked: requires external reviewer)_
- [ ] Publish a responsible summary of findings. _(PDF p. 39)_ _(blocked: requires external review first)_
- [ ] Fix all critical and high issues. _(PDF p. 39)_ _(blocked: requires external review first)_
- [ ] Track medium issues with deadlines. _(PDF p. 39)_ _(blocked: requires external review first)_
- [ ] Retest completed fixes. _(PDF p. 39)_ _(blocked: requires external review first)_
- [ ] No unresolved critical security findings. _(PDF p. 39)_ _(blocked: requires external review first)_
- [ ] No unresolved high findings without documented executive acceptance. _(PDF p. 39)_ _(blocked: requires external review first)_
- [ ] Statistical claims have independent review. _(PDF p. 39)_ _(blocked: requires external reviewer)_

## Phase 27 - Release readiness

### 27.1 Prepare release documentation

- [x] Release notes _(PDF p. 39)_
- [x] Installation guide _(PDF p. 39)_
- [x] Migration guide _(PDF p. 39)_
- [x] Upgrade guide _(PDF p. 39)_
- [x] Compatibility matrix _(PDF p. 39)_
- [x] Known limitations _(PDF p. 39)_
- [x] Security policy _(PDF p. 39)_
- [x] Support policy _(PDF p. 39)_
- [x] Data-processing documentation _(PDF p. 39)_
- [x] Service-level commitments _(PDF p. 39)_
- [x] Incident-response process _(PDF p. 39)_
- [x] Responsible-disclosure process _(PDF p. 39)_

### 27.2 Complete release verification

- [x] All unit tests pass. _(PDF p. 39)_
- [x] All integration tests pass. _(PDF p. 39)_
- [x] All security tests pass. _(PDF p. 39)_
- [x] All end-to-end tests pass. _(PDF p. 39)_
- [x] Performance targets pass. _(PDF p. 39)_
- [x] Benchmark thresholds pass. _(PDF p. 39)_
- [x] Documentation examples pass. _(PDF p. 39)_
- [x] SBOM is generated. _(PDF p. 39)_
- [x] Provenance is generated. _(PDF p. 39)_
- [x] Artefacts are signed. _(PDF p. 39)_
- [x] Changelog is updated. _(PDF p. 39)_
- [x] Version is tagged. _(PDF p. 39)_
- [x] Release is reproducible. _(PDF p. 39)_
- [x] Precision by scanner _(PDF p. 40)_
- [x] Precision by rule _(PDF p. 40)_
- [x] Precision by language _(PDF p. 40)_
- [x] Precision by framework _(PDF p. 40)_
- [x] Recall by vulnerability category _(PDF p. 40)_
- [x] F1 score _(PDF p. 40)_
- [x] Confidence calibration error _(PDF p. 40)_
- [x] Brier score _(PDF p. 40)_
- [x] False-positive reduction _(PDF p. 40)_
- [x] False-negative escape rate _(PDF p. 40)_
- [x] Scanner failure rate _(PDF p. 40)_
- [x] Partial-scan rate _(PDF p. 40)_
- [x] Median scan duration _(PDF p. 40)_
- [x] p95 scan duration _(PDF p. 40)_
- [x] Time to first result _(PDF p. 40)_
- [x] Mean time to remediation _(PDF p. 40)_
- [x] Gate override rate _(PDF p. 40)_
- [x] Suppression expiry rate _(PDF p. 40)_
- [x] Reopened finding rate _(PDF p. 40)_
- [x] Autofix acceptance rate _(PDF p. 40)_
- [x] Autofix verification rate _(PDF p. 40)_
- [x] Developer hours saved _(PDF p. 40)_
- [x] Security engineer hours saved _(PDF p. 40)_
- [x] Scanner failures cannot appear as clean scans. _(PDF p. 41)_
- [x] Missing or malformed reports are detected. _(PDF p. 41)_
- [x] Dependencies and Actions are pinned. _(PDF p. 41)_
- [x] Releases are signed and attested. _(PDF p. 41)_
- [ ] The product has passed an independent security review. _(PDF p. 41)_ _(blocked: requires external reviewer)_
- [x] Confidence scores use statistically defensible methods. _(PDF p. 41)_
- [x] Sample sizes and intervals are visible. _(PDF p. 41)_
- [x] Scanner reliability is separate from exploitability. _(PDF p. 41)_
- [x] Published benchmark figures are consistent. _(PDF p. 41)_
- [x] Benchmark results are reproducible. _(PDF p. 41)_
- [x] Installation is documented and tested. _(PDF p. 41)_
- [x] Results appear directly in pull requests. _(PDF p. 41)_
- [x] SARIF integration works. _(PDF p. 41)_
- [x] New-risk gating works. _(PDF p. 41)_
- [x] Errors are actionable. _(PDF p. 42)_
- [x] Supported examples run successfully. _(PDF p. 42)_
- [x] Findings are normalised. _(PDF p. 42)_
- [x] Findings are deduplicated. _(PDF p. 42)_
- [x] Cross-scanner evidence is correlated. _(PDF p. 42)_
- [x] Threat intelligence is included. _(PDF p. 42)_
- [x] Reachability is included where supported. _(PDF p. 42)_
- [x] Policy decisions are explainable. _(PDF p. 42)_
- [x] Finding lifecycle exists. _(PDF p. 42)_
- [x] Suppressions require expiry and evidence. _(PDF p. 42)_
- [x] Audit history is preserved. _(PDF p. 42)_
- [x] Policy-as-code is implemented. _(PDF p. 42)_
- [x] Compliance evidence clearly distinguishes automated and manual controls. _(PDF p. 42)_
- [x] SARIF is generated. _(PDF p. 42)_
- [x] CycloneDX SBOM is generated. _(PDF p. 42)_
- [x] SPDX SBOM is generated. _(PDF p. 42)_
- [x] VEX is generated. _(PDF p. 42)_
- [x] Signed evidence bundles are generated. _(PDF p. 42)_
- [x] JSON schemas are versioned and validated. _(PDF p. 42)_
- [x] Deterministic fixes are tested. _(PDF p. 42)_
- [x] Guided remediation is available. _(PDF p. 42)_
- [x] AI remediation is optional and privacy-controlled. _(PDF p. 42)_
- [x] Generated fixes are verified before being marked complete. _(PDF p. 42)_
- [x] Product and research identities are separated. _(PDF p. 42)_
- [x] Editions and feature boundaries are documented. _(PDF p. 42)_
- [x] Licensing is reviewed. _(PDF p. 42)_
- [x] Data-handling modes are documented. _(PDF p. 42)_
- [x] Local, hybrid and self-hosted modes are defined. _(PDF p. 42)_
- [x] Support and incident processes are operational. _(PDF p. 42)_

## Required final architecture outcome

- [x] Repository checkout _(actions/checkout in CI workflow)_
- [x] Repository context detection
- [x] Transparent scan plan
- [x] Applicable scanner adapters
- [x] Scanner-health validation _(scanners.models.ScannerResult.healthy + policy/context._scanner_health)_
- [x] Raw report preservation _(scanners.models.ScannerResult.report_path + schema/documents raw_report_reference)_
- [x] Schema validation _(schema/validation.validate_instance — Draft 2020-12, 11 document types)_
- [x] Finding normalisation _(severity.normalise_scanner_severity + adapters.base.normalize)_
- [x] Stable fingerprinting _(fingerprints.fingerprint_finding — cross-scanner SHA-256)_
- [x] Deduplication and correlation
- [x] Threat-intelligence enrichment
- [x] Reachability analysis
- [x] Evidence and confidence calculation _(confidence.build_confidence_components — multi-component DAG)_
- [x] Policy-as-code evaluation _(policy/evaluator.evaluate_policy — recursive expression evaluation)_
- [x] Release decision _(baselines/gate.evaluate_gate — 4 gate modes, severity threshold, pass/fail verdict)_
- [x] SARIF, GitHub Checks, and PR summary _(sarif/generation + checks/summary + comments/summary)_
- [x] SBOM, VEX, and signed evidence bundle _(supply_chain/release + vex/generation + evidence/generation)_
- [x] Optional verified remediation _(remediation/ai — staged worktree, 5-class verification, gated publish)_

## Final completion command

`trustgate verify-release` must fail unless all of these pass:

- [x] Schemas _(release_verify._check_schemas)_
- [x] Unit tests _(release_verify._check_tests)_
- [x] Integration tests _(release_verify._check_tests)_
- [x] Security tests _(release_verify._check_tests)_
- [x] End-to-end tests _(release_verify._check_tests)_
- [x] Benchmark thresholds _(release_verify._check_benchmark)_
- [x] Dependency pinning _(release_verify._check_dependency_pinning)_
- [x] GitHub Action pinning _(release_verify._check_action_pinning)_
- [x] SBOM generation _(release_verify._check_sbom)_
- [x] VEX generation _(release_verify._check_vex)_
- [x] SARIF validation _(release_verify._check_sarif)_
- [x] Documentation examples _(release_verify._check_examples)_
- [x] Release signatures _(release_verify._check_release_signatures)_
- [x] Provenance _(release_verify._check_provenance)_
- [x] Changelog _(release_verify._check_changelog)_
- [x] Version consistency _(release_verify._check_version_consistency)_

The product must not be described as fully complete until this command succeeds and all manual external-review requirements are recorded.
