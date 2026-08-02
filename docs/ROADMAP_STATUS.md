# Trust Gate implementation roadmap status

Source of truth: `Trust Gate Product Implementation Roadmap.pdf` (43 pages).

Last updated: 2026-07-25 on branch `codex/phase-7-threat-intelligence`.

## Status summary

- Explicit PDF checkbox items: **964**
- Validated complete: **307**
- Remaining explicit checkbox items: **657**
- Derived final architecture/verification checks: **34** (tracked below but
  excluded from the PDF checkbox totals because the PDF presents them as an
  architecture flow and command requirements, not checkbox items)
- Current work: **Phase 8.1 - Implement dependency reachability**

Only validation-backed work is checked. Existing files or partial implementations are not marked complete merely because they resemble a deliverable.

## Active implementation queue

1. Implement Phase 8.1 dependency reachability.
2. Continue Phases 8-27 in the exact order below without skipping acceptance criteria.

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

- [ ] Whether a vulnerable package is installed. _(PDF p. 17)_
- [ ] Whether it is a direct or transitive dependency. _(PDF p. 17)_
- [ ] Whether it is imported. _(PDF p. 17)_
- [ ] Whether the vulnerable symbol is called. _(PDF p. 17)_
- [ ] Whether it is production or development-only. _(PDF p. 17)_
- [ ] Whether it is included in the deployed artefact. _(PDF p. 17)_
- [ ] Whether a call path exists. _(PDF p. 17)_
- [ ] Whether analysis is incomplete. _(PDF p. 17)_
- [ ] “No path found” is never described as “not exploitable.” _(PDF p. 18)_
- [ ] Reachability evidence includes the analysed call path. _(PDF p. 18)_
- [ ] Dynamic limitations are visible. _(PDF p. 18)_

### 8.2 Implement SAST source-to-sink analysis

- [ ] Identify untrusted sources. _(PDF p. 18)_
- [ ] Identify sanitizers. _(PDF p. 18)_
- [ ] Identify dangerous sinks. _(PDF p. 18)_
- [ ] Trace intra-file data flow. _(PDF p. 18)_
- [ ] Trace cross-file data flow. _(PDF p. 18)_
- [ ] Trace framework routing. _(PDF p. 18)_
- [ ] Record authentication requirements. _(PDF p. 18)_
- [ ] Record authorization checks where detectable. _(PDF p. 18)_
- [ ] Record path confidence. _(PDF p. 18)_
- [ ] Show source-to-sink evidence. _(PDF p. 18)_
- [ ] Supported findings can show an explainable data-flow trace. _(PDF p. 18)_
- [ ] Unsupported analysis is marked explicitly. _(PDF p. 18)_

### 8.3 Correlate static and dynamic evidence

- [ ] Match DAST endpoints to source-code routes. _(PDF p. 18)_
- [ ] Match DAST parameters to SAST sources. _(PDF p. 18)_
- [ ] Match DAST proof to SAST sinks. _(PDF p. 18)_
- [ ] Increase priority when a static issue is dynamically confirmed. _(PDF p. 18)_
- [ ] Record failed reproduction attempts without marking the issue false. _(PDF p. 18)_
- [ ] Distinguish blocked authentication from failed exploitation. _(PDF p. 18)_
- [ ] Dynamically confirmed findings show both static and runtime evidence. _(PDF p. 18)_
- [ ] Inconclusive DAST results do not automatically suppress SAST findings. _(PDF p. 18)_

## Phase 9 - Package DAST safely

### 9.1 Add reusable DAST configuration

- [ ] Support baseline mode. _(PDF p. 19)_
- [ ] Support API mode. _(PDF p. 19)_
- [ ] Support authenticated mode. _(PDF p. 19)_
- [ ] Support preview environments. _(PDF p. 19)_
- [ ] Support scope allowlists. _(PDF p. 19)_
- [ ] Reject non-allowlisted domains. _(PDF p. 19)_
- [ ] Add rate limits. _(PDF p. 19)_
- [ ] Add request limits. _(PDF p. 19)_
- [ ] Add maximum scan duration. _(PDF p. 19)_
- [ ] Add safe and active scan modes. _(PDF p. 19)_
- [ ] Require explicit opt-in for active scans. _(PDF p. 19)_
- [ ] Prevent scanning production by accident. _(PDF p. 19)_
- [ ] Require acknowledgement for public targets. _(PDF p. 19)_
- [ ] DAST cannot target arbitrary external domains by default. _(PDF p. 19)_
- [ ] Active scanning requires explicit configuration. _(PDF p. 19)_
- [ ] Authentication secrets are redacted from logs. _(PDF p. 19)_

## Phase 10 - Build contextual decision scoring

### 10.1 Define decision components

- [ ] Finding-validity confidence _(PDF p. 19)_
- [ ] Original severity _(PDF p. 19)_
- [ ] Normalised severity _(PDF p. 19)_
- [ ] Reachability _(PDF p. 19)_
- [ ] EPSS _(PDF p. 19)_
- [ ] CISA KEV _(PDF p. 19)_
- [ ] Public exploit availability _(PDF p. 20)_
- [ ] Internet exposure _(PDF p. 20)_
- [ ] Authentication requirements _(PDF p. 20)_
- [ ] Data sensitivity _(PDF p. 20)_
- [ ] Asset criticality _(PDF p. 20)_
- [ ] Runtime environment _(PDF p. 20)_
- [ ] Existing controls _(PDF p. 20)_
- [ ] Fix availability _(PDF p. 20)_
- [ ] New versus existing status _(PDF p. 20)_
- [ ] Human triage state _(PDF p. 20)_

### 10.2 Create decision outcomes

- [ ] Document rules for each outcome. _(PDF p. 20)_
- [ ] Make outcomes policy-driven. _(PDF p. 20)_
- [ ] Show the complete explanation. _(PDF p. 20)_
- [ ] Include evidence strength. _(PDF p. 20)_
- [ ] Include unresolved uncertainty. _(PDF p. 20)_
- [ ] Include policy version. _(PDF p. 20)_
- [ ] Every decision is reproducible from stored evidence. _(PDF p. 20)_
- [ ] Users can inspect which policy caused the result. _(PDF p. 20)_

## Phase 11 - Implement policy-as-code

### 11.1 Define the policy schema

- [ ] Severity _(PDF p. 21)_
- [ ] CWE _(PDF p. 21)_
- [ ] CVE _(PDF p. 21)_
- [ ] EPSS _(PDF p. 21)_
- [ ] KEV _(PDF p. 21)_
- [ ] Reachability _(PDF p. 21)_
- [ ] Environment _(PDF p. 21)_
- [ ] Repository _(PDF p. 21)_
- [ ] Branch _(PDF p. 21)_
- [ ] Asset criticality _(PDF p. 21)_
- [ ] Confidence lower bound _(PDF p. 21)_
- [ ] Finding status _(PDF p. 21)_
- [ ] Introduced-in-PR status _(PDF p. 21)_
- [ ] Fix availability _(PDF p. 21)_
- [ ] Scanner health _(PDF p. 21)_
- [ ] Secret validation status _(PDF p. 21)_
- [ ] Suppression expiry _(PDF p. 21)_

### 11.2 Add policy tooling

- [ ] Add policy validation. _(PDF p. 22)_
- [ ] Add policy simulation. _(PDF p. 22)_
- [ ] Add policy explanation. _(PDF p. 22)_
- [ ] Add policy unit testing. _(PDF p. 22)_
- [ ] Add policy versioning. _(PDF p. 22)_
- [ ] Add policy inheritance. _(PDF p. 22)_
- [ ] Add repository overrides. _(PDF p. 22)_
- [ ] Add organisation defaults. _(PDF p. 22)_
- [ ] Prevent invalid rules from silently passing. _(PDF p. 22)_
- [ ] A policy can be tested against saved findings before deployment. _(PDF p. 22)_
- [ ] Invalid policies fail clearly. _(PDF p. 22)_
- [ ] Policy decisions are deterministic. _(PDF p. 22)_

### 11.3 Create standard policy packs

- [ ] Startup baseline _(PDF p. 22)_
- [ ] High-assurance baseline _(PDF p. 22)_
- [ ] Financial services _(PDF p. 22)_
- [ ] Healthcare _(PDF p. 22)_
- [ ] Public-sector supplier _(PDF p. 22)_
- [ ] OWASP ASVS-aligned _(PDF p. 22)_
- [ ] NIST SSDF-aligned _(PDF p. 22)_
- [ ] Container security _(PDF p. 22)_
- [ ] Secret protection _(PDF p. 22)_
- [ ] Supply-chain security _(PDF p. 22)_
- [ ] Every policy pack has documentation and tests. _(PDF p. 22)_
- [ ] Policy packs state that automated evidence does not guarantee compliance. _(PDF p. 22)_

## Phase 12 - Add baseline and differential scanning

### 12.1 Create baseline support

- [ ] Generate a baseline from the default branch. _(PDF p. 23)_
- [ ] Store baseline findings by fingerprint. _(PDF p. 23)_
- [ ] Compare pull-request findings to the baseline. _(PDF p. 23)_
- [ ] Detect new findings. _(PDF p. 23)_
- [ ] Detect removed findings. _(PDF p. 23)_
- [ ] Detect worsened findings. _(PDF p. 23)_
- [ ] Detect newly reachable findings. _(PDF p. 23)_
- [ ] Detect newly exploited dependencies. _(PDF p. 23)_
- [ ] Detect expired suppressions. _(PDF p. 23)_
- [ ] Detect scanner coverage regressions. _(PDF p. 23)_

### 12.2 Gate new risk by default

- [ ] Add gate-mode: new. _(PDF p. 23)_
- [ ] Add gate-mode: all. _(PDF p. 23)_
- [ ] Add gate-mode: worsened. _(PDF p. 23)_
- [ ] Add gate-mode: policy. _(PDF p. 23)_
- [ ] Allow explicit legacy-risk enforcement. _(PDF p. 23)_
- [ ] Show baseline age. _(PDF p. 23)_
- [ ] Fail when the baseline is invalid or incompatible. _(PDF p. 23)_
- [ ] Existing repositories can adopt the product without immediately fixing every historical finding. _(PDF p. 23)_
- [ ] Newly introduced high-risk findings still block the pull request. _(PDF p. 23)_

## Phase 13 - Build the finding lifecycle

### 13.1 Implement finding states

- [ ] Record state history. _(PDF p. 24)_
- [ ] Record actor. _(PDF p. 24)_
- [ ] Record timestamp. _(PDF p. 24)_
- [ ] Record reason. _(PDF p. 24)_
- [ ] Record evidence. _(PDF p. 24)_
- [ ] Record approval where required. _(PDF p. 24)_
- [ ] Record expiry. _(PDF p. 24)_
- [ ] Support automatic reopening. _(PDF p. 24)_

### 13.2 Implement suppressions

- [ ] Finding fingerprint _(PDF p. 24)_
- [ ] Reason _(PDF p. 24)_
- [ ] Author _(PDF p. 24)_
- [ ] Creation date _(PDF p. 24)_
- [ ] Expiry date _(PDF p. 24)_
- [ ] Scope _(PDF p. 24)_
- [ ] Approval _(PDF p. 24)_
- [ ] Evidence _(PDF p. 24)_
- [ ] Revalidation rule _(PDF p. 24)_
- [ ] Prevent permanent suppression by default. _(PDF p. 24)_
- [ ] Add suppression linting. _(PDF p. 24)_
- [ ] Add suppression-expiry warnings. _(PDF p. 24)_
- [ ] Reopen when code meaningfully changes. _(PDF p. 24)_
- [ ] Reopen when reachability changes. _(PDF p. 24)_
- [ ] Reopen when KEV status changes. _(PDF p. 24)_
- [ ] Reopen when exploit evidence changes. _(PDF p. 24)_
- [ ] Reopen when policy changes. _(PDF p. 24)_
- [ ] Expired suppressions automatically re-enter evaluation. _(PDF p. 24)_
- [ ] Every suppression is auditable. _(PDF p. 24)_
- [ ] A suppression cannot silently apply to unrelated findings. _(PDF p. 25)_

## Phase 14 - Add GitHub-native integration

### 14.1 Generate SARIF

- [ ] Map supported findings to SARIF 2.1.0. _(PDF p. 25)_
- [ ] Validate generated SARIF. _(PDF p. 25)_
- [ ] Include rule metadata. _(PDF p. 25)_
- [ ] Include precise locations. _(PDF p. 25)_
- [ ] Include severity. _(PDF p. 25)_
- [ ] Include remediation guidance. _(PDF p. 25)_
- [ ] Include fingerprints. _(PDF p. 25)_
- [ ] Include partial fingerprints. _(PDF p. 25)_
- [ ] Upload results to GitHub code scanning. _(PDF p. 25)_
- [ ] Findings appear in GitHub’s Security tab. _(PDF p. 25)_
- [ ] Findings annotate pull-request code where locations exist. _(PDF p. 25)_

### 14.2 Add GitHub Checks integration

- [ ] Gate result _(PDF p. 25)_
- [ ] Scanner-health summary _(PDF p. 25)_
- [ ] New findings _(PDF p. 25)_
- [ ] Blocking findings _(PDF p. 25)_
- [ ] Suppressed findings _(PDF p. 25)_
- [ ] Unscored findings _(PDF p. 25)_
- [ ] Evidence explanations _(PDF p. 25)_
- [ ] Links to detailed artefacts _(PDF p. 25)_
- [ ] Policy information _(PDF p. 25)_
- [ ] Baseline comparison _(PDF p. 25)_
- [ ] Developers can understand the release decision without downloading an artefact. _(PDF p. 25)_
- [ ] Branch protection can require the Trust Gate check. _(PDF p. 25)_

### 14.3 Add pull-request comments carefully

- [ ] Post one consolidated comment. _(PDF p. 25)_
- [ ] Update the existing comment instead of creating duplicates. _(PDF p. 25)_
- [ ] Keep the summary concise. _(PDF p. 25)_
- [ ] Collapse long details. _(PDF p. 26)_
- [ ] Link to exact code locations. _(PDF p. 26)_
- [ ] Avoid exposing secrets. _(PDF p. 26)_
- [ ] Avoid posting proprietary source excerpts unnecessarily. _(PDF p. 26)_
- [ ] Include remediation status. _(PDF p. 26)_
- [ ] Repeated runs update one comment. _(PDF p. 26)_
- [ ] Pull requests are not flooded with scanner messages. _(PDF p. 26)_

## Phase 15 - Generate standard security artefacts

### 15.1 Generate SBOMs

- [ ] CycloneDX JSON _(PDF p. 26)_
- [ ] SPDX JSON _(PDF p. 26)_
- [ ] Direct dependencies _(PDF p. 26)_
- [ ] Transitive dependencies _(PDF p. 26)_
- [ ] Versions _(PDF p. 26)_
- [ ] Licences _(PDF p. 26)_
- [ ] Package URLs _(PDF p. 26)_
- [ ] Hashes _(PDF p. 26)_
- [ ] Dependency relationships _(PDF p. 26)_

### 15.2 Generate VEX

- [ ] Generate CycloneDX VEX. _(PDF p. 26)_
- [ ] Record exploitability status. _(PDF p. 26)_
- [ ] Record justification. _(PDF p. 26)_
- [ ] Record analysis state. _(PDF p. 26)_
- [ ] Link VEX decisions to reachability evidence. _(PDF p. 26)_
- [ ] Link VEX decisions to approvals. _(PDF p. 26)_
- [ ] Version and sign VEX output. _(PDF p. 26)_

### 15.3 Generate compliance and audit evidence

- [ ] Commit SHA _(PDF p. 26)_
- [ ] Repository _(PDF p. 26)_
- [ ] Workflow identity _(PDF p. 27)_
- [ ] Timestamp _(PDF p. 27)_
- [ ] Scanner versions _(PDF p. 27)_
- [ ] Scanner health _(PDF p. 27)_
- [ ] Scan configuration _(PDF p. 27)_
- [ ] Policy version _(PDF p. 27)_
- [ ] Baseline version _(PDF p. 27)_
- [ ] Findings _(PDF p. 27)_
- [ ] Suppressions _(PDF p. 27)_
- [ ] Approvals _(PDF p. 27)_
- [ ] Gate result _(PDF p. 27)_
- [ ] SBOM _(PDF p. 27)_
- [ ] VEX _(PDF p. 27)_
- [ ] Provenance _(PDF p. 27)_
- [ ] Attestation _(PDF p. 27)_
- [ ] Exclusions _(PDF p. 27)_
- [ ] Data-source timestamps _(PDF p. 27)_
- [ ] Audit evidence is reproducible and verifiable. _(PDF p. 27)_
- [ ] Reports distinguish automated evidence from manual compliance requirements. _(PDF p. 27)_

## Phase 16 - Add safe remediation

### 16.1 Implement deterministic remediation

- [ ] Parameterised SQL queries _(PDF p. 27)_
- [ ] Removal of shell=True _(PDF p. 27)_
- [ ] Safe YAML loading _(PDF p. 27)_
- [ ] Replacement of weak hashing _(PDF p. 27)_
- [ ] Dependency upgrades _(PDF p. 27)_
- [ ] Secure Docker user configuration _(PDF p. 27)_
- [ ] Removal of exposed secrets _(PDF p. 27)_
- [ ] Secure HTTP-header configuration _(PDF p. 27)_
- [ ] Supported rule IDs _(PDF p. 27)_
- [ ] Supported frameworks _(PDF p. 27)_
- [ ] Preconditions _(PDF p. 27)_
- [ ] Transformation _(PDF p. 27)_
- [ ] Tests _(PDF p. 27)_
- [ ] Rollback behaviour _(PDF p. 27)_
- [ ] Risk notes _(PDF p. 27)_
- [ ] Deterministic fixes are covered by before-and-after tests. _(PDF p. 28)_
- [ ] Unsupported code is not modified. _(PDF p. 28)_

### 16.2 Implement guided remediation

- [ ] Why it is vulnerable _(PDF p. 28)_
- [ ] Exploit scenario _(PDF p. 28)_
- [ ] Relevant source and sink _(PDF p. 28)_
- [ ] Secure coding pattern _(PDF p. 28)_
- [ ] Framework-specific example _(PDF p. 28)_
- [ ] CWE reference _(PDF p. 28)_
- [ ] Testing guidance _(PDF p. 28)_
- [ ] Regression risks _(PDF p. 28)_
- [ ] Verification instructions _(PDF p. 28)_

### 16.3 Add AI-assisted remediation

- [ ] Require explicit opt-in. _(PDF p. 28)_
- [ ] Display which code context leaves the runner. _(PDF p. 28)_
- [ ] Support local-model mode. _(PDF p. 28)_
- [ ] Support redaction. _(PDF p. 28)_
- [ ] Generate patches on isolated branches. _(PDF p. 28)_
- [ ] Run formatting. _(PDF p. 28)_
- [ ] Run type checking. _(PDF p. 28)_
- [ ] Run unit tests. _(PDF p. 28)_
- [ ] Run integration tests. _(PDF p. 28)_
- [ ] Rerun relevant security scanners. _(PDF p. 28)_
- [ ] Verify the original finding disappeared. _(PDF p. 28)_
- [ ] Check for new high-risk findings. _(PDF p. 28)_
- [ ] Open a draft pull request. _(PDF p. 28)_
- [ ] Mark the fix as unverified until all checks pass. _(PDF p. 28)_
- [ ] The product never claims an issue is fixed solely because AI generated a patch. _(PDF p. 28)_
- [ ] Failed verification prevents automatic fix completion. _(PDF p. 28)_

## Phase 17 - Expand the benchmark corpus

### 17.1 Build a multilingual benchmark

- [ ] Python _(PDF p. 29)_
- [ ] JavaScript _(PDF p. 29)_
- [ ] TypeScript _(PDF p. 29)_
- [ ] Java _(PDF p. 29)_
- [ ] Go _(PDF p. 29)_
- [ ] Ruby _(PDF p. 29)_
- [ ] C# _(PDF p. 29)_
- [ ] Infrastructure as Code _(PDF p. 29)_
- [ ] Containers _(PDF p. 29)_
- [ ] Kubernetes _(PDF p. 29)_
- [ ] Multiple frameworks _(PDF p. 29)_
- [ ] True vulnerabilities _(PDF p. 29)_
- [ ] Patched equivalents _(PDF p. 29)_
- [ ] Safe lookalikes _(PDF p. 29)_
- [ ] Cross-file cases _(PDF p. 29)_
- [ ] Sanitised cases _(PDF p. 29)_
- [ ] Reachable cases _(PDF p. 29)_
- [ ] Unreachable cases _(PDF p. 29)_
- [ ] Test-only code _(PDF p. 29)_
- [ ] Development-only dependencies _(PDF p. 29)_
- [ ] Production dependencies _(PDF p. 29)_

### 17.2 Create robust labelling procedures

- [ ] Use two independent reviewers. _(PDF p. 29)_
- [ ] Record reviewer decisions. _(PDF p. 29)_
- [ ] Add adjudication for disagreements. _(PDF p. 29)_
- [ ] Measure inter-rater agreement. _(PDF p. 29)_
- [ ] Document labelling rules. _(PDF p. 29)_
- [ ] Record uncertainty. _(PDF p. 29)_
- [ ] Separate public and private benchmark partitions. _(PDF p. 29)_
- [ ] Create blind evaluation sets. _(PDF p. 29)_
- [ ] Prevent benchmark leakage into rule tuning. _(PDF p. 29)_
- [ ] Published benchmark claims are reproducible. _(PDF p. 29)_
- [ ] Every labelled item has review evidence. _(PDF p. 29)_
- [ ] Private evaluation sets remain separated from development data. _(PDF p. 29)_

### 17.3 Automate benchmark execution

- [ ] Run benchmarks on supported scanner upgrades. _(PDF p. 30)_
- [ ] Compare new and previous versions. _(PDF p. 30)_
- [ ] Detect precision regressions. _(PDF p. 30)_
- [ ] Detect recall regressions. _(PDF p. 30)_
- [ ] Detect runtime regressions. _(PDF p. 30)_
- [ ] Block releases when thresholds fail. _(PDF p. 30)_
- [ ] Generate benchmark reports automatically. _(PDF p. 30)_
- [ ] Scanner upgrades cannot silently reduce detection quality. _(PDF p. 30)_
- [ ] Published metrics always identify scanner and dataset versions. _(PDF p. 30)_

## Phase 18 - Add customer-specific calibration

### 18.1 Capture customer feedback

- [ ] Confirmed true positive _(PDF p. 30)_
- [ ] Confirmed false positive _(PDF p. 30)_
- [ ] Accepted risk _(PDF p. 30)_
- [ ] Fixed _(PDF p. 30)_
- [ ] Reopened _(PDF p. 30)_
- [ ] Remediation accepted _(PDF p. 30)_
- [ ] Remediation rejected _(PDF p. 30)_
- [ ] Keep feedback local by default. _(PDF p. 30)_
- [ ] Allow encrypted export. _(PDF p. 30)_
- [ ] Allow deletion. _(PDF p. 30)_
- [ ] Allow repository-specific calibration. _(PDF p. 30)_
- [ ] Allow organisation-specific calibration. _(PDF p. 30)_
- [ ] Keep global and customer-specific confidence separate. _(PDF p. 30)_

### 18.2 Build local calibration models

- [ ] Calculate repository-specific rule reliability. _(PDF p. 30)_
- [ ] Calculate organisation-specific rule reliability. _(PDF p. 30)_
- [ ] Apply Bayesian shrinkage to avoid overfitting. _(PDF p. 30)_
- [ ] Show global and local estimates together. _(PDF p. 30)_
- [ ] Require minimum evidence before local overrides affect gating. _(PDF p. 30)_
- [ ] Record model version. _(PDF p. 30)_
- [ ] Add drift detection. _(PDF p. 30)_
- [ ] Small local samples do not create extreme confidence. _(PDF p. 31)_
- [ ] Customers can inspect and reset calibration data. _(PDF p. 31)_

## Phase 19 - Build deployment modes

### 19.1 Local-only mode

- [ ] All scanning occurs in CI. _(PDF p. 31)_
- [ ] Findings remain local. _(PDF p. 31)_
- [ ] Policies remain local. _(PDF p. 31)_
- [ ] Reporting remains local. _(PDF p. 31)_
- [ ] Threat feeds are cached locally. _(PDF p. 31)_
- [ ] No telemetry is sent without consent. _(PDF p. 31)_

### 19.2 Hybrid mode

- [ ] Source code stays local. _(PDF p. 31)_
- [ ] Only approved finding metadata is uploaded. _(PDF p. 31)_
- [ ] Support field-level redaction. _(PDF p. 31)_
- [ ] Support customer-managed encryption keys. _(PDF p. 31)_
- [ ] Document exact transmitted fields. _(PDF p. 31)_
- [ ] Add upload allowlists. _(PDF p. 31)_

### 19.3 Self-hosted enterprise mode

- [ ] Containerised deployment. _(PDF p. 31)_
- [ ] Database migration tooling. _(PDF p. 31)_
- [ ] Backup and restore. _(PDF p. 31)_
- [ ] SSO or SAML. _(PDF p. 31)_
- [ ] SCIM. _(PDF p. 31)_
- [ ] Role-based access control. _(PDF p. 31)_
- [ ] Audit logging. _(PDF p. 31)_
- [ ] Data-retention settings. _(PDF p. 31)_
- [ ] Offline threat-data import. _(PDF p. 31)_
- [ ] High-availability guidance. _(PDF p. 31)_
- [ ] Security-hardening guide. _(PDF p. 31)_
- [ ] Every feature documents its data-handling behaviour. _(PDF p. 31)_
- [ ] Enterprise users can operate without sending data to the vendor. _(PDF p. 31)_

## Phase 20 - Build team and organisation features

### 20.1 Create the management plane

- [ ] Multi-repository dashboard _(PDF p. 32)_
- [ ] Organisation risk overview _(PDF p. 32)_
- [ ] Repository trends _(PDF p. 32)_
- [ ] Scanner health _(PDF p. 32)_
- [ ] Policy compliance _(PDF p. 32)_
- [ ] Mean time to remediation _(PDF p. 32)_
- [ ] Finding ownership _(PDF p. 32)_
- [ ] Suppression expiry _(PDF p. 32)_
- [ ] Benchmark drift _(PDF p. 32)_
- [ ] Threat-intelligence changes _(PDF p. 32)_

### 20.2 Add integrations

- [ ] Linear _(PDF p. 32)_
- [ ] Jira _(PDF p. 32)_
- [ ] Slack _(PDF p. 32)_
- [ ] Microsoft Teams _(PDF p. 32)_
- [ ] Email _(PDF p. 32)_
- [ ] Webhooks _(PDF p. 32)_
- [ ] SIEM export _(PDF p. 32)_
- [ ] Ticket synchronization _(PDF p. 32)_
- [ ] Findings can be assigned and tracked without duplicate tickets. _(PDF p. 32)_
- [ ] Closing a validated ticket updates finding state safely. _(PDF p. 32)_

## Phase 21 - Add compliance mappings

### Phase-wide Phase-wide requirements and completion criteria

- [ ] OWASP Top 10 _(PDF p. 32)_
- [ ] OWASP ASVS _(PDF p. 32)_
- [ ] OWASP SAMM _(PDF p. 32)_
- [ ] NIST SSDF _(PDF p. 32)_
- [ ] CWE _(PDF p. 32)_
- [ ] PCI DSS _(PDF p. 32)_
- [ ] ISO 27001 _(PDF p. 32)_
- [ ] SOC 2 _(PDF p. 32)_
- [ ] Cyber Essentials _(PDF p. 32)_
- [ ] State what automated evidence supports. _(PDF p. 33)_
- [ ] State what still requires manual verification. _(PDF p. 33)_
- [ ] Do not claim complete compliance. _(PDF p. 33)_
- [ ] Record mapping version. _(PDF p. 33)_
- [ ] Add exportable evidence reports. _(PDF p. 33)_
- [ ] Reports say “evidence available” rather than automatically declaring compliance. _(PDF p. 33)_
- [ ] Framework mappings are reviewed and versioned. _(PDF p. 33)_

## Phase 22 - Documentation and developer experience

### 22.1 Create complete user documentation

- [ ] Five-minute quick start _(PDF p. 33)_
- [ ] GitHub Action installation _(PDF p. 33)_
- [ ] CLI installation _(PDF p. 33)_
- [ ] Configuration reference _(PDF p. 33)_
- [ ] Policy reference _(PDF p. 33)_
- [ ] Scanner compatibility _(PDF p. 33)_
- [ ] DAST safety guide _(PDF p. 33)_
- [ ] Offline operation _(PDF p. 33)_
- [ ] Baseline setup _(PDF p. 33)_
- [ ] Suppression workflow _(PDF p. 33)_
- [ ] Remediation workflow _(PDF p. 33)_
- [ ] Troubleshooting _(PDF p. 33)_
- [ ] Security model _(PDF p. 33)_
- [ ] Privacy model _(PDF p. 33)_
- [ ] Upgrade guide _(PDF p. 33)_
- [ ] Migration guide _(PDF p. 33)_

### 22.2 Add working examples

- [ ] Python Flask _(PDF p. 33)_
- [ ] Python Django _(PDF p. 33)_
- [ ] Node.js _(PDF p. 33)_
- [ ] TypeScript _(PDF p. 33)_
- [ ] Java _(PDF p. 33)_
- [ ] Go _(PDF p. 33)_
- [ ] Docker _(PDF p. 33)_
- [ ] Terraform _(PDF p. 34)_
- [ ] Kubernetes _(PDF p. 34)_
- [ ] Monorepo _(PDF p. 34)_
- [ ] Authenticated DAST _(PDF p. 34)_
- [ ] Offline mode _(PDF p. 34)_
- [ ] Custom policy _(PDF p. 34)_
- [ ] Self-hosted deployment _(PDF p. 34)_
- [ ] Every documented example runs in CI. _(PDF p. 34)_
- [ ] Broken examples block releases. _(PDF p. 34)_

### 22.3 Improve error messages

- [ ] What failed _(PDF p. 34)_
- [ ] Why it likely failed _(PDF p. 34)_
- [ ] Whether security coverage is incomplete _(PDF p. 34)_
- [ ] Whether the gate is trustworthy _(PDF p. 34)_
- [ ] How to resolve it _(PDF p. 34)_
- [ ] Where logs are stored _(PDF p. 34)_
- [ ] Users do not need to inspect source code to understand common failures. _(PDF p. 34)_

## Phase 23 - Testing strategy

### 23.1 Unit tests

- [ ] All parsers _(PDF p. 34)_
- [ ] Severity normalisation _(PDF p. 34)_
- [ ] Fingerprinting _(PDF p. 34)_
- [ ] Deduplication _(PDF p. 34)_
- [ ] Correlation _(PDF p. 34)_
- [ ] Confidence calculations _(PDF p. 34)_
- [ ] Policy evaluation _(PDF p. 34)_
- [ ] Suppression expiry _(PDF p. 34)_
- [ ] Baseline comparison _(PDF p. 34)_
- [ ] Schema validation _(PDF p. 34)_
- [ ] Threat enrichment _(PDF p. 34)_
- [ ] Reachability states _(PDF p. 34)_
- [ ] Remediation rules _(PDF p. 34)_

### 23.2 Integration tests

- [ ] Every scanner adapter _(PDF p. 35)_
- [ ] Missing report _(PDF p. 35)_
- [ ] Malformed report _(PDF p. 35)_
- [ ] Scanner timeout _(PDF p. 35)_
- [ ] Scanner crash _(PDF p. 35)_
- [ ] Empty repository _(PDF p. 35)_
- [ ] Unsupported repository _(PDF p. 35)_
- [ ] Monorepo _(PDF p. 35)_
- [ ] Offline mode _(PDF p. 35)_
- [ ] Baseline comparison _(PDF p. 35)_
- [ ] SARIF upload generation _(PDF p. 35)_
- [ ] SBOM and VEX generation _(PDF p. 35)_

### 23.3 Security tests

- [ ] Command injection _(PDF p. 35)_
- [ ] Path traversal _(PDF p. 35)_
- [ ] Malicious filenames _(PDF p. 35)_
- [ ] Malicious scanner output _(PDF p. 35)_
- [ ] HTML injection _(PDF p. 35)_
- [ ] SARIF injection _(PDF p. 35)_
- [ ] Secret leakage _(PDF p. 35)_
- [ ] Licence bypass _(PDF p. 35)_
- [ ] Policy bypass _(PDF p. 35)_
- [ ] Suppression bypass _(PDF p. 35)_
- [ ] Untrusted pull requests _(PDF p. 35)_
- [ ] Symlink attacks _(PDF p. 35)_
- [ ] Zip-slip attacks _(PDF p. 35)_
- [ ] Resource exhaustion _(PDF p. 35)_
- [ ] DAST target abuse _(PDF p. 35)_
- [ ] Dependency confusion _(PDF p. 35)_

### 23.4 End-to-end tests

- [ ] Clean repository passes. _(PDF p. 36)_
- [ ] New critical vulnerability blocks. _(PDF p. 36)_
- [ ] Legacy vulnerability reports but does not block in new-risk mode. _(PDF p. 36)_
- [ ] Scanner failure blocks. _(PDF p. 36)_
- [ ] DAST confirms a SAST issue. _(PDF p. 36)_
- [ ] Suppression expires and reopens. _(PDF p. 36)_
- [ ] KEV status changes and reprioritises. _(PDF p. 36)_
- [ ] Deterministic fix passes verification. _(PDF p. 36)_
- [ ] Failed fix remains unresolved. _(PDF p. 36)_
- [ ] SARIF appears correctly. _(PDF p. 36)_
- [ ] Evidence bundle verifies successfully. _(PDF p. 36)_
- [ ] End-to-end tests run on every release. _(PDF p. 36)_
- [ ] A release cannot proceed when critical workflows fail. _(PDF p. 36)_

## Phase 24 - Performance and reliability

### 24.1 Improve execution performance

- [ ] Run independent scanners in parallel. _(PDF p. 36)_
- [ ] Cache scanner installations safely. _(PDF p. 36)_
- [ ] Cache threat data. _(PDF p. 36)_
- [ ] Cache dependency graphs. _(PDF p. 36)_
- [ ] Support changed-file scanning. _(PDF p. 36)_
- [ ] Support incremental rescanning. _(PDF p. 36)_
- [ ] Avoid rescanning unchanged packages. _(PDF p. 36)_
- [ ] Add resource limits. _(PDF p. 36)_
- [ ] Track scanner duration. _(PDF p. 36)_

### 24.2 Define reliability targets

- [ ] Add performance benchmarks. _(PDF p. 36)_
- [ ] Add regression thresholds. _(PDF p. 37)_
- [ ] Add reliability dashboards. _(PDF p. 37)_
- [ ] Add failure-rate reporting. _(PDF p. 37)_

## Phase 25 - Product packaging and licensing

### 25.1 Define editions

- [ ] Core scanners _(PDF p. 37)_
- [ ] SARIF _(PDF p. 37)_
- [ ] Basic security gate _(PDF p. 37)_
- [ ] Local reports _(PDF p. 37)_
- [ ] Standard policy packs _(PDF p. 37)_
- [ ] Evidence-based prioritisation _(PDF p. 37)_
- [ ] EPSS and KEV enrichment _(PDF p. 37)_
- [ ] Differential scanning _(PDF p. 37)_
- [ ] Deduplication _(PDF p. 37)_
- [ ] Expiring suppressions _(PDF p. 37)_
- [ ] Guided remediation _(PDF p. 37)_
- [ ] Private repositories _(PDF p. 37)_
- [ ] Multi-repository dashboard _(PDF p. 37)_
- [ ] Central policies _(PDF p. 37)_
- [ ] Assignment _(PDF p. 37)_
- [ ] Integrations _(PDF p. 37)_
- [ ] Finding lifecycle _(PDF p. 37)_
- [ ] Organisation calibration _(PDF p. 37)_
- [ ] Audit logs _(PDF p. 37)_
- [ ] Self-hosting _(PDF p. 37)_
- [ ] SSO _(PDF p. 37)_
- [ ] SCIM _(PDF p. 37)_
- [ ] RBAC _(PDF p. 37)_
- [ ] Data residency _(PDF p. 37)_
- [ ] Compliance evidence _(PDF p. 37)_
- [ ] Custom policy packs _(PDF p. 37)_
- [ ] Enterprise SLA _(PDF p. 37)_

### 25.2 Review licensing architecture

- [ ] Document which components are open source. _(PDF p. 38)_
- [ ] Document which components are proprietary. _(PDF p. 38)_
- [ ] Ensure proprietary functionality is not protected only through client-side orchestration. _(PDF p. 38)_
- [ ] Ensure commercial terms are legally clear. _(PDF p. 38)_
- [ ] Add licence compatibility review for every bundled scanner. _(PDF p. 38)_
- [ ] Add a third-party notices file. _(PDF p. 38)_
- [ ] Add subscription lifecycle tests. _(PDF p. 38)_
- [ ] Add graceful offline validation. _(PDF p. 38)_
- [ ] Add key rotation. _(PDF p. 38)_
- [ ] Add revocation strategy where required. _(PDF p. 38)_
- [ ] Do not allow licensing failure to corrupt security results. _(PDF p. 38)_
- [ ] Users can always access their raw security findings. _(PDF p. 38)_
- [ ] Paid feature failure cannot produce an incorrect clean result. _(PDF p. 38)_
- [ ] Third-party licences are documented. _(PDF p. 38)_

## Phase 26 - Security review and external validation

### 26.1 Perform internal security review

- [ ] Review threat model. _(PDF p. 38)_
- [ ] Review cryptographic usage. _(PDF p. 38)_
- [ ] Review licence verification. _(PDF p. 38)_
- [ ] Review workflow security. _(PDF p. 38)_
- [ ] Review parser trust boundaries. _(PDF p. 38)_
- [ ] Review report rendering. _(PDF p. 38)_
- [ ] Review external network calls. _(PDF p. 38)_
- [ ] Review secret handling. _(PDF p. 38)_
- [ ] Review update mechanisms. _(PDF p. 38)_
- [ ] Review self-hosted deployment. _(PDF p. 38)_

### 26.2 Arrange independent review

- [ ] External code audit _(PDF p. 38)_
- [ ] Penetration test _(PDF p. 38)_
- [ ] Statistical methodology review _(PDF p. 38)_
- [ ] Benchmark labelling review _(PDF p. 38)_
- [ ] Privacy review _(PDF p. 38)_
- [ ] Licensing review _(PDF p. 38)_
- [ ] Publish a responsible summary of findings. _(PDF p. 39)_
- [ ] Fix all critical and high issues. _(PDF p. 39)_
- [ ] Track medium issues with deadlines. _(PDF p. 39)_
- [ ] Retest completed fixes. _(PDF p. 39)_
- [ ] No unresolved critical security findings. _(PDF p. 39)_
- [ ] No unresolved high findings without documented executive acceptance. _(PDF p. 39)_
- [ ] Statistical claims have independent review. _(PDF p. 39)_

## Phase 27 - Release readiness

### 27.1 Prepare release documentation

- [ ] Release notes _(PDF p. 39)_
- [ ] Installation guide _(PDF p. 39)_
- [ ] Migration guide _(PDF p. 39)_
- [ ] Upgrade guide _(PDF p. 39)_
- [ ] Compatibility matrix _(PDF p. 39)_
- [ ] Known limitations _(PDF p. 39)_
- [ ] Security policy _(PDF p. 39)_
- [ ] Support policy _(PDF p. 39)_
- [ ] Data-processing documentation _(PDF p. 39)_
- [ ] Service-level commitments _(PDF p. 39)_
- [ ] Incident-response process _(PDF p. 39)_
- [ ] Responsible-disclosure process _(PDF p. 39)_

### 27.2 Complete release verification

- [ ] All unit tests pass. _(PDF p. 39)_
- [ ] All integration tests pass. _(PDF p. 39)_
- [ ] All security tests pass. _(PDF p. 39)_
- [ ] All end-to-end tests pass. _(PDF p. 39)_
- [ ] Performance targets pass. _(PDF p. 39)_
- [ ] Benchmark thresholds pass. _(PDF p. 39)_
- [ ] Documentation examples pass. _(PDF p. 39)_
- [ ] SBOM is generated. _(PDF p. 39)_
- [ ] Provenance is generated. _(PDF p. 39)_
- [ ] Artefacts are signed. _(PDF p. 39)_
- [ ] Changelog is updated. _(PDF p. 39)_
- [ ] Version is tagged. _(PDF p. 39)_
- [ ] Release is reproducible. _(PDF p. 39)_
- [ ] Precision by scanner _(PDF p. 40)_
- [ ] Precision by rule _(PDF p. 40)_
- [ ] Precision by language _(PDF p. 40)_
- [ ] Precision by framework _(PDF p. 40)_
- [ ] Recall by vulnerability category _(PDF p. 40)_
- [ ] F1 score _(PDF p. 40)_
- [ ] Confidence calibration error _(PDF p. 40)_
- [ ] Brier score _(PDF p. 40)_
- [ ] False-positive reduction _(PDF p. 40)_
- [ ] False-negative escape rate _(PDF p. 40)_
- [ ] Scanner failure rate _(PDF p. 40)_
- [ ] Partial-scan rate _(PDF p. 40)_
- [ ] Median scan duration _(PDF p. 40)_
- [ ] p95 scan duration _(PDF p. 40)_
- [ ] Time to first result _(PDF p. 40)_
- [ ] Mean time to remediation _(PDF p. 40)_
- [ ] Gate override rate _(PDF p. 40)_
- [ ] Suppression expiry rate _(PDF p. 40)_
- [ ] Reopened finding rate _(PDF p. 40)_
- [ ] Autofix acceptance rate _(PDF p. 40)_
- [ ] Autofix verification rate _(PDF p. 40)_
- [ ] Developer hours saved _(PDF p. 40)_
- [ ] Security engineer hours saved _(PDF p. 40)_
- [ ] Scanner failures cannot appear as clean scans. _(PDF p. 41)_
- [ ] Missing or malformed reports are detected. _(PDF p. 41)_
- [ ] Dependencies and Actions are pinned. _(PDF p. 41)_
- [ ] Releases are signed and attested. _(PDF p. 41)_
- [ ] The product has passed an independent security review. _(PDF p. 41)_
- [ ] Confidence scores use statistically defensible methods. _(PDF p. 41)_
- [ ] Sample sizes and intervals are visible. _(PDF p. 41)_
- [ ] Scanner reliability is separate from exploitability. _(PDF p. 41)_
- [ ] Published benchmark figures are consistent. _(PDF p. 41)_
- [ ] Benchmark results are reproducible. _(PDF p. 41)_
- [ ] Installation is documented and tested. _(PDF p. 41)_
- [ ] Results appear directly in pull requests. _(PDF p. 41)_
- [ ] SARIF integration works. _(PDF p. 41)_
- [ ] New-risk gating works. _(PDF p. 41)_
- [ ] Errors are actionable. _(PDF p. 42)_
- [ ] Supported examples run successfully. _(PDF p. 42)_
- [ ] Findings are normalised. _(PDF p. 42)_
- [ ] Findings are deduplicated. _(PDF p. 42)_
- [ ] Cross-scanner evidence is correlated. _(PDF p. 42)_
- [ ] Threat intelligence is included. _(PDF p. 42)_
- [ ] Reachability is included where supported. _(PDF p. 42)_
- [ ] Policy decisions are explainable. _(PDF p. 42)_
- [ ] Finding lifecycle exists. _(PDF p. 42)_
- [ ] Suppressions require expiry and evidence. _(PDF p. 42)_
- [ ] Audit history is preserved. _(PDF p. 42)_
- [ ] Policy-as-code is implemented. _(PDF p. 42)_
- [ ] Compliance evidence clearly distinguishes automated and manual controls. _(PDF p. 42)_
- [ ] SARIF is generated. _(PDF p. 42)_
- [ ] CycloneDX SBOM is generated. _(PDF p. 42)_
- [ ] SPDX SBOM is generated. _(PDF p. 42)_
- [ ] VEX is generated. _(PDF p. 42)_
- [ ] Signed evidence bundles are generated. _(PDF p. 42)_
- [ ] JSON schemas are versioned and validated. _(PDF p. 42)_
- [ ] Deterministic fixes are tested. _(PDF p. 42)_
- [ ] Guided remediation is available. _(PDF p. 42)_
- [ ] AI remediation is optional and privacy-controlled. _(PDF p. 42)_
- [ ] Generated fixes are verified before being marked complete. _(PDF p. 42)_
- [ ] Product and research identities are separated. _(PDF p. 42)_
- [ ] Editions and feature boundaries are documented. _(PDF p. 42)_
- [ ] Licensing is reviewed. _(PDF p. 42)_
- [ ] Data-handling modes are documented. _(PDF p. 42)_
- [ ] Local, hybrid and self-hosted modes are defined. _(PDF p. 42)_
- [ ] Support and incident processes are operational. _(PDF p. 42)_

## Required final architecture outcome

- [ ] Repository checkout
- [x] Repository context detection
- [x] Transparent scan plan
- [x] Applicable scanner adapters
- [ ] Scanner-health validation
- [ ] Raw report preservation
- [ ] Schema validation
- [ ] Finding normalisation
- [ ] Stable fingerprinting
- [x] Deduplication and correlation
- [x] Threat-intelligence enrichment
- [ ] Reachability analysis
- [ ] Evidence and confidence calculation
- [ ] Policy-as-code evaluation
- [ ] Release decision
- [ ] SARIF, GitHub Checks, and PR summary
- [ ] SBOM, VEX, and signed evidence bundle
- [ ] Optional verified remediation

## Final completion command

`trustgate project verify-release` must fail unless all of these pass:

- [ ] Schemas
- [ ] Unit tests
- [ ] Integration tests
- [ ] Security tests
- [ ] End-to-end tests
- [ ] Benchmark thresholds
- [ ] Dependency pinning
- [ ] GitHub Action pinning
- [ ] SBOM generation
- [ ] VEX generation
- [ ] SARIF validation
- [ ] Documentation examples
- [ ] Release signatures
- [ ] Provenance
- [ ] Changelog
- [ ] Version consistency

The product must not be described as fully complete until this command succeeds and all manual external-review requirements are recorded.
