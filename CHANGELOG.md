# Changelog

All notable Trust Gate changes are recorded here.

The format follows Keep a Changelog, and package releases follow Semantic
Versioning as described in `docs/VERSIONING.md`.

## [Unreleased]

### Added

- Complete repository, dependency, data-flow, and test-gap audits.
- Exhaustive PDF roadmap status tracking.
- A versioned, hash-bound multilingual benchmark corpus with 27 cases across
  Python, JavaScript, TypeScript, Java, Go, Ruby, C#, Terraform, Dockerfiles,
  and Kubernetes; distinct vulnerable/patched pairs; safe lookalikes;
  cross-file, sanitised, reachable and unreachable flows; test-only code; and
  production/development dependency scopes, plus fail-closed CLI validation.
- Versioned benchmark-labelling rules, exactly-two-reviewer integrity records,
  file/line evidence, uncertainty, Cohen's kappa, mandatory third-party
  disagreement adjudication, public-blind fixtures, commitment-only private
  partitions, salted label commitments, rule-tuning leakage gates, and
  deterministic labelling/control receipts without fabricated human reviews.
- Installable `trustgate` package and CLI.
- `trustgate aggregate` and `trustgate report` commands.
- Unit and integration coverage for CLI and legacy compatibility entry points.
- Explicit seller-side private-key path support.
- Product migration and versioning documentation.
- Dedicated benchmark fixture directory with safety guidance.
- Hash-locked runtime, development, and scanner dependency sets.
- Scanner compatibility and dependency-upgrade documentation.
- Automated dependency update configuration and immutable-pin validation.
- A common scanner-health model and health evidence in aggregated output.
- Health-aware scanner execution with timeouts, version capture, and separate
  stdout/stderr logs.
- Deterministic versioned source archives, SHA-256 manifests, and keyless
  Sigstore release signatures.
- Deterministic CycloneDX 1.6 and SPDX 2.3 product SBOMs with complete runtime
  dependency graphs, exact versions, reviewed licences, Package URLs, lockfile
  hashes, CLI generation, signed release assets, and published CycloneDX
  attestations.
- Deterministic CycloneDX 1.6 VEX generation with explicit exploitability
  status, analysis state and justification, scan-run and reachability evidence
  binding, approval digests, revisioning, atomic CLI output, and optional
  keyless Sigstore signing.
- Versioned, deterministic audit-evidence manifests covering repository and
  workflow identity, scanner health and configuration, findings, policy gates,
  baselines, suppressions, approvals, SBOM, VEX, provenance, attestations,
  exclusions, and threat-data timestamps, with root-confined artifact paths,
  full integrity verification, and separate manual compliance requirements.
- Content-bound deterministic remediation for parameterised SQLite queries,
  shell-free subprocess calls, safe PyYAML loading, security-purpose hash
  upgrades, hash-locked dependency upgrades, numeric Docker users,
  environment-backed secrets, and Flask response security headers, with
  published rule contracts, strict preconditions, protected backups,
  transaction receipts, verified rollback, and before-and-after safety tests.
- Evidence-bound, versioned guided-remediation reports with explicit
  finding-to-rule mappings, framework and CWE applicability checks, recorded
  source/sink provenance, vulnerability and exploit explanations, secure coding
  patterns, framework examples, CWE links, testing guidance, regression risks,
  verification instructions, deterministic digests, and guidance-only status.
- Explicitly opt-in AI-assisted remediation with reviewable and redacted context
  disclosure, shell-free local and separately authorised remote model modes,
  bounded unified-diff proposals, isolated worktree branches, mandatory
  formatting/type/unit/integration/scanner verification, original-finding and
  new-high-risk regression checks, content-bound receipts, and verified-only
  draft pull-request publication.
- Versioned canonical finding, scan-run, and policy-result schemas with
  migrations, raw-evidence preservation, severity normalization, and stable
  fingerprints.
- A hashed benchmark manifest, explainable multi-signal matching, manual
  adjudication, Beta-Binomial credible intervals, calibration metrics, and
  generated benchmark publications.
- Six separate, report-visible confidence concepts with an acyclic dependency
  model and conservative-bound decisions.
- Conservative cross-scanner correlation with ancestry-aware corroboration.
- Cache-backed OSV, GitHub advisory, NVD, EPSS, and CISA KEV enrichment,
  including offline and privacy-preserving network modes.
- Conservative dependency reachability with direct/transitive, scope,
  deployment, import, vulnerable-symbol, call-path, and limitation evidence.
- Python source-to-sink analysis across files and framework routes, including
  sanitizer, authentication, authorization, confidence, and support metadata.
- DAST-to-static correlation that preserves failed and inconclusive attempts,
  distinguishes authentication blocking, and renders combined evidence.
- `trustgate reachability` and aggregate-time reachability analysis.
- `trustgate dast` for reusable ZAP Automation Framework plans and execution,
  including baseline/API discovery, safe/active modes, preview and production
  controls, authenticated headers, scope allowlists, and bounded resources.
- Opt-in composite Action DAST using a digest-pinned ZAP image with
  authentication-secret redaction and health-aware aggregation.
- A 16-component contextual decision engine with nine versioned outcomes,
  complete rule traces, evidence-strength labels, explicit uncertainty, and
  deterministic reproduction.
- `trustgate decide`, a standalone decision schema, scan-run decision summaries,
  custom policy snapshots, and report-visible policy explanations.
- A public JSON/YAML policy-as-code schema with 17 typed predicates,
  exact-version inheritance, organisation defaults, repository overrides,
  deterministic simulation and explanation, and saved-finding policy tests.
- `trustgate policy validate`, `simulate`, `explain`, and `test` commands.
- Ten packaged standard policy packs with `pack:<name>` aliases, per-pack
  documentation, saved-finding expectations, and explicit compliance limits.
- Versioned, content-bound default-branch baselines keyed by finding fingerprint,
  plus deterministic pull-request comparison for finding transitions, expired
  suppressions, and scanner coverage regressions.
- `trustgate baseline create`, `compare`, and `gate` commands, with new-risk
  gating by default, `all`, `worsened`, and policy modes, optional legacy-risk
  enforcement, baseline-age reporting, and fail-closed coverage regression.
- Immutable finding-state history with actor, timestamp, reason, evidence,
  approval, expiry, chronological integrity validation, and automatic reopening
  when the current state expires.
- Versioned, content-bound suppression records with exact finding/repository
  scope, optional branch/path/environment narrowing, explicit permanent-risk
  authorization, lint and expiry warnings, and automatic reopening when code,
  reachability, KEV, exploit evidence, policy, or expiry changes.
- `trustgate suppression create`, `lint`, `apply`, and `revalidate` commands.
- Deterministic `trustgate sarif` generation with strict emitted-profile
  validation, security rule metadata, remediation guidance, precise source
  locations, and full and partial fingerprints.
- Composite Action SARIF output/artifact publication and an isolated,
  least-privilege GitHub code-scanning upload job with safe fork behavior.
- A bounded `trustgate checks` Markdown renderer and stable `Trust Gate` Actions
  Check Run covering the gate decision, scanner health, new, blocking,
  suppressed and unscored findings, policy, evidence explanations, baseline
  comparison, and artifact links, including merge-queue support.
- A bounded `trustgate pr-comment` renderer and least-privilege workflow upsert
  for one bot-owned, marker-bearing pull-request summary with collapsed detail,
  exact code links, remediation availability, and no source or evidence excerpts.

### Changed

- Moved reusable aggregation, reporting, licensing, issuance, and proprietary
  scoring logic under `src/trustgate/`.
- Retained existing script paths as thin wrappers for Action compatibility.
- Separated the deliberately vulnerable Flask fixture from production code.
- Renamed public-facing product text from DevSecOps Trust Gate to Trust Gate.
- Replaced production-like confidence claims with explicit experimental limits.
- Pinned third-party Actions to commits and container images to registry digests.
- Missing or malformed required scanner reports now fail the gate by default.
- Composite Action scanner crashes and timeouts can no longer become clean
  results through broad shell error suppression.
- Byte-identical benchmark runs no longer inflate statistical maturity, and
  contradictory generated precision figures block release publication.
- Policy results explicitly expose stale or degraded threat-feed context.

### Security

- Private signing keys created by the seller tool now use mode `0600`.
- Required scanner failures, malformed reports, unsafe workflow inputs, and
  inconsistent benchmark publications now fail closed.
- Threat-feed requests use an HTTPS host allowlist and never include source
  code, file paths, scanner excerpts, or raw reports.
