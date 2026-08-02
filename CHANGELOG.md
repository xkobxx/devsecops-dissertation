# Changelog

All notable Trust Gate changes are recorded here.

The format follows Keep a Changelog, and package releases follow Semantic
Versioning as described in `docs/VERSIONING.md`.

## [Unreleased]

### Added

- Complete repository, dependency, data-flow, and test-gap audits.
- Exhaustive PDF roadmap status tracking.
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
- CycloneDX product SBOMs plus published SLSA provenance and SBOM attestations.
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
