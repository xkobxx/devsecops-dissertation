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

### Security

- Private signing keys created by the seller tool now use mode `0600`.
- The current fail-open scanner/report behaviour is documented as a release
  blocker; remediation remains scheduled for Phase 1.
