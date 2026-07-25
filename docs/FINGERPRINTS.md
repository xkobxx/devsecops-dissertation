# Finding Fingerprints

Trust Gate uses fingerprint algorithm `v2`. Every new canonical finding carries:

- `fingerprint: v2:sha256:<digest>` for cross-report correlation;
- `finding_id: finding-v2-<digest-prefix>` for scanner-specific identity.

The algorithm version is part of the stored value so future implementations can
recognize and explicitly migrate older identities.

## Stability rules

Fingerprint inputs deliberately exclude:

- line numbers;
- severity;
- scanner wording in titles and descriptions;
- timestamps and status;
- dependency version.

This keeps an issue identifiable after nearby lines move, scanner descriptions
change, severity data improves, or an affected dependency version changes.

Repository paths use `/` separators, remove redundant `.` segments, and become
relative to the supplied repository root when possible. Scanner output retains
its original path in normalization evidence and the raw report.

## Correlation identities

Dependency findings use:

- canonical ecosystem (`pip`, `python`, and `pypi` become `pypi`);
- normalized component name;
- the strongest available advisory namespace, preferring CVE, then GHSA, then
  OSV, and finally the scanner rule identifier.

Python component names apply PEP 503-style `-`, `_`, and `.` normalization.
Dependency version and scanner name are excluded, which allows pip-audit and
Trivy reports for the same advisory/package pair to share a fingerprint.

Other findings use:

- category;
- scanner rule identifier;
- normalized repository path;
- symbol, source, and sink when available;
- CWE identifiers.

Keeping the rule identifier prevents unrelated findings in the same file from
being merged. The scanner name is excluded from the correlation fingerprint but
included in `finding_id`, so two scanners can correlate without becoming the
same scanner-specific record.

Fingerprint equality is one correlation input, not the whole Phase 6
consolidation policy. `trustgate.correlation` uses conservative multi-signal
matching for scanner rules whose versioned fingerprints differ, and emits a
`correlation-v1:sha256` cluster identity. See `docs/CORRELATION.md` for the
thresholds and non-merging controls.

## Migration

`trustgate.schema.migrate_fingerprint(finding, repository_root=...)` upgrades a
validated canonical finding whose fingerprint predates `v2`. Migration:

1. computes the current fingerprint and finding ID;
2. normalizes the canonical file path;
3. adds a `fingerprint_migration` evidence item containing the prior
   fingerprint;
4. validates the migrated finding.

Calling it on a current `v2` finding is idempotent and returns a defensive copy.
General schema migration does not silently rewrite an already-versioned
canonical document; callers choose fingerprint migration explicitly.

## Collision testing

The unit suite covers unrelated rules in the same file, path variants,
line/description changes, cross-scanner dependency correlation, and a generated
sample of 1,000 distinct findings. Cryptographic collision resistance comes
from SHA-256; the semantic tests additionally ensure the identity inputs do not
collapse obviously unrelated findings before hashing.
