# Canonical JSON Schemas

Trust Gate publishes three JSON document types using JSON Schema Draft 2020-12:

| Document | Schema | Current version |
|---|---|---:|
| Finding | `schemas/finding.schema.json` | `1.0.0` |
| Scan run | `schemas/scan-run.schema.json` | `1.0.0` |
| Policy result | `schemas/policy-result.schema.json` | `1.0.0` |

`schemas/registry.json` is the version registry used by the runtime. Every
document carries a required `schema_version`, and every schema has a versioned
canonical `$id`. Unknown document versions fail closed; the runtime does not
silently interpret a future contract as the current one.

## Publication contract

`trustgate aggregate` writes:

- `reports/findings.json`: a canonical scan-run document. The historical
  filename is retained for Action compatibility.
- `reports/policy-result.json`: the explainable result of the configured
  severity and scanner-failure policy.

Every adapter finding is validated after parsing and again after scanner-version
metadata is attached. Invalid adapter output becomes a scanner parser error,
which cannot be interpreted as a clean scan. The complete scan run and policy
result are both validated before either is published. JSON publication uses a
temporary file followed by an atomic replacement.

The scan-run `findings` array remains available to report consumers. Scanner
health is now under `scanners`, and aggregate counts are under `summary`.
Before publication, findings are exactly deduplicated and conservatively
correlated. Optional Phase 6 fields preserve occurrence locations, all raw
evidence references, source finding IDs, scanner agreement, match reasons, and
bounded corroboration evidence. See `docs/CORRELATION.md`.

## Raw reports and normalisation evidence

Before parsing, every produced scanner report is copied byte-for-byte to:

```text
<reports-directory>/raw/<scanner>-<sha256>.<extension>
```

The SHA-256 digest in the filename makes the archive content-addressed. A later
scan that rewrites the scanner's working report creates a new archive object;
it does not overwrite the earlier object. Empty and malformed reports are
archived as well, so a parser failure cannot erase the input needed to
investigate it. Archive objects are written atomically, made read-only, and
existing objects must still match their digest.

Each canonical finding's `raw_report_reference` contains the archive path,
digest, and scanner finding identifier when one exists. The scanner result's
`report_path` also points at the archive object after preservation. Raw reports
can contain source excerpts, dependency metadata, or detected secrets and
should therefore inherit the access controls and retention policy of the scan
run.

Transformations are additive. The original scanner value remains in the
canonical field intended for original data, while an `evidence` item with
`kind: "normalisation"` records:

- the canonical destination field;
- the source JSON path in `reference`;
- the exact source value in `excerpt`;
- the transformation and resulting canonical value in `summary`.

These records do not replace the raw report. They explain how Trust Gate derived
values such as `normalised_severity` or classified advisory identifiers while
the content-addressed report remains the authoritative audit source.

Available CVSS metrics are retained as `evidence` items with `kind: "cvss"`.
See `docs/SEVERITY_NORMALISATION.md` for precedence and score ranges.

New findings use the versioned, line-stable `v2:sha256` correlation algorithm.
See `docs/FINGERPRINTS.md` for identity inputs and explicit migration.

### Optional redaction

Pass `--redact-sensitive-content` to `trustgate aggregate`, or set the composite
Action input `redact-sensitive-content: true`, to create a separate
content-addressed view under `reports/redacted/`. Fields whose scanner-report
keys identify secrets, tokens, passwords, API keys, private keys,
authorization data, credentials, or matched secret material are replaced with
`[REDACTED]`. Non-sensitive report structure remains intact.

Redaction never edits or replaces `reports/raw/`. Findings retain their
`raw_report_reference` for authorized audit and add a `redacted_report` evidence
reference for ordinary consumption. With redaction enabled, scanner-result
`report_path` points to the redacted view. The composite Action uploads the
redacted view with the dashboard and stores raw scanner evidence in a separate
artifact. Raw artifacts inherit the repository's normal GitHub Actions artifact
permissions; operators must treat them as sensitive and configure repository
access and retention accordingly.

## Runtime API

```python
from trustgate.schema import (
    migrate_finding,
    migrate_scan_run,
    validate_instance,
    write_validated_json,
)

canonical = migrate_scan_run(legacy_document)
validate_instance("scan-run", canonical)
write_validated_json("findings.json", canonical, schema_name="scan-run")
```

`migrate_finding` and `migrate_scan_run` accept the unversioned legacy format and
produce version `1.0.0`. Passing a document with an unknown explicit version is
an error rather than a guessed migration. Current documents are validated and
returned as defensive copies, making migration idempotent.

## Null and absent values

Phase 2 canonical finding fields are required. Scanner data that is genuinely
unavailable is represented by the field’s documented `null` value or an empty
collection. An absent required field therefore indicates an invalid adapter or
document, not “no data”.

Phase 3 adds six optional confidence-component fields so existing `1.0.0`
findings remain valid. When confidence scoring runs, all six are published
together and each component object is fully required and validated. See
`docs/CONFIDENCE_METHODOLOGY.md`.

Phase 6 adds optional correlation and provenance fields to the backward-
compatible `1.0.0` contract. Parser findings without these fields remain valid;
canonical scan-run construction populates them before publication.

## Packaging

The source schemas live under `schemas/` and are installed under
`share/trustgate/schemas`. Runtime loading is independent of the caller’s
working directory.
