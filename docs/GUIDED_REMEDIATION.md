# Guided remediation

Trust Gate can generate educational, framework-specific remediation guidance
for a canonical finding without reading or changing repository source files.
Every report is bound to the exact scan-run content and labels every entry
`guidance_only`. Guidance is neither an applied patch nor evidence that a
finding has been fixed.

## Create a guidance request

The request explicitly maps a finding fingerprint to a supported Trust Gate
remediation rule and framework:

```json
{
  "schema_version": "1.0.0",
  "revision": 1,
  "generated_at": "2026-08-04T16:00:00Z",
  "run_id": "run-example",
  "scan_run_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "guidance": [
    {
      "finding_fingerprint": "v1:sha256:example",
      "remediation_rule_id": "TG-PY-SQL-001",
      "framework": "python-sqlite3"
    }
  ]
}
```

The canonical digest is SHA-256 over compact JSON with keys sorted and Unicode
preserved. The request must match the scan's `run_id` and current digest.
Mappings must use a rule and framework published by `trustgate remediate rules`.
The finding's recorded CWE must overlap the profile's applicable CWE set. These
checks prevent stale, cross-framework, or unrelated advice from being emitted.

Generate the versioned report:

```bash
trustgate remediate guide \
  --input reports/findings.json \
  --guidance remediation-guidance.json \
  --output reports/remediation-guidance.json
```

## Report content

Every entry contains:

- why the pattern is vulnerable;
- a concrete exploit scenario;
- the source and sink recorded by the finding;
- a secure coding pattern;
- a framework-specific example;
- direct MITRE CWE references;
- testing guidance;
- regression risks; and
- verification instructions.

Source and sink values come only from `finding.source` and `finding.sink`. When
either field is absent, the report records `unknown` with `not_available`
evidence. It does not reconstruct or invent a flow from the finding title,
description, file, or line number.

The report includes the finding identity, scanner rule, Trust Gate remediation
rule, framework, scan-run digest, repository, commit, explicit generation time,
revision, deterministic report ID, and content digest. Output is validated
against `schemas/remediation-guidance.schema.json` before publication.

## Supported guidance profiles

Guidance is available for the same eight narrow remediation contracts described
in [DETERMINISTIC_REMEDIATION.md](DETERMINISTIC_REMEDIATION.md): Python SQLite,
`subprocess`, PyYAML, `hashlib`, Python requirements, single-stage Dockerfiles,
Python environment-backed secrets, and Flask response headers.

The examples demonstrate a secure pattern; they are not copied from or inserted
into the target repository. They deliberately avoid application-specific names,
credentials, source excerpts, and claims about business logic.

## Verification boundary

Every entry instructs the operator to:

1. review the pattern against the repository's actual framework and data flow;
2. run the listed unit, integration, and regression tests;
3. rerun the scanner rule that produced the finding; and
4. confirm the original fingerprint is absent and no new high-risk finding
   appeared.

The report's top-level limitations state that it does not modify code, does not
prove remediation, and must be verified with repository tests and scanners.
Actual deterministic transformations use the separate content-bound apply and
rollback workflow. AI-assisted changes use the separate, explicitly opt-in,
verification-gated workflow documented in
[AI_REMEDIATION.md](AI_REMEDIATION.md).
