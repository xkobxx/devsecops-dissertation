# Audit evidence

Trust Gate generates a deterministic, content-addressed audit manifest from a
declared evidence root. The manifest records what the product can verify
automatically and lists manual compliance obligations separately. It does not
claim that collecting scanner output automatically proves regulatory
compliance.

## Generate a manifest

Create `audit-evidence.json` with this versioned shape. Every artifact path must
be relative to `--root`; absolute paths, parent traversal, missing files, and
symlinks resolving outside the root are rejected.

```json
{
  "schema_version": "1.0.0",
  "generated_at": "2026-08-04T13:00:00Z",
  "workflow_identity": "https://github.com/example/service/.github/workflows/security.yml@refs/heads/main",
  "scan_run": "reports/findings.json",
  "scan_configuration": "reports/scan-configuration.json",
  "policy_result": "reports/policy-result.json",
  "baseline": "reports/baseline.json",
  "suppressions": ["reports/suppressions/approved.json"],
  "approvals": ["reports/approvals/vex-review.json"],
  "sboms": ["release/trustgate.cdx.json", "release/trustgate.spdx.json"],
  "vex": "release/trustgate.vex.cdx.json",
  "provenance": ["release/provenance.json"],
  "attestations": ["release/attestation.json"],
  "exclusions": "reports/exclusions.json",
  "manual_requirements": [
    {
      "id": "change-approval",
      "requirement": "Confirm production change-board approval.",
      "owner": "release-management",
      "status": "complete",
      "evidence": ["compliance/change-approval.json"]
    }
  ]
}
```

Generate the manifest:

```bash
trustgate evidence generate \
  --root . \
  --config audit-evidence.json \
  --output reports/audit-evidence.json
```

The input requires both CycloneDX 1.6 and SPDX 2.3 SBOMs, a CycloneDX VEX
document bound to the same scan-run content, provenance, an attestation, a
verified default-branch baseline, policy output, scan configuration, and an
explicit exclusions document. Suppression lists may be empty. At least one
approval digest must be available from a suppression, an approval artifact, or
the VEX document.

The generation timestamp is explicit rather than read from the system clock.
Given the same configuration and artifact bytes, generation produces the same
manifest and evidence digest.

## Verify a manifest

```bash
trustgate evidence verify \
  --root . \
  --manifest reports/audit-evidence.json
```

Verification checks the versioned `audit-evidence` JSON Schema, recomputes the
canonical manifest digest and identifier, resolves every artifact beneath the
declared root, and compares its SHA-256 digest and byte length. A moved root is
supported because the manifest stores only normalized relative paths.

## Recorded evidence

The `automated_evidence` section records repository, commit, ref, workflow
identity, generation and scan timestamps, scanner versions and health, scan
configuration, findings and severity counts, exclusions, policy version and
gate result, baseline version, suppressions, approval digests, SBOMs, VEX,
provenance, attestations, and threat-data source timestamps.

The `manual_compliance_requirements` section has its own owner, status, and
evidence references. Artifact descriptors label their source as `automated` or
`manual`. A `complete` manual requirement must reference evidence; `required`
and `not_applicable` requirements can be recorded without an evidence file.

Approval digests are retained in the automated record without copying approval
actors or reasons into the summary. The referenced approval artifacts remain
available to authorized auditors through the evidence set's access controls.
