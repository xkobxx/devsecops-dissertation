# Vulnerability Exploitability eXchange

Trust Gate generates deterministic CycloneDX 1.6 VEX documents from a
canonical scan run and a separate, explicit analysis document. It never turns
missing evidence, an unsuccessful dynamic test, or `NO_PATH_FOUND` into an
automatic `not_affected` assertion. Every emitted decision requires a matching
dependency finding, recorded reachability evidence, and a complete approval.

## Analysis document

The analysis document is versioned and content-bound to exactly one canonical
scan run:

```json
{
  "schema_version": "1.0.0",
  "revision": 1,
  "run_id": "run-example",
  "scan_run_digest": "sha256:<canonical-scan-run-digest>",
  "generated_at": "2026-08-04T12:00:00Z",
  "analyses": [
    {
      "finding_fingerprint": "v2:sha256:<finding-digest>",
      "vulnerability_id": "CVE-2026-1234",
      "exploitability_status": "not_affected",
      "analysis_state": "not_affected",
      "justification": "code_not_reachable",
      "detail": "Reviewed evidence and the remaining limitations.",
      "approval": {
        "actor": "user:security-reviewer@example.test",
        "timestamp": "2026-08-04T11:55:00Z",
        "reason": "Reachability evidence and limitations reviewed."
      }
    }
  ]
}
```

The canonical digest is SHA-256 over UTF-8 JSON with keys sorted and compact
separators. It can be produced with `trustgate.vex.canonical_digest` when
building an analysis document programmatically. Generation rejects a stale
digest or different run ID, unknown or duplicate findings, vulnerability IDs
not present on the finding, missing dependency metadata, and missing
reachability evidence.

Each analysis must use a consistent status/state pair:

| Exploitability status | CycloneDX analysis states | Component version status |
|---|---|---|
| `affected` | `exploitable` | `affected` |
| `not_affected` | `not_affected`, `false_positive` | `unaffected` |
| `under_investigation` | `in_triage` | `unknown` |
| `fixed` | `resolved`, `resolved_with_pedigree` | `unaffected` |

Justification must be one of the CycloneDX impact-analysis justification
values. A `code_not_reachable` assertion is rejected when the canonical
evidence records a confirmed path. Human approval remains required even when
the evidence appears consistent because static reachability is not proof of
exploitability or non-exploitability.

## Generate and sign

Generate an unsigned document for local review:

```shell
trustgate vex \
  --input reports/reachability.json \
  --analyses vex-analyses.json \
  --output reports/trustgate.vex.cdx.json
```

In a trusted CI identity with Sigstore/OIDC available, add `--sign`:

```shell
trustgate vex \
  --input reports/reachability.json \
  --analyses vex-analyses.json \
  --output reports/trustgate.vex.cdx.json \
  --sign
```

The output path must be new. Publication is atomic and `--sign` creates
`trustgate.vex.cdx.json.sigstore.json` through `cosign sign-blob --bundle`.
Consumers must verify the bundle against the expected repository workflow and
OIDC issuer:

```shell
cosign verify-blob reports/trustgate.vex.cdx.json \
  --bundle reports/trustgate.vex.cdx.json.sigstore.json \
  --certificate-identity "<expected-workflow-identity>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Evidence and approval links

Each vulnerability carries content digests for the complete source decision,
canonical scan run, reachability evidence, and approval. The finding
fingerprint, run ID, exploitability status, and reachability status are also
recorded as CycloneDX properties. These fields make later audit comparison
possible without publishing the approval actor or reason in the VEX itself.
Changing the scan, reachability evidence, decision, or approval changes the
corresponding digest and requires a newly approved VEX revision.
