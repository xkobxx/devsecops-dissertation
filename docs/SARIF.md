# SARIF and GitHub code scanning

Trust Gate converts every schema-valid canonical finding into deterministic
SARIF 2.1.0 with `trustgate sarif`. The output declares the official OASIS
SARIF 2.1.0 errata schema and is validated against Trust Gate's strict emitted
profile before it is atomically published. The profile checks the structures
and required fields Trust Gate emits; GitHub's upload boundary performs the
service-side ingestion validation.

```bash
trustgate sarif \
  --input reports/findings.json \
  --output reports/trustgate.sarif
```

The command exits `2` and does not replace the destination when the canonical
scan run or generated SARIF is invalid. Output is stable for the same input:
rules are ordered by rule ID and results by canonical finding fingerprint.

## Mapping contract

| Canonical data | SARIF 2.1.0 data |
| --- | --- |
| Scanner and rule ID | Unique rule ID `<scanner>/<rule_id>` |
| Title and description | Short and full rule descriptions plus result message |
| Normalised severity | `error`, `warning`, or `note` result/rule level |
| Security severity | Numeric `security-severity` rule property for GitHub |
| Category, scanner, and CWE | Sorted rule tags |
| Remediation | Rule help text, guidance, references, and first reference as `helpUri` |
| Repository-relative file and lines | Percent-encoded physical location rooted at `%SRCROOT%` |
| Symbol | Logical function location |
| Canonical fingerprint | Versioned full SARIF fingerprint |
| Stable finding context | SHA-256 partial fingerprint independent of line numbers |
| Repository, ref, commit, trigger, and run ID | Run properties and automation identity |

Critical and high findings map to `error`, medium to `warning`, and low, info,
or unknown to `note`. GitHub-compatible numeric security severities are `9.5`,
`8.0`, `5.5`, `3.0`, `1.0`, and `0.0` respectively. When several findings use
the same scanner rule, the rule default reflects the highest occurrence while
each result retains its own level.

Findings without a repository-relative file remain valid SARIF results but do
not claim a source location. This is common for dependency, container, and
repository-level findings. Only file-backed findings can produce pull-request
line annotations.

## GitHub publication

The composite Action always places `reports/trustgate.sarif` in its dashboard
artifact when canonical findings were produced and exposes the path through the
`sarif-path` output. It does not assume permission to mutate the caller's code
scanning database.

The repository workflow demonstrates the publication boundary. A separate job
downloads the SARIF artifact and invokes the immutable-pinned
`github/codeql-action/upload-sarif` Action with only:

```yaml
permissions:
  contents: read
  security-events: write
```

That job never checks out or executes repository code. It runs for pushes and
same-repository pull requests, causing uploaded findings to appear under the
repository Security tab and file-backed findings to annotate pull-request code.
Fork pull requests keep the build artifact but skip publication because their
token is intentionally read-only. Repository administrators must enable GitHub
code scanning and permit SARIF uploads for the target repository.

SARIF is an exchange view, not Trust Gate's audit source. The canonical scan
run and content-addressed raw evidence remain authoritative and should be
retained with appropriate access controls.
