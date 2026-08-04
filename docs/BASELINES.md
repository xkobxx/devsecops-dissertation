# Baseline comparison and differential gates

Trust Gate can capture a canonical scan from the declared default branch and
compare a pull-request scan with it by finding fingerprint. This separates new
or changing risk from historical findings without discarding the historical
evidence.

## Create a baseline

Generate a baseline only from a canonical scan whose ref matches the declared
default branch:

```bash
trustgate baseline create \
  --input reports/default-branch-findings.json \
  --output reports/baseline.json \
  --default-branch main
```

The versioned baseline stores:

- repository, default branch, ref, commit, source run, and generation time;
- complete canonical findings in an object keyed by exact fingerprint;
- complete scanner-health records keyed by scanner name;
- a canonical SHA-256 digest over all baseline content.

Duplicate fingerprints or scanner names are rejected. A missing repository,
commit, or default-branch match is also an error. The source scan is never
modified. Before every comparison, Trust Gate validates the baseline schema,
checks that each index key matches its embedded record, and verifies the digest.

## Compare a pull request

```bash
trustgate baseline compare \
  --baseline reports/baseline.json \
  --input reports/pull-request-findings.json \
  --output reports/baseline-diff.json
```

The comparison requires a canonical scan with `trigger: pull_request` from the
same repository. It emits these deterministic fingerprint sets:

| Set | Meaning |
|---|---|
| `new_findings` | Present in the pull request but absent from the baseline |
| `removed_findings` | Present in the baseline but absent from the pull request |
| `persisting_findings` | Present in both inputs |
| `worsened_findings` | Persisting finding whose normalised severity increased |
| `newly_reachable_findings` | Persisting finding that changed to `reachable` |
| `newly_exploited_dependencies` | Persisting dependency finding that gained KEV, known-exploitation-date, or explicit public-exploit evidence |
| `expired_suppressions` | Current suppressed finding whose lifecycle expiry is at or before comparison time; legacy environment expiry remains supported |
| `scanner_coverage_regressions` | Previously healthy scanner that is now missing or unhealthy |

Severity ordering is `unknown`, `info`, `low`, `medium`, `high`, `critical`.
Every array is fingerprint-sorted. The result records baseline age, source and
current identities, category counts, and a canonical comparison digest.
Identical inputs and comparison time produce byte-equivalent logical results.

## Gate changed risk

The default gate evaluates only findings introduced by the pull request, so an
existing repository can adopt Trust Gate without first resolving every
historical finding:

```bash
trustgate baseline gate \
  --baseline reports/baseline.json \
  --input reports/pull-request-findings.json \
  --output reports/baseline-gate.json \
  --gate-mode new \
  --fail-on high
```

`--gate-mode` supports four strategies:

| Mode | Candidates evaluated |
|---|---|
| `new` | New findings only; this is the default |
| `worsened` | New findings and findings whose severity, reachability, exploitation evidence, or suppression state worsened |
| `all` | Every current finding, including historical risk |
| `policy` | Changed findings evaluated by a public policy-as-code document supplied with `--policy` |

Severity modes block candidates at or above `--fail-on`, which defaults to
`high`. Policy mode blocks the `BLOCK_IMMEDIATELY`, `FIX_BEFORE_RELEASE`, and
`INSUFFICIENT_EVIDENCE` outcomes. `--enforce-legacy-risk` expands `new`,
`worsened`, and `policy` gates to every current finding. Scanner coverage
regressions always fail every mode because missing security evidence must not
appear as a clean result.

The command prints and stores the baseline age. A genuine gate failure exits
with status 1. An invalid digest, schema-invalid input, repository mismatch,
incompatible schema version, or missing policy exits with status 2 and does not
publish a result. Successful gates exit with status 0.

## Safety and operational use

Treat `baseline.json` as release evidence. Store it in a write-controlled,
auditable location and update it only from a successful default-branch scan.
Do not hand-edit a baseline: any content change invalidates its digest.

A baseline cannot prove scanner completeness: coverage regression detects loss
of a previously healthy scanner, while broader scanner selection remains
governed by the scan plan and repository inventory.
