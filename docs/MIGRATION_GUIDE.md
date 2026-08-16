# Migration Guide

This guide covers migrating from ad-hoc security gating scripts and CI-only
workflows to Trust Gate's local-first, policy-as-code model.

## Importing Existing SARIF Results

Trust Gate ingests raw scanner reports from a directory. Place existing SARIF
files (or any supported scanner output) in a reports directory and aggregate:

```bash
trustgate aggregate --reports-dir ./existing-reports --output findings.json
```

To produce a SARIF file from the canonical output:

```bash
trustgate sarif --input findings.json --output trustgate.sarif
```

## Policy Migration

### From a severity-gate script

A typical bash gate looks like this:

```bash
# Old approach
if grep -q '"severity": "critical"' report.json; then exit 1; fi
```

The equivalent Trust Gate aggregate flag:

```bash
trustgate aggregate --reports-dir reports --fail-on critical
```

To move beyond severity thresholds, convert to a policy file. A minimal
`policy.yml` replacing `--fail-on high`:

```yaml
schema_version: 1.0.0
policy_id: migrated-gate
policy_version: 1.0.0
default_action: monitor

policies:
  - name: block-high-and-above
    action: block
    when:
      severity: [critical, high]
```

Validate and test the policy before adopting it:

```bash
trustgate policy --validate policy.yml
trustgate decide --policy policy.yml --input reports/findings.json
```

### From custom bash pipelines

Replace multi-step shell pipelines with the Trust Gate command chain:

```bash
# 1. Aggregate scanner output
trustgate aggregate --reports-dir reports

# 2. Evaluate policy
trustgate decide --policy policy.yml --input reports/findings.json

# 3. Generate SARIF for IDE consumption
trustgate sarif --input reports/findings.json
```

Each step produces a canonical JSON file that the next step consumes,
replacing fragile `jq` and `grep` chains.

## Baseline Migration

Import an existing suppression list by creating a baseline from a clean
default-branch scan:

```bash
trustgate aggregate --reports-dir reports
trustgate baseline create --input reports/findings.json --default-branch main
```

On subsequent pull requests, compare against the baseline so only new
findings trigger the gate:

```bash
trustgate baseline compare --baseline reports/baseline.json --input reports/findings.json
trustgate baseline gate --baseline reports/baseline.json --input reports/findings.json --gate-mode new
```

For individual finding suppressions with audit metadata:

```bash
trustgate suppression create --input reports/finding.json \
  --repository org/repo --reason "False positive per manual review" \
  --author "security-team" --approval '{"actor":"lead","timestamp":"2026-08-01T00:00:00Z","reason":"reviewed"}' \
  --evidence '[{"type":"manual_review","url":"https://example.com/ticket-123"}]' \
  --policy-digest "$(sha256sum policy.yml | cut -d' ' -f1)" \
  --expires-at 2027-02-01T00:00:00Z
```

## CI-Only to Local-First Workflow

Trust Gate runs identically on a developer workstation and in CI. To migrate:

1. Install locally: `pip install trustgate`
2. Run scanners and aggregate locally before pushing:
   ```bash
   trustgate aggregate --reports-dir reports
   trustgate decide --policy policy.yml --input reports/findings.json
   ```
3. Keep the same commands in CI. The canonical output format is identical
   regardless of environment.
4. Use `trustgate plan` to preview which scanners apply to the repository
   without executing them.

## Migration Checklist

1. Collect existing scanner reports into a single directory.
2. Run `trustgate aggregate` to verify all reports parse correctly.
3. Write a `policy.yml` that mirrors current gate logic.
4. Validate the policy with `trustgate policy --validate policy.yml`.
5. Create a baseline from the default branch.
6. Replace CI gate scripts with `trustgate decide` and `trustgate baseline gate`.
7. Run locally to confirm results match CI output.
8. Remove legacy scripts.
