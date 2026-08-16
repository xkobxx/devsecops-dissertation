# Policy Reference

TrustGate policies are YAML files that define automated pass/fail gates for security findings.

## Policy Structure

```yaml
version: "1.0"
rules:
  - name: rule_name
    type: rule_type
    params:
      key: value
    action: block | warn
```

- **version** — schema version, currently `"1.0"`
- **rules** — ordered list of rules evaluated top-to-bottom; first `block` match fails the gate
- **action** — `block` stops the pipeline, `warn` logs but continues

## Available Rules

| Rule Type | Purpose | Key Params |
|---|---|---|
| `severity_gate` | Block on findings at or above a severity | `threshold`: `critical`, `high`, `medium`, `low` |
| `scanner_required` | Require a minimum number of scanners to have run | `min_scanners`: integer |
| `baseline_comparison` | Detect regressions against a prior baseline | `baseline`: path to baseline JSON |
| `suppression_limit` | Cap the percentage of suppressed findings | `max_percent`: integer (0–100) |
| `finding_threshold` | Set a hard ceiling on total finding count | `max_findings`: integer |

## Example Policy

```yaml
version: "1.0"
rules:
  - name: block-critical
    type: severity_gate
    params:
      threshold: critical
    action: block

  - name: require-two-scanners
    type: scanner_required
    params:
      min_scanners: 2
    action: block

  - name: no-regressions
    type: baseline_comparison
    params:
      baseline: baselines/last-release.json
    action: block

  - name: suppression-cap
    type: suppression_limit
    params:
      max_percent: 10
    action: warn

  - name: finding-ceiling
    type: finding_threshold
    params:
      max_findings: 50
    action: block
```

## Testing a Policy

Validate syntax and rule definitions without evaluating findings:

```bash
trustgate policy --test policy.yaml
```

Returns exit code 0 on valid policy, non-zero with diagnostics on errors.

## Simulating a Policy

Dry-run a policy against a findings file to preview the gate outcome:

```bash
trustgate policy --simulate --policy policy.yaml --findings findings.json
```

Output shows each rule's result (`pass`, `warn`, `block`) and the overall gate decision. No pipeline state is modified.
