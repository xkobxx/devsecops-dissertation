# Remediation Workflow

TrustGate provides deterministic, repeatable remediation for security findings. All transforms are local-first: no network calls, no AI-generated patches.

## Listing Available Remediations

Review which findings have known fixes before applying anything:

```bash
trustgate remediate --list --findings findings.json
```

Output shows each finding ID, remediation type, and confidence level.

## Applying a Remediation

Apply a fix for a specific finding:

```bash
trustgate remediate --apply --finding-id FINDING-123
```

TrustGate modifies the source in place and records the change in a local remediation log for rollback support.

## Dry-Run Mode

Preview what a remediation would change without modifying any files:

```bash
trustgate remediate --dry-run --finding-id FINDING-123
```

Dry-run prints the unified diff to stdout and exits with code 0 if the transform would succeed.

## Rollback

Revert a previously applied remediation:

```bash
trustgate remediate --rollback --finding-id FINDING-123
```

Rollback restores the original file content from the remediation log. If the file has been modified since the fix was applied, rollback aborts with a conflict warning.

## Remediation Types

| Type | Description | Example |
|---|---|---|
| **Dependency upgrade** | Bumps a pinned version in a manifest file | `requests==2.25.0` to `requests==2.31.0` |
| **Code fix** | Deterministic source transform targeting a known vulnerability pattern | Replacing `subprocess.call(shell=True)` with a safe invocation |
| **Configuration change** | Adjusts a config file to disable an insecure setting | Setting `debug = false` in a production config |

## Deterministic Source Transforms

All code fixes are deterministic: the same finding on the same source always produces the same patch. Transforms are defined as pattern-matching rules, not LLM output. This guarantees:

- **Repeatability** -- re-running a remediation on unchanged source is idempotent.
- **Auditability** -- every transform maps to a documented rule ID in the schema registry.
- **Safety** -- transforms that cannot be applied cleanly (ambiguous match, conflicting edits) fail rather than guess.

## Typical Workflow

```bash
# 1. Scan and produce findings
trustgate scan --output findings.json

# 2. Review available remediations
trustgate remediate --list --findings findings.json

# 3. Preview a specific fix
trustgate remediate --dry-run --finding-id FINDING-123

# 4. Apply the fix
trustgate remediate --apply --finding-id FINDING-123

# 5. Re-scan to confirm resolution
trustgate scan --output findings-after.json
```
