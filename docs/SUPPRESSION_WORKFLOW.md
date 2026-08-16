# Suppression Workflow

Suppressions let you acknowledge findings that do not require remediation, keeping reports clean without losing audit history.

## Creating a Suppression

```bash
trustgate suppression --create --finding-id FINDING-123 --reason "false positive"
```

Specify a suppression type with `--type`:

```bash
trustgate suppression --create \
  --finding-id FINDING-456 \
  --type accepted_risk \
  --reason "Risk accepted per threat model review TM-2026-04"
```

### Suppression Types

| Type | Use When |
|------|----------|
| `false_positive` | The finding is incorrect; the vulnerability does not exist. |
| `accepted_risk` | The risk is real but formally accepted by a stakeholder. |
| `mitigated` | A compensating control renders the finding non-exploitable. |
| `duplicate` | Another finding already covers this issue. |

If `--type` is omitted, it defaults to `false_positive`.

## Listing Suppressions

```bash
trustgate suppression --list
```

Filter by type or status:

```bash
trustgate suppression --list --type accepted_risk
trustgate suppression --list --expired
```

## Expiry and Revalidation

Suppressions can carry an expiry so they are periodically re-evaluated:

```bash
trustgate suppression --create \
  --finding-id FINDING-789 \
  --type accepted_risk \
  --reason "Accepted until next quarterly review" \
  --expires 90d
```

Accepted duration units: `d` (days), `w` (weeks), `m` (months). When a suppression expires, the finding resurfaces in scan results automatically. Run revalidation explicitly with:

```bash
trustgate suppression --revalidate
```

## Audit Trail

Every suppression records who created it, when, and why. This metadata is preserved in the suppression file and included in evidence exports. Fields tracked:

- `suppressed_by` -- user identity from git config or `--author`
- `suppressed_at` -- ISO 8601 timestamp
- `reason` -- free-text justification (required)
- `expires_at` -- optional expiry timestamp

## Suppression File Format

Suppressions are stored locally in `.trustgate/suppressions.json`:

```json
{
  "version": "1.0",
  "suppressions": [
    {
      "finding_id": "FINDING-123",
      "type": "false_positive",
      "reason": "Test helper, not reachable in production",
      "suppressed_by": "dev@example.com",
      "suppressed_at": "2026-04-15T10:30:00Z",
      "expires_at": null
    }
  ]
}
```

This file should be committed to version control so suppressions are shared across the team and changes are tracked in git history.
