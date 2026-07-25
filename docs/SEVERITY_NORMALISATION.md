# Severity Normalisation

Trust Gate preserves scanner-native severity in `original_severity` and records
the canonical policy value in `normalised_severity`. A missing scanner severity
is `null`/`unknown`; it is never silently promoted to `high` or demoted to
`low`.

## Scanner-native mapping rules

Matching is case-insensitive, while `original_severity` retains the scanner's
exact source string. Any label absent from the relevant table maps to `unknown`.

| Scanner | Scanner value | Canonical value |
|---|---|---|
| Bandit | `HIGH` | `high` |
| Bandit | `MEDIUM` | `medium` |
| Bandit | `LOW` | `low` |
| Semgrep | `ERROR` | `high` |
| Semgrep | `WARNING` | `medium` |
| Semgrep | `INFO` | `info` |
| pip-audit enriched data | `CRITICAL` | `critical` |
| pip-audit enriched data | `HIGH` | `high` |
| pip-audit enriched data | `MEDIUM`, `MODERATE` | `medium` |
| pip-audit enriched data | `LOW` | `low` |
| pip-audit enriched data | `INFO` | `info` |
| pip-audit enriched data | `UNKNOWN` | `unknown` |
| Trivy | `CRITICAL` | `critical` |
| Trivy | `HIGH` | `high` |
| Trivy | `MEDIUM` | `medium` |
| Trivy | `LOW` | `low` |
| Trivy | `UNKNOWN` | `unknown` |
| Gitleaks explicit label | `CRITICAL` | `critical` |
| Gitleaks explicit label | `HIGH` | `high` |
| Gitleaks explicit label | `MEDIUM` | `medium` |
| Gitleaks explicit label | `LOW` | `low` |
| Gitleaks explicit label | `INFO` | `info` |
| Gitleaks explicit label | `UNKNOWN` | `unknown` |

Unversioned findings from an unknown legacy scanner use the compatibility
mapping `CRITICAL→critical`, `HIGH|ERROR→high`,
`MEDIUM|MODERATE|WARNING→medium`, `LOW→low`, `INFO→info`, and
`UNKNOWN→unknown`. This compatibility mapping is not used to reinterpret a
known scanner's undocumented labels.

## Dependency and secret defaults

The standard pip-audit JSON format exposes advisory identifiers, aliases,
descriptions, and fix versions, but does not expose a severity or CVSS field.
Trust Gate therefore emits `original_severity: null` and
`normalised_severity: unknown` for standard pip-audit findings. It does not
invent a severity from the fact that a dependency is vulnerable.

Gitleaks findings likewise remain `unknown` when the report does not include a
severity and neither secret type nor validation supplies a defensible basis. A
secret finding is not automatically `high` merely because its category is
`secrets`.

When Gitleaks has no explicit label, Trust Gate considers its `RuleID` and
`Verified`, `Validated`, or `VerificationStatus` field:

| Secret basis | Verified | Explicitly unverified | Validation absent |
|---|---|---|---|
| Private keys and high-impact provider tokens | `high` | `medium` | `medium` |
| API keys, passwords, credentials and generic tokens | `medium` | `low` | `medium` |
| Unclassified type | `medium` | `unknown` | `unknown` |

An explicit Gitleaks severity always takes precedence over inference.

## Trivy CVSS fallback

Trivy vulnerability records can include:

```json
{
  "Severity": "UNKNOWN",
  "CVSS": {
    "redhat": {
      "V3Vector": "CVSS:3.1/...",
      "V3Score": 9.8
    }
  }
}
```

Trust Gate retains every valid per-source CVSS metric as `evidence` with
`kind: "cvss"`. A scanner-provided textual severity takes precedence. CVSS is
used only when Trivy severity is absent or `UNKNOWN`.

When multiple sources provide valid scores and no usable textual severity is
available, Trust Gate conservatively selects the highest base score. Ties prefer
the newer CVSS version and then a deterministic source name. The selected score
uses the standard qualitative ranges:

| Base score | Trust Gate severity |
|---:|---|
| `0.0` | `info` |
| `0.1–3.9` | `low` |
| `4.0–6.9` | `medium` |
| `7.0–8.9` | `high` |
| `9.0–10.0` | `critical` |

Scores that are non-numeric, non-finite, below zero, or above ten are ignored.
If no valid scanner severity or CVSS score remains, severity stays `unknown`.
The finding's `severity_reason` names the selected CVSS source, version, score,
and canonical result.

Enriched pip-audit-compatible input can also provide `cvss_score`,
`cvss_version`, and `severity_source`, or a per-source `CVSS`/`cvss` object.
The same validation, precedence, and qualitative ranges apply. Standard
pip-audit output remains `unknown` because it does not expose those fields.

## Severity quality

Every adapter emits one `severity_quality` evidence item with a stable
`quality=<value>` indicator and the applied rule:

| Indicator | Meaning |
|---|---|
| `high` | Direct recognized scanner label, or a well-identified verified secret type |
| `medium` | Validated CVSS fallback, or severity inferred from secret type/validation |
| `low` | Missing, explicitly unknown, or unrecognized severity evidence |

This is confidence in the quality of the severity assignment, not confidence
that the finding itself is a true positive.

## Policy basis

The default policy uses `normalised_severity`. Pass
`--severity-basis original`, or set the Action input `severity-basis: original`,
to gate on the scanner-native value after applying that scanner's documented
mapping. CVSS and secret-type inference do not affect an original-basis policy
when the scanner did not supply an original severity. The policy result records
the selected basis in `metadata.severity_basis`.
