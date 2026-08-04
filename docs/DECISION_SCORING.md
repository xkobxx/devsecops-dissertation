# Contextual decision scoring

Trust Gate evaluates findings with explicit policy rules. It does not add the
inputs together into an unexplained risk number. Every result stores the input
snapshot, the policy snapshot, the matched rule, the complete evaluation trace,
evidence strength, unresolved uncertainty, and a reproduction digest.

The built-in policy is `trustgate-contextual-default@1.0.0`. It is intentionally
conservative and is an in-process Phase 10 policy contract. Phase 11 will add the
full supported policy-as-code file format and broader rule vocabulary.

## Decision context

Every finding is evaluated with all 16 roadmap components. An unavailable value
is stored as `null` with an uncertainty reason; it is never silently interpreted
as `false` or low risk.

| Component | Canonical source or runtime context |
|---|---|
| Finding-validity confidence | Conservative bound, then estimate, then legacy finding confidence |
| Original severity | Scanner-native `original_severity` |
| Normalised severity | Canonical `normalised_severity` |
| Reachability | Canonical reachability and its separately stored evidence |
| EPSS | Threat-intelligence probability or an explicit runtime value |
| CISA KEV | Threat-intelligence KEV status or an explicit runtime value |
| Public exploit availability | Runtime/deployment context |
| Internet exposure | Runtime/deployment context |
| Authentication requirements | Runtime/deployment context |
| Data sensitivity | Runtime/deployment context |
| Asset criticality | Runtime/deployment context |
| Runtime environment | Local, preview, staging, production, or another policy value |
| Existing controls | Explicit list; an empty list means known to have no listed controls |
| Fix availability | Explicit context, fixed versions, or structured remediation evidence |
| New versus existing status | Explicit change context |
| Human triage state | Explicit context or canonical finding status |

Runtime context overrides deployment-oriented values without rewriting the
source finding. Shared values apply to every finding and `findings` entries
override them by finding ID.

## Built-in outcome rules

Rules are evaluated in order. The first matching rule selects the outcome, but
the result retains the evaluation of every rule so users can inspect alternatives
and failed conditions.

| Outcome | Default `1.0.0` rule |
|---|---|
| `TEMPORARILY_SUPPRESSED` | Human triage state is `suppressed`. Phase 13.1 records the approved state and expiry; Phase 13.2 adds suppression policy and revalidation. |
| `ACCEPTED_RISK` | Human triage state is `accepted_risk`. The human state remains visible in the stored context. |
| `LIKELY_NOISE` | Human triage state is `false_positive`. Trust Gate does not infer noise solely from a low scanner score. |
| `INSUFFICIENT_EVIDENCE` | Finding-validity confidence is unavailable. Missing data is not converted to a pass. |
| `BLOCK_IMMEDIATELY` | A high/critical, reachable, unauthenticated, internet-exposed production issue is in CISA KEV; or a high/critical, reachable, internet-exposed production issue has a public exploit. |
| `FIX_BEFORE_RELEASE` | A high/critical reachable issue is new in the evaluated change. |
| `FIX_WITHIN_SLA` | A fix is available for a high/critical issue not selected by an earlier rule. SLA duration is a Phase 11 policy concern. |
| `MONITOR` | A low/info finding is explicitly not internet exposed. |
| `INVESTIGATE` | An open or acknowledged finding needs human review, or no more specific rule matches. |

Known controls, data sensitivity, asset criticality, authentication, EPSS, and
the remaining context stay in the decision snapshot even when the selected
default rule does not use them. A policy can reference any component with the
supported `equals`, `not_equals`, `in`, `gte`, `lte`, `contains`, and `is_known`
operators.

## Evidence strength and uncertainty

Evidence strength describes context completeness, not risk:

- `strong`: at least 14 known components and validity lower bound at least 0.70;
- `moderate`: at least 10 known components and validity lower bound at least 0.40;
- `weak`: at least 6 known components;
- `insufficient`: fewer than 6 known components.

The decision also lists every component that remains uncertain. The HTML report
shows the outcome, policy ID/version, matched rule, explanation, evidence
strength, uncertainty, and reproduction digest.

## Reproducibility and tamper detection

`contextual_decision` stores the complete context and policy snapshot. Its
`decision_id` and `reproduction_digest` are the SHA-256 digest of those canonical
JSON snapshots. `reproduce_decision` re-evaluates them and rejects changed
evidence, policy, outcome, explanation, or trace data.

The standalone decision and enriched scan run are validated against
`schemas/decision.schema.json` and `schemas/scan-run.schema.json` before atomic
publication. `summary.decision_analysis` records policy identity, counts for all
nine outcomes, evidence-strength counts, and the number of findings with
unresolved uncertainty.

## CLI usage

Create deployment context without editing the scan run:

```json
{
  "shared": {
    "runtime_environment": "production",
    "internet_exposure": true,
    "authentication_requirements": false,
    "data_sensitivity": "restricted",
    "asset_criticality": "critical",
    "existing_controls": ["waf"],
    "public_exploit_availability": false,
    "fix_availability": true,
    "new_existing_status": "new"
  },
  "findings": {
    "finding-001": {
      "authentication_requirements": true
    }
  }
}
```

Evaluate and persist decisions:

```bash
trustgate decide \
  --input reports/reachability.json \
  --runtime-context deployment-context.json \
  --output reports/decisions.json
```

`--policy policy-snapshot.json` accepts the inspectable Phase 10 policy snapshot
shape emitted inside a decision. Unknown context sections, invalid policy rules,
and schema-invalid output fail closed.

## Current boundary

Phase 10 provides deterministic contextual outcomes, not the complete policy
product. Phase 11 will define the public policy schema, repository and branch
selectors, scanner-health conditions, secret validation, suppression expiry,
policy precedence, and policy test tooling. Until then, custom snapshots should
be treated as an internal versioned interface rather than a stable authoring
contract.
