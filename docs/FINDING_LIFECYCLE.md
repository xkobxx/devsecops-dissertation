# Finding lifecycle

Trust Gate records finding disposition as an append-only history on the
canonical finding. The current `status` remains available for existing
consumers; `state_history` provides the audit trail behind that value.

## States

The supported states are `open`, `acknowledged`, `suppressed`, `resolved`,
`false_positive`, and `accepted_risk`. A history entry records:

- a contiguous sequence number and the previous and new states;
- the actor, UTC timestamp, and non-empty reason;
- structured evidence with a kind, reference, and summary;
- an approval record when one is required;
- an optional expiry and whether the transition was automatic.

Trust Gate requires approval for `suppressed`, `false_positive`, and
`accepted_risk`. The approver, approval timestamp, and approval reason are
retained. Approvals cannot post-date the transition. Expiries must be later than
the transition, and the `open` state cannot expire.

## Python API

State changes return a new canonical finding and never mutate the input:

```python
from datetime import datetime, timezone

from trustgate.lifecycle import FindingState, transition_finding

acknowledged = transition_finding(
    finding,
    to_state=FindingState.ACKNOWLEDGED,
    actor="user:security@example.com",
    reason="Security triage started.",
    evidence=[
        {
            "kind": "ticket",
            "reference": "SEC-42",
            "summary": "Assigned for investigation.",
        }
    ],
    changed_at=datetime.now(timezone.utc),
)
```

The API rejects unsupported or unchanged states, non-chronological history,
sequence gaps, state discontinuities, missing required approvals, and a current
status that disagrees with the final history entry. The finding schema validates
the complete result before it is returned.

## Automatic reopening

`reopen_expired_finding` checks only the expiry on the current state. At or
after that instant it appends an automatic transition back to `open`, attributed
to `system:trustgate`, with evidence referencing the expired history entry. It
returns an independent unchanged copy before expiry or when no expiry exists.

## Suppression records

A suppression is a separate, versioned document bound to one exact finding
fingerprint and repository. It records the reason, author, creation and expiry
times, approval, structured evidence, scope selectors, and the risk context
that must remain unchanged. A canonical digest detects any modification after
approval.

Scope can be narrowed with branch, repository-relative path, and environment
patterns. Empty selector arrays mean no additional restriction, but the exact
fingerprint and repository are always required. Missing context never matches a
non-empty selector.

Create a suppression from a canonical finding and separate approval, evidence,
and optional scope JSON documents:

```bash
trustgate suppression create \
  --input reports/finding.json \
  --output reports/suppression.json \
  --repository example/service \
  --reason "Compensating control during upgrade" \
  --author user:developer@example.com \
  --expires-at 2026-08-10T12:00:00Z \
  --scope suppression-scope.json \
  --approval suppression-approval.json \
  --evidence suppression-evidence.json \
  --policy-digest sha256:<64-hex-characters>
```

Permanent suppressions are rejected by default. `--allow-permanent` is an
explicit escape hatch, and the linter continues to warn about the resulting
ongoing review obligation.

## Lint, apply, and revalidate

```bash
trustgate suppression lint --input reports/suppression.json --warning-days 7
trustgate suppression apply \
  --finding reports/finding.json \
  --suppression reports/suppression.json \
  --output reports/suppressed-finding.json \
  --repository example/service --ref main --environment production
trustgate suppression revalidate \
  --finding reports/suppressed-finding.json \
  --suppression reports/suppression.json \
  --output reports/revalidated-finding.json \
  --repository example/service --ref main --environment production \
  --policy-digest sha256:<64-hex-characters>
```

Linting reports invalid or tampered documents, permanent suppressions, upcoming
expiry, and expired records. Application fails unless the digest, exact
fingerprint, repository, all configured selectors, and recorded risk context
match.

Revalidation automatically returns the finding to `open` when the suppression
expires or when its code-region hash, reachability, CISA KEV status, exploit
evidence, or policy digest changes. The system-authored reopening entry names
every reason and references the suppression ID, so the expired or invalidated
finding immediately re-enters policy and baseline evaluation.
