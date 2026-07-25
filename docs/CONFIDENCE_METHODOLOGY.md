# Confidence methodology

Trust Gate does not use one unexplained confidence number. A scored canonical
finding can carry six separate component fields:

| Field | Meaning | Evidence |
|---|---|---|
| `scanner_rule_reliability` | How consistently the rule produced valid labelled findings | Versioned benchmark labels, sample size, credible interval |
| `finding_validity_confidence` | How likely this specific finding is real | Rule reliability, independent corroboration, manual validation |
| `reachability_confidence` | Strength of evidence that execution reaches the issue | Data-flow and runtime reachability evidence |
| `exploitability_confidence` | Strength of evidence that the issue is exploitable here | Exploit validation, environment preconditions, known-exploited evidence |
| `remediation_confidence` | Strength of evidence that the proposed fix applies | Remediation references and fix validation |
| `overall_decision_confidence` | Conservative confidence in the resulting decision | The minimum available decision-relevant leaf component |

Every component includes an estimate, conservative bound, sample size where
applicable, method, methodology version, evidence list, explanation, maturity,
and decision tier. Reports display all six components and the reason behind
each value.

## Non-circular dependency graph

```text
scanner_rule_reliability
        |
        v
finding_validity_confidence ----\
reachability_confidence ---------+--> overall_decision_confidence
exploitability_confidence -------+
remediation_confidence ----------/
```

Scanner reliability is consumed once through finding validity. Overall decision
confidence does not consume scanner reliability again. Reachability,
exploitability, and remediation are independent leaves. The dependency graph is
validated for cycles in tests.

Scanner reliability is never presented as exploitability probability. When no
exploit-specific evidence exists, `exploitability_confidence` remains unscored
even if rule reliability is high.

## Conservative decisions

The benchmark posterior mean is for display. Gate and prioritization decisions
use the lower 95% credible bound. Samples below 30 remain `Experimental` or
`Directional`; therefore one true positive and zero false positives cannot be
labelled high confidence.

The legacy scalar `confidence` field remains as a compatibility view of the
overall displayed estimate. It is not the source for the six components and
must not be interpreted without the component explanations.
