"""Built-in, versioned contextual policy used before Phase 11 policy-as-code."""

from __future__ import annotations

from .models import Condition, DecisionOutcome, DecisionPolicy, DecisionRule


def _rule(
    rule_id: str,
    outcome: DecisionOutcome,
    explanation: str,
    *conditions: Condition,
) -> DecisionRule:
    return DecisionRule(
        rule_id=rule_id,
        outcome=outcome,
        all_of=tuple(conditions),
        explanation=explanation,
    )


def default_policy() -> DecisionPolicy:
    """Return the conservative default policy as inspectable data."""

    high_severity = Condition(
        "normalised_severity", "in", ("critical", "high")
    )
    return DecisionPolicy(
        policy_id="trustgate-contextual-default",
        version="1.0.0",
        rules=(
            _rule(
                "honour-temporary-suppression",
                DecisionOutcome.TEMPORARILY_SUPPRESSED,
                "A human-approved temporary suppression is active.",
                Condition("human_triage_state", "equals", "suppressed"),
            ),
            _rule(
                "honour-accepted-risk",
                DecisionOutcome.ACCEPTED_RISK,
                "A human has explicitly accepted this risk.",
                Condition("human_triage_state", "equals", "accepted_risk"),
            ),
            _rule(
                "honour-false-positive-triage",
                DecisionOutcome.LIKELY_NOISE,
                "Human triage marked the finding as a false positive.",
                Condition("human_triage_state", "equals", "false_positive"),
            ),
            _rule(
                "insufficient-core-evidence",
                DecisionOutcome.INSUFFICIENT_EVIDENCE,
                "Core validity evidence is unavailable.",
                Condition(
                    "finding_validity_confidence", "is_known", False
                ),
            ),
            _rule(
                "block-exploitable-production-risk",
                DecisionOutcome.BLOCK_IMMEDIATELY,
                "Confirmed reachable high-severity issue",
                high_severity,
                Condition("reachability", "equals", "reachable"),
                Condition("runtime_environment", "equals", "production"),
                Condition("internet_exposure", "equals", True),
                Condition("authentication_requirements", "equals", False),
                Condition("cisa_kev", "equals", True),
            ),
            _rule(
                "block-public-exploit-production-risk",
                DecisionOutcome.BLOCK_IMMEDIATELY,
                "A public exploit makes this reachable production issue urgent.",
                high_severity,
                Condition("reachability", "equals", "reachable"),
                Condition("runtime_environment", "equals", "production"),
                Condition("internet_exposure", "equals", True),
                Condition("public_exploit_availability", "equals", True),
            ),
            _rule(
                "fix-new-reachable-risk-before-release",
                DecisionOutcome.FIX_BEFORE_RELEASE,
                "A new reachable high-severity issue must be fixed before release.",
                high_severity,
                Condition("reachability", "equals", "reachable"),
                Condition("new_existing_status", "equals", "new"),
            ),
            _rule(
                "fix-known-high-risk-within-sla",
                DecisionOutcome.FIX_WITHIN_SLA,
                "A fix is available for a high-severity issue.",
                high_severity,
                Condition("fix_availability", "equals", True),
            ),
            _rule(
                "monitor-contained-low-risk",
                DecisionOutcome.MONITOR,
                "Current evidence supports monitoring rather than immediate action.",
                Condition(
                    "normalised_severity", "in", ("low", "info")
                ),
                Condition("internet_exposure", "equals", False),
            ),
            _rule(
                "investigate-uncertain-risk",
                DecisionOutcome.INVESTIGATE,
                "The finding needs human investigation before a stronger outcome.",
                Condition("human_triage_state", "in", ("open", "acknowledged")),
            ),
        ),
        default_outcome=DecisionOutcome.INVESTIGATE,
    )


__all__ = ["default_policy"]
