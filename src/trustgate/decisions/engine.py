"""Deterministic evaluation of contextual decision policies."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .models import (
    COMPONENT_NAMES,
    Decision,
    DecisionContext,
    DecisionPolicy,
    EvidenceStrength,
)


_COMPONENT_LABELS = {
    "finding_validity_confidence": "Finding-validity confidence",
    "original_severity": "Original severity",
    "normalised_severity": "Normalised severity",
    "reachability": "Reachability",
    "epss": "EPSS",
    "cisa_kev": "CISA KEV",
    "public_exploit_availability": "Public exploit availability",
    "internet_exposure": "Internet exposure",
    "authentication_requirements": "Authentication requirements",
    "data_sensitivity": "Data sensitivity",
    "asset_criticality": "Asset criticality",
    "runtime_environment": "Runtime environment",
    "existing_controls": "Existing controls",
    "fix_availability": "Fix availability",
    "new_existing_status": "New versus existing status",
    "human_triage_state": "Human triage state",
}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _reproduction_digest(
    context: DecisionContext,
    policy: DecisionPolicy,
) -> str:
    payload = {
        "context": context.to_dict(),
        "policy": policy.to_dict(),
    }
    digest = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _strength(context: DecisionContext) -> EvidenceStrength:
    known = sum(
        1
        for component in context.components
        if component.value is not None and component.uncertainty is None
    )
    confidence = context.value("finding_validity_confidence")
    if known >= 14 and confidence is not None and confidence >= 0.7:
        level = "strong"
    elif known >= 10 and confidence is not None and confidence >= 0.4:
        level = "moderate"
    elif known >= 6:
        level = "weak"
    else:
        level = "insufficient"
    return EvidenceStrength(
        level=level,
        known_components=known,
        total_components=len(COMPONENT_NAMES),
        finding_validity_lower_bound=confidence,
    )


def evaluate(context: DecisionContext, policy: DecisionPolicy) -> Decision:
    """Evaluate every rule and retain the complete, inspectable trace."""

    trace: list[dict[str, Any]] = []
    matched_rule = None
    for rule in policy.rules:
        conditions = [
            {
                **condition.to_dict(),
                "actual": context.value(condition.component),
                "matched": condition.matches(context),
            }
            for condition in rule.all_of
        ]
        matched = all(condition["matched"] for condition in conditions)
        trace.append(
            {
                "rule_id": rule.rule_id,
                "outcome": rule.outcome.value,
                "matched": matched,
                "conditions": conditions,
            }
        )
        if matched_rule is None and matched:
            matched_rule = rule

    outcome = matched_rule.outcome if matched_rule else policy.default_outcome
    matched_rule_id = matched_rule.rule_id if matched_rule else None
    explanation = [
        (
            matched_rule.explanation
            if matched_rule
            else f"No rule matched; policy defaulted to {outcome.value}."
        )
    ]
    if matched_rule:
        explanation.extend(
            f"{_COMPONENT_LABELS[condition.component]} is "
            f"{context.value(condition.component)!r}."
            for condition in matched_rule.all_of
        )
    uncertainty = tuple(context.unresolved_uncertainty())
    explanation.append(
        (
            "No unresolved component uncertainty remains."
            if not uncertainty
            else "Unresolved components: " + ", ".join(uncertainty) + "."
        )
    )
    digest = _reproduction_digest(context, policy)
    return Decision(
        decision_id=digest,
        finding_id=context.finding_id,
        outcome=outcome,
        policy={
            "id": policy.policy_id,
            "version": policy.version,
            "matched_rule_id": matched_rule_id,
            "snapshot": policy.to_dict(),
        },
        context=context,
        explanation=tuple(explanation),
        evidence_strength=_strength(context),
        unresolved_uncertainty=uncertainty,
        evaluation_trace=tuple(trace),
        reproduction_digest=digest,
    )


def reproduce_decision(document: dict[str, Any]) -> Decision:
    """Re-evaluate a stored decision and reject any altered evidence or policy."""

    context = DecisionContext.from_dict(document.get("context", {}))
    policy_data = document.get("policy", {}).get("snapshot")
    if not isinstance(policy_data, dict):
        raise ValueError("stored decision has no policy snapshot")
    policy = DecisionPolicy.from_dict(policy_data)
    reproduced = evaluate(context, policy)
    expected_digest = reproduced.reproduction_digest
    if (
        document.get("reproduction_digest") != expected_digest
        or document.get("decision_id") != expected_digest
    ):
        raise ValueError("stored decision reproduction digest does not match evidence")
    if reproduced.to_dict() != document:
        raise ValueError("stored decision result is not reproducible")
    return reproduced


__all__ = ["evaluate", "reproduce_decision"]
