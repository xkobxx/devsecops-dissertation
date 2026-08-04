"""Persist contextual decisions onto canonical scan-run documents."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from trustgate.schema import validate_instance

from .context import build_decision_context
from .engine import evaluate
from .models import DecisionOutcome, DecisionPolicy
from .policy import default_policy


def evaluate_scan_run(
    scan_run: dict[str, Any],
    *,
    policy: DecisionPolicy | None = None,
    runtime_context: Mapping[str, Any] | None = None,
    finding_contexts: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate every finding and return a separately validated document."""

    validate_instance("scan-run", scan_run)
    selected_policy = policy or default_policy()
    shared_context = dict(runtime_context or {})
    per_finding = finding_contexts or {}
    evaluated = deepcopy(scan_run)
    decisions: list[dict[str, Any]] = []

    for finding in evaluated["findings"]:
        finding_id = str(finding["finding_id"])
        specific = per_finding.get(finding_id, {})
        if not isinstance(specific, Mapping):
            raise ValueError(
                f"runtime context for {finding_id} must be an object"
            )
        merged_context = {**shared_context, **dict(specific)}
        decision = evaluate(
            build_decision_context(
                finding,
                runtime_context=merged_context,
            ),
            selected_policy,
        ).to_dict()
        validate_instance("decision", decision)
        finding["contextual_decision"] = decision
        decisions.append(decision)

    outcome_counts = {outcome.value: 0 for outcome in DecisionOutcome}
    strength_counts = {
        "strong": 0,
        "moderate": 0,
        "weak": 0,
        "insufficient": 0,
    }
    for decision in decisions:
        outcome_counts[str(decision["outcome"])] += 1
        strength = str(decision["evidence_strength"]["level"])
        strength_counts[strength] += 1

    evaluated["summary"]["decision_analysis"] = {
        "policy_id": selected_policy.policy_id,
        "policy_version": selected_policy.version,
        "total_decisions": len(decisions),
        "outcome_counts": outcome_counts,
        "evidence_strength_counts": strength_counts,
        "findings_with_uncertainty": sum(
            bool(decision["unresolved_uncertainty"])
            for decision in decisions
        ),
    }
    validate_instance("scan-run", evaluated)
    return evaluated


__all__ = ["evaluate_scan_run"]
