"""Deterministic evaluation for recursive public policy expressions."""

from __future__ import annotations

from fnmatch import fnmatchcase
import hashlib
import json
import operator
import re
from typing import Any

from .context import PolicyContext
from .models import (
    ACTION_OUTCOMES,
    PolicyDocument,
    PolicyEvaluation,
)


_COMPARISON = re.compile(r"^(>=|<=|>|<|==)([01](?:\.[0-9]+)?)$")
_OPERATORS = {
    ">=": operator.ge,
    "<=": operator.le,
    ">": operator.gt,
    "<": operator.lt,
    "==": operator.eq,
}


def _compare_probability(actual: Any, expected: Any) -> bool:
    if not isinstance(actual, (int, float)) or isinstance(actual, bool):
        return False
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        return float(actual) >= float(expected)
    match = _COMPARISON.fullmatch(str(expected))
    if match is None:
        return False
    return bool(_OPERATORS[match.group(1)](float(actual), float(match.group(2))))


def _selector_match(actual: Any, expected: Any, field: str) -> bool:
    if field in {"epss", "confidence_lower_bound"}:
        return _compare_probability(actual, expected)
    if isinstance(expected, list):
        return any(_selector_match(actual, item, field) for item in expected)
    if isinstance(actual, list):
        return expected in actual
    if field in {"repository", "branch"} and isinstance(actual, str):
        return fnmatchcase(actual, str(expected))
    return actual == expected


def _evaluate_expression(
    expression: dict[str, Any],
    context: PolicyContext,
) -> tuple[bool, dict[str, Any]]:
    if "any" in expression:
        children = [
            _evaluate_expression(child, context) for child in expression["any"]
        ]
        matched = any(result for result, _trace in children)
        return matched, {
            "operator": "any",
            "matched": matched,
            "children": [trace for _result, trace in children],
        }
    if "all" in expression:
        children = [
            _evaluate_expression(child, context) for child in expression["all"]
        ]
        matched = all(result for result, _trace in children)
        return matched, {
            "operator": "all",
            "matched": matched,
            "children": [trace for _result, trace in children],
        }
    if "not" in expression:
        child_result, child_trace = _evaluate_expression(expression["not"], context)
        return not child_result, {
            "operator": "not",
            "matched": not child_result,
            "children": [child_trace],
        }
    field, expected = next(iter(expression.items()))
    actual = context.value(field)
    matched = _selector_match(actual, expected, field)
    return matched, {
        "field": field,
        "expected": expected,
        "actual": actual,
        "evidence_source": context.evidence(field),
        "matched": matched,
    }


def _digest(document: PolicyDocument, context: PolicyContext) -> str:
    payload = {
        "policy": document.to_dict(),
        "context": context.to_dict(),
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def evaluate_policy(
    document: PolicyDocument,
    context: PolicyContext,
) -> PolicyEvaluation:
    """Evaluate every rule and select the first matching policy."""

    trace: list[dict[str, Any]] = []
    selected = None
    for rule in document.policies:
        matched, expression_trace = _evaluate_expression(rule.when, context)
        trace.append(
            {
                "policy": rule.name,
                "action": rule.action.value,
                "matched": matched,
                "expression": expression_trace,
            }
        )
        if selected is None and matched:
            selected = rule
    action = selected.action if selected else document.default_action
    matched_name = selected.name if selected else None
    explanation = (
        f"Policy {selected.name!r} matched and selected {action.value}."
        if selected
        else f"No policy matched; default action {action.value!r} was selected."
    )
    return PolicyEvaluation(
        policy_id=document.policy_id,
        policy_version=document.policy_version,
        matched_policy=matched_name,
        action=action,
        outcome=ACTION_OUTCOMES[action],
        explanation=explanation,
        context=context.to_dict(),
        trace=tuple(trace),
        evaluation_digest=_digest(document, context),
    )


__all__ = ["evaluate_policy"]
