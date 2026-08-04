"""Simulation, explanation, and unit-test tooling for policy-as-code."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from typing import Any

from trustgate.schema import validate_instance

from .context import build_policy_context
from .evaluator import evaluate_policy
from .models import ACTION_OUTCOMES, PolicyDocument


class PolicyTestError(ValueError):
    """Raised when a policy test definition is invalid."""


def _canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _context_for_finding(
    finding_id: str,
    shared: Mapping[str, Any],
    finding_contexts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    merged = dict(shared)
    specific = finding_contexts.get(finding_id, {})
    if not isinstance(specific, Mapping):
        raise ValueError(
            f"runtime context for finding {finding_id!r} must be an object"
        )
    merged.update(specific)
    return merged


def simulate_scan_run(
    document: PolicyDocument,
    scan_run: Mapping[str, Any],
    *,
    runtime_context: Mapping[str, Any] | None = None,
    finding_contexts: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate a saved scan run without changing the source document."""

    validate_instance("scan-run", scan_run)
    shared = runtime_context or {}
    per_finding = finding_contexts or {}
    if not isinstance(shared, Mapping) or not isinstance(per_finding, Mapping):
        raise ValueError("runtime context values must be objects")

    evaluations: list[dict[str, Any]] = []
    for source_finding in scan_run.get("findings", ()):
        finding = deepcopy(source_finding)
        finding_id = str(finding.get("finding_id") or "")
        context = build_policy_context(
            scan_run,
            finding,
            runtime_context=_context_for_finding(
                finding_id,
                shared,
                per_finding,
            ),
        )
        evaluations.append(evaluate_policy(document, context).to_dict())

    result: dict[str, Any] = {
        "policy_id": document.policy_id,
        "policy_version": document.policy_version,
        "run_id": scan_run.get("run_id"),
        "total_findings": len(evaluations),
        "evaluations": evaluations,
    }
    result["simulation_digest"] = _canonical_digest(result)
    return result


def _expression_lines(expression: Mapping[str, Any], indent: str) -> list[str]:
    operator = expression.get("operator")
    if operator in {"any", "all", "not"}:
        lines = [
            f"{indent}{operator.upper()}: "
            f"matched={str(bool(expression.get('matched'))).lower()}"
        ]
        for child in expression.get("children", ()):
            if isinstance(child, Mapping):
                lines.extend(_expression_lines(child, indent + "  "))
        return lines
    return [
        f"{indent}{expression.get('field')}: expected={expression.get('expected')!r}, "
        f"actual={expression.get('actual')!r}, "
        f"matched={str(bool(expression.get('matched'))).lower()}, "
        f"evidence={expression.get('evidence_source') or 'unresolved'}"
    ]


def explain_policy_result(evaluation: Mapping[str, Any]) -> str:
    """Render a deterministic human-readable evaluation trace."""

    required = {"policy_id", "policy_version", "outcome", "trace"}
    missing = sorted(required - set(evaluation))
    if missing:
        raise ValueError(f"policy evaluation is missing fields: {missing}")
    lines = [
        f"Policy: {evaluation['policy_id']}@{evaluation['policy_version']}",
        f"Finding: {evaluation.get('context', {}).get('finding_id', 'unknown')}",
        f"Outcome: {evaluation['outcome']}",
        "Matched policy: "
        f"{evaluation.get('matched_policy') or 'none (default action)'}",
        str(evaluation.get("explanation") or ""),
        "Evaluation trace:",
    ]
    for trace in evaluation["trace"]:
        if not isinstance(trace, Mapping):
            continue
        lines.append(
            f"- {trace.get('policy')}: action={trace.get('action')}, "
            f"matched={str(bool(trace.get('matched'))).lower()}"
        )
        expression = trace.get("expression")
        if isinstance(expression, Mapping):
            lines.extend(_expression_lines(expression, "  "))
    return "\n".join(lines).rstrip() + "\n"


def _validated_expectations(value: Mapping[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise PolicyTestError("expectations must be an object")
    unexpected = sorted(set(value) - {"version", "tests"})
    if unexpected:
        raise PolicyTestError(f"unknown expectation fields: {unexpected}")
    if value.get("version") != 1:
        raise PolicyTestError("expectations version must be 1")
    tests = value.get("tests")
    if not isinstance(tests, list) or not tests:
        raise PolicyTestError("expectations tests must be a non-empty array")

    allowed_outcomes = set(ACTION_OUTCOMES.values())
    validated: list[dict[str, Any]] = []
    for index, test in enumerate(tests):
        if not isinstance(test, Mapping):
            raise PolicyTestError(f"tests[{index}] must be an object")
        unexpected_test = sorted(
            set(test)
            - {"name", "finding_id", "expected_outcome", "expected_policy"}
        )
        if unexpected_test:
            raise PolicyTestError(
                f"tests[{index}] has unknown fields: {unexpected_test}"
            )
        for field in ("name", "finding_id", "expected_outcome"):
            if not isinstance(test.get(field), str) or not test[field]:
                raise PolicyTestError(f"tests[{index}].{field} is required")
        if test["expected_outcome"] not in allowed_outcomes:
            raise PolicyTestError(
                f"tests[{index}].expected_outcome is not a supported outcome"
            )
        expected_policy = test.get("expected_policy")
        if expected_policy is not None and (
            not isinstance(expected_policy, str) or not expected_policy
        ):
            raise PolicyTestError(
                f"tests[{index}].expected_policy must be a non-empty string"
            )
        validated.append(dict(test))
    return validated


def run_policy_tests(
    document: PolicyDocument,
    scan_run: Mapping[str, Any],
    expectations: Mapping[str, Any],
    *,
    runtime_context: Mapping[str, Any] | None = None,
    finding_contexts: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare deterministic simulation results with explicit expectations."""

    tests = _validated_expectations(expectations)
    simulation = simulate_scan_run(
        document,
        scan_run,
        runtime_context=runtime_context,
        finding_contexts=finding_contexts,
    )
    evaluations = {
        evaluation["context"]["finding_id"]: evaluation
        for evaluation in simulation["evaluations"]
    }
    results: list[dict[str, Any]] = []
    for test in tests:
        evaluation = evaluations.get(test["finding_id"])
        actual_outcome = evaluation.get("outcome") if evaluation else None
        actual_policy = evaluation.get("matched_policy") if evaluation else None
        outcome_matches = actual_outcome == test["expected_outcome"]
        policy_matches = (
            "expected_policy" not in test
            or actual_policy == test["expected_policy"]
        )
        results.append(
            {
                "name": test["name"],
                "finding_id": test["finding_id"],
                "passed": outcome_matches and policy_matches,
                "expected_outcome": test["expected_outcome"],
                "actual_outcome": actual_outcome,
                "expected_policy": test.get("expected_policy"),
                "actual_policy": actual_policy,
            }
        )
    passed = sum(1 for result in results if result["passed"])
    return {
        "policy_id": document.policy_id,
        "policy_version": document.policy_version,
        "passed": passed,
        "failed": len(results) - passed,
        "tests": results,
        "simulation_digest": simulation["simulation_digest"],
    }


__all__ = [
    "PolicyTestError",
    "explain_policy_result",
    "run_policy_tests",
    "simulate_scan_run",
]
