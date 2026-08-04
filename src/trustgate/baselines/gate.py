"""Differential release gates over verified baseline comparisons."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
import hashlib
import json
from typing import Any

from trustgate.policy.models import PolicyDocument
from trustgate.policy.tooling import simulate_scan_run
from trustgate.schema import validate_instance

from .comparison import compare_to_baseline
from .creation import BaselineError


class GateMode(StrEnum):
    NEW = "new"
    ALL = "all"
    WORSENED = "worsened"
    POLICY = "policy"


class BaselineGateError(BaselineError):
    """Raised when a differential gate cannot be evaluated safely."""


_SEVERITY_RANK = {
    "unknown": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}
_THRESHOLDS = {
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
    "none": 6,
}
_BLOCKING_POLICY_OUTCOMES = {
    "BLOCK_IMMEDIATELY",
    "FIX_BEFORE_RELEASE",
    "INSUFFICIENT_EVIDENCE",
}


def _digest(value: Mapping[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "gate_digest"}
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _finding_index(scan_run: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        str(finding["fingerprint"]): finding
        for finding in scan_run.get("findings", ())
    }


def _change_reasons(difference: Mapping[str, Any]) -> dict[str, list[str]]:
    reasons: dict[str, list[str]] = {}
    categories = (
        ("new_findings", "new"),
        ("worsened_findings", "worsened"),
        ("newly_reachable_findings", "newly_reachable"),
        ("newly_exploited_dependencies", "newly_exploited"),
        ("expired_suppressions", "expired_suppression"),
    )
    for field, reason in categories:
        for fingerprint in difference[field]:
            reasons.setdefault(fingerprint, []).append(reason)
    return reasons


def _selected_candidates(
    mode: GateMode,
    current: Mapping[str, Mapping[str, Any]],
    reasons: Mapping[str, list[str]],
    *,
    enforce_legacy_risk: bool,
) -> tuple[list[str], dict[str, list[str]]]:
    selected_reasons = {key: list(value) for key, value in reasons.items()}
    if mode is GateMode.ALL or enforce_legacy_risk:
        candidates = list(current)
        for fingerprint in candidates:
            selected_reasons.setdefault(fingerprint, ["legacy"])
    elif mode is GateMode.NEW:
        candidates = [
            fingerprint
            for fingerprint, values in selected_reasons.items()
            if "new" in values
        ]
    elif mode in {GateMode.WORSENED, GateMode.POLICY}:
        candidates = list(selected_reasons)
    else:
        raise BaselineGateError(f"unsupported gate mode {mode.value!r}")
    return sorted(candidates), selected_reasons


def _policy_evaluations(
    policy: PolicyDocument,
    scan_run: Mapping[str, Any],
    *,
    runtime_context: Mapping[str, Any] | None,
    finding_contexts: Mapping[str, Mapping[str, Any]] | None,
) -> dict[str, Mapping[str, Any]]:
    simulation = simulate_scan_run(
        policy,
        scan_run,
        runtime_context=runtime_context,
        finding_contexts=finding_contexts,
    )
    return {
        str(finding["fingerprint"]): evaluation
        for finding, evaluation in zip(
            scan_run.get("findings", ()),
            simulation["evaluations"],
            strict=True,
        )
    }


def evaluate_gate(
    baseline: Mapping[str, Any],
    scan_run: Mapping[str, Any],
    *,
    mode: GateMode | str = GateMode.NEW,
    fail_on: str = "high",
    enforce_legacy_risk: bool = False,
    policy: PolicyDocument | None = None,
    runtime_context: Mapping[str, Any] | None = None,
    finding_contexts: Mapping[str, Mapping[str, Any]] | None = None,
    evaluated_at: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate a deterministic severity gate over differential candidates."""

    try:
        selected_mode = GateMode(mode)
    except ValueError as error:
        raise BaselineGateError(f"unsupported gate mode {mode!r}") from error
    if fail_on not in _THRESHOLDS:
        raise BaselineGateError(f"unsupported fail-on severity {fail_on!r}")
    if selected_mode is GateMode.POLICY and policy is None:
        raise BaselineGateError("policy gate mode requires a policy document")

    difference = compare_to_baseline(
        baseline,
        scan_run,
        compared_at=evaluated_at,
    )
    current = _finding_index(scan_run)
    reasons = _change_reasons(difference)
    candidates, selected_reasons = _selected_candidates(
        selected_mode,
        current,
        reasons,
        enforce_legacy_risk=enforce_legacy_risk,
    )
    policy_evaluations = (
        _policy_evaluations(
            policy,
            scan_run,
            runtime_context=runtime_context,
            finding_contexts=finding_contexts,
        )
        if selected_mode is GateMode.POLICY and policy is not None
        else {}
    )
    blocked: list[dict[str, Any]] = []
    threshold = _THRESHOLDS[fail_on]
    for fingerprint in candidates:
        finding = current[fingerprint]
        severity = str(finding["normalised_severity"])
        policy_evaluation = policy_evaluations.get(fingerprint)
        if selected_mode is GateMode.POLICY:
            if (
                policy_evaluation is None
                or policy_evaluation.get("outcome") not in _BLOCKING_POLICY_OUTCOMES
            ):
                continue
            blocked_reasons = [*selected_reasons[fingerprint], "policy"]
        else:
            if _SEVERITY_RANK.get(severity, 0) < threshold:
                continue
            blocked_reasons = selected_reasons[fingerprint]
        blocked.append(
            {
                "fingerprint": fingerprint,
                "finding_id": finding["finding_id"],
                "severity": severity,
                "reasons": blocked_reasons,
                "policy_outcome": (
                    policy_evaluation.get("outcome")
                    if policy_evaluation is not None
                    else None
                ),
                "matched_policy": (
                    policy_evaluation.get("matched_policy")
                    if policy_evaluation is not None
                    else None
                ),
            }
        )

    coverage = difference["scanner_coverage_regressions"]
    result: dict[str, Any] = {
        "schema_version": "1.0.0",
        "version": 1,
        "gate_mode": selected_mode.value,
        "fail_on": fail_on,
        "enforce_legacy_risk": enforce_legacy_risk,
        "repository": difference["repository"],
        "baseline_digest": difference["baseline_digest"],
        "comparison_digest": difference["comparison_digest"],
        "baseline_age_seconds": difference["baseline_age_seconds"],
        "current_run_id": difference["current_run_id"],
        "policy_id": policy.policy_id if policy is not None else None,
        "policy_version": policy.policy_version if policy is not None else None,
        "candidate_fingerprints": candidates,
        "blocked_findings": blocked,
        "scanner_coverage_regressions": coverage,
        "passed": not blocked and not coverage,
        "summary": {
            "candidate_findings": len(candidates),
            "blocked_findings": len(blocked),
            "scanner_coverage_regressions": len(coverage),
        },
    }
    result["gate_digest"] = _digest(result)
    validate_instance("baseline-gate", result)
    return result


__all__ = ["BaselineGateError", "GateMode", "evaluate_gate"]
