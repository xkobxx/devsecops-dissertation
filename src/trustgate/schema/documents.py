"""Builders for validated canonical scan-run and policy-result documents."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Iterable

from trustgate.scanners.models import ScannerResult
from trustgate.correlation import (
    CorrelationConfig,
    ScannerContradiction,
    correlate_findings,
)
from trustgate.severity import normalise_scanner_severity

from .validation import CURRENT_SCHEMA_VERSION, validate_instance


_SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
_SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}
_SCANNER_STATES = (
    "CLEAN",
    "FINDINGS",
    "FAILED_SCANNER",
    "PARTIAL",
    "SKIPPED",
)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _scanner_document(result: ScannerResult) -> dict[str, Any]:
    return {
        "scanner": result.scanner,
        "scanner_version": result.version,
        "state": result.state.value,
        "healthy": result.healthy,
        "required": result.required,
        "started_at": _timestamp(result.started_at),
        "ended_at": _timestamp(result.ended_at),
        "duration_seconds": result.duration_seconds,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "report_path": result.report_path,
        "report_produced": result.report_produced,
        "parser_status": result.parser_status.value,
        "stdout_path": result.stdout_path,
        "stderr_path": result.stderr_path,
        "finding_count": result.finding_count,
        "error": result.error,
    }


def _severity_counts(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in _SEVERITIES}
    for finding in findings:
        severity = str(finding.get("normalised_severity") or "unknown")
        counts[severity if severity in counts else "unknown"] += 1
    return counts


def _state_counts(scanners: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {state: 0 for state in _SCANNER_STATES}
    for scanner in scanners:
        state = str(scanner["state"])
        counts[state] += 1
    return counts


def build_scan_run(
    *,
    target: str,
    findings: list[dict[str, Any]],
    scanner_results: list[ScannerResult],
    repository: str | None = None,
    ref: str | None = None,
    commit: str | None = None,
    trigger: str = "local",
    correlation_config: CorrelationConfig | None = None,
    contradictions: Iterable[ScannerContradiction] = (),
) -> dict[str, Any]:
    """Build and validate one canonical scan-run document."""

    findings = correlate_findings(
        findings,
        config=correlation_config,
        contradictions=contradictions,
    )
    for finding in findings:
        validate_instance("finding", finding)
    scanners = [_scanner_document(result) for result in scanner_results]
    now = datetime.now(timezone.utc)
    started = min(
        (result.started_at for result in scanner_results),
        default=now,
    )
    ended = max(
        (result.ended_at for result in scanner_results),
        default=started,
    )
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    if ended.tzinfo is None:
        ended = ended.replace(tzinfo=timezone.utc)
    required_failures = [
        scanner
        for scanner in scanners
        if scanner["required"] and not scanner["healthy"]
    ]
    status = (
        "failed"
        if required_failures
        else "partial"
        if any(scanner["state"] == "PARTIAL" for scanner in scanners)
        else "complete"
    )
    errors = [
        {
            "code": f"SCANNER_{scanner['state']}",
            "message": (
                scanner["error"]
                or f"{scanner['scanner']} ended in {scanner['state']} state."
            ),
            "scanner": scanner["scanner"],
            "detail": scanner["error"],
        }
        for scanner in scanners
        if not scanner["healthy"] and scanner["state"] != "SKIPPED"
    ]
    run_identity = {
        "target": target,
        "started_at": _timestamp(started),
        "ended_at": _timestamp(ended),
        "findings": [finding["finding_id"] for finding in findings],
        "scanners": [
            {
                "scanner": scanner["scanner"],
                "state": scanner["state"],
            }
            for scanner in scanners
        ],
    }
    run_digest = hashlib.sha256(
        json.dumps(
            run_identity,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    scan_run = {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "run_id": f"run-{run_digest[:24]}",
        "status": status,
        "started_at": _timestamp(started),
        "ended_at": _timestamp(ended),
        "duration_seconds": max(0.0, (ended - started).total_seconds()),
        "target": target,
        "repository": repository,
        "ref": ref,
        "commit": commit,
        "trigger": trigger,
        "scanners": scanners,
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "required_scanners": sum(
                1 for scanner in scanners if scanner["required"]
            ),
            "healthy_scanners": sum(
                1 for scanner in scanners if scanner["healthy"]
            ),
            "severity_counts": _severity_counts(findings),
            "scanner_state_counts": _state_counts(scanners),
        },
        "errors": errors,
    }
    validate_instance("scan-run", scan_run)
    return scan_run


def build_policy_result(
    scan_run: dict[str, Any],
    *,
    fail_on: str,
    scanner_failure_policy: str,
    severity_basis: str = "normalised",
    evaluated_at: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate the legacy threshold policy into an explainable document."""

    validate_instance("scan-run", scan_run)
    required_failures = [
        scanner
        for scanner in scan_run["scanners"]
        if scanner["required"] and not scanner["healthy"]
    ]
    if severity_basis not in {"normalised", "original"}:
        raise ValueError("severity_basis must be 'normalised' or 'original'")
    threshold = _SEVERITY_RANK.get(fail_on)
    gating_findings = (
        []
        if fail_on == "none"
        else [
            finding
            for finding in scan_run["findings"]
            if _SEVERITY_RANK.get(
                (
                    str(finding["normalised_severity"])
                    if severity_basis == "normalised"
                    else normalise_scanner_severity(
                        str(finding["scanner"]),
                        finding["original_severity"],
                    ).normalised
                ),
                0,
            )
            >= int(threshold or 0)
        ]
    )

    if required_failures and scanner_failure_policy == "fail":
        outcome = "fail"
        exit_code = 2
        reason = (
            "Required scanner failure: "
            + ", ".join(
                f"{scanner['scanner']} ({scanner['state']})"
                for scanner in required_failures
            )
            + "."
        )
    elif gating_findings:
        outcome = "fail"
        exit_code = 1
        reason = (
            f"{len(gating_findings)} finding(s) met or exceeded "
            f"the {fail_on} {severity_basis}-severity threshold."
        )
    elif required_failures and scanner_failure_policy == "warn":
        outcome = "warn"
        exit_code = 0
        reason = (
            "Required scanner failure was allowed by warn policy: "
            + ", ".join(
                f"{scanner['scanner']} ({scanner['state']})"
                for scanner in required_failures
            )
            + "."
        )
    elif fail_on == "none":
        outcome = "pass"
        exit_code = 0
        reason = "Finding severity gating is disabled."
    else:
        outcome = "pass"
        exit_code = 0
        reason = (
            f"No finding met the {fail_on} {severity_basis}-severity threshold."
        )

    identity = {
        "run_id": scan_run["run_id"],
        "fail_on": fail_on,
        "scanner_failure_policy": scanner_failure_policy,
        "severity_basis": severity_basis,
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    evaluated = evaluated_at or datetime.now(timezone.utc)
    policy_result = {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "policy_result_id": f"policy-result-{digest[:24]}",
        "run_id": scan_run["run_id"],
        "policy_name": "default",
        "policy_version": CURRENT_SCHEMA_VERSION,
        "evaluated_at": _timestamp(evaluated),
        "outcome": outcome,
        "reason": reason,
        "fail_on": fail_on,
        "scanner_failure_policy": scanner_failure_policy,
        "matched_finding_ids": [
            finding["finding_id"] for finding in gating_findings
        ],
        "finding_counts": dict(scan_run["summary"]["severity_counts"]),
        "scanner_state_counts": dict(
            scan_run["summary"]["scanner_state_counts"]
        ),
        "waivers": [],
        "metadata": {
            "engine": "trustgate",
            "exit_code": exit_code,
            "gating_findings": len(gating_findings),
            "required_scanner_failures": len(required_failures),
            "severity_basis": severity_basis,
        },
    }
    validate_instance("policy-result", policy_result)
    return policy_result
