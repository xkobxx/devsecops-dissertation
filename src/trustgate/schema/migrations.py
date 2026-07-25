"""Backward-compatible migrations into Trust Gate schema version 1.0.0."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from trustgate.fingerprints import (
    FINGERPRINT_ALGORITHM_VERSION,
    fingerprint_finding,
    normalise_repository_path,
)
from trustgate.severity import normalise_scanner_severity

from .validation import (
    CURRENT_SCHEMA_VERSION,
    SchemaValidationError,
    SchemaVersionError,
    validate_instance,
)


class SchemaMigrationError(ValueError):
    """Raised when an older document cannot be migrated safely."""


_CATEGORY_BY_SCANNER = {
    "bandit": "sast",
    "semgrep": "sast",
    "pip-audit": "sca",
    "trivy": "container",
    "gitleaks": "secrets",
}

_SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
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


def _non_empty(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SchemaMigrationError(f"legacy finding {label} must be a non-empty string")
    return value.strip()


def _nullable_string(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _identifier_list(value: Any) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    return list(dict.fromkeys(str(item) for item in values if item))


def _positive_line(value: Any) -> int | None:
    if value is None:
        return None
    try:
        line = int(value)
    except (TypeError, ValueError):
        return None
    return line if line >= 1 else None


def _evidence_excerpt(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _normalisation_evidence(
    records: list[dict[str, Any]] | None,
    migrated: dict[str, Any],
) -> list[dict[str, str | None]]:
    evidence: list[dict[str, str | None]] = []
    for record in records or []:
        if not isinstance(record, dict):
            raise SchemaMigrationError("normalisation record must be an object")
        canonical_field = _non_empty(
            record.get("canonical_field"),
            label="normalisation canonical_field",
        )
        source = _non_empty(
            record.get("source"),
            label="normalisation source",
        )
        transformation = _non_empty(
            record.get("transformation"),
            label="normalisation transformation",
        )
        if canonical_field not in migrated:
            raise SchemaMigrationError(
                f"normalisation record references unknown field {canonical_field!r}"
            )
        output = _evidence_excerpt(migrated[canonical_field])
        evidence.append(
            {
                "kind": "normalisation",
                "summary": (
                    f"{canonical_field}: {transformation}; "
                    f"canonical value={output}."
                ),
                "reference": source,
                "excerpt": _evidence_excerpt(record.get("original")),
            }
        )
    return evidence


def _dependency(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return {
            "name": value,
            "version": None,
            "ecosystem": None,
            "purl": None,
            "direct": None,
        }
    if not isinstance(value, dict):
        raise SchemaMigrationError("legacy finding dependency must be an object")
    name = _non_empty(value.get("name"), label="dependency.name")
    return {
        "name": name,
        "version": _nullable_string(value.get("version")),
        "ecosystem": _nullable_string(value.get("ecosystem")),
        "purl": _nullable_string(value.get("purl")),
        "direct": (
            value.get("direct")
            if isinstance(value.get("direct"), bool)
            else None
        ),
    }


def migrate_finding(
    finding: dict[str, Any],
    *,
    observed_at: datetime | None = None,
    category: str | None = None,
    scanner_version: str | None = None,
    raw_report_reference: dict[str, Any] | None = None,
    normalisation_records: list[dict[str, Any]] | None = None,
    normalised_severity_override: str | None = None,
    severity_reason_override: str | None = None,
    repository_root: str | Path | None = None,
) -> dict[str, Any]:
    """Migrate one unversioned legacy finding into the current contract."""

    if not isinstance(finding, dict):
        raise SchemaMigrationError("finding must be an object")
    source_version = finding.get("schema_version")
    if source_version is not None:
        if source_version != CURRENT_SCHEMA_VERSION:
            raise SchemaMigrationError(
                f"unsupported finding schema version {source_version!r}"
            )
        migrated = deepcopy(finding)
        try:
            validate_instance("finding", migrated)
        except (SchemaValidationError, SchemaVersionError) as error:
            raise SchemaMigrationError(str(error)) from error
        return migrated

    scanner = _non_empty(
        finding.get("scanner") or finding.get("tool"),
        label="scanner",
    )
    rule_id = _non_empty(finding.get("rule_id"), label="rule_id")
    description = str(finding.get("description") or "")
    title = str(finding.get("title") or description or rule_id)
    severity_decision = normalise_scanner_severity(
        scanner,
        finding.get("original_severity", finding.get("severity"))
    )
    original_severity = severity_decision.original
    normalised_severity = severity_decision.normalised
    if normalised_severity_override is not None:
        if normalised_severity_override not in _SEVERITIES:
            raise SchemaMigrationError(
                "normalised severity override must be a canonical severity"
            )
        normalised_severity = normalised_severity_override
    observed = observed_at or datetime.now(timezone.utc)
    observed_timestamp = _timestamp(observed)
    finding_category = (
        category
        or _CATEGORY_BY_SCANNER.get(scanner.lower())
        or "unknown"
    )
    normalised_file = normalise_repository_path(
        _nullable_string(finding.get("file")),
        repository_root=repository_root,
    )
    identity_source = {
        **finding,
        "scanner": scanner,
        "category": finding_category,
        "file": normalised_file,
    }
    finding_id, fingerprint = fingerprint_finding(
        identity_source,
        repository_root=repository_root,
    )

    confidence = finding.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        confidence = None
    if confidence is not None and not 0 <= confidence <= 1:
        confidence = None
    sample_size = finding.get("confidence_sample_size")
    if not isinstance(sample_size, int) or isinstance(sample_size, bool):
        sample_size = None

    migrated = {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "finding_id": finding_id,
        "fingerprint": fingerprint,
        "scanner": scanner,
        "scanner_version": scanner_version,
        "rule_id": rule_id,
        "rule_version": _nullable_string(finding.get("rule_version")),
        "category": finding_category,
        "cwe": _identifier_list(finding.get("cwe")),
        "cve": _identifier_list(finding.get("cve")),
        "ghsa": _identifier_list(finding.get("ghsa")),
        "osv": _identifier_list(finding.get("osv")),
        "title": title,
        "description": description,
        "original_severity": original_severity,
        "normalised_severity": normalised_severity,
        "severity_reason": (
            severity_reason_override
            or severity_decision.reason
        ),
        "confidence": confidence,
        "confidence_method": _nullable_string(
            finding.get("confidence_method", finding.get("confidence_source"))
        ),
        "confidence_sample_size": sample_size,
        "confidence_interval": deepcopy(finding.get("confidence_interval")),
        "file": normalised_file,
        "start_line": _positive_line(
            finding.get("start_line", finding.get("line"))
        ),
        "end_line": _positive_line(
            finding.get("end_line", finding.get("line"))
        ),
        "symbol": _nullable_string(finding.get("symbol")),
        "source": _nullable_string(finding.get("source")),
        "sink": _nullable_string(finding.get("sink")),
        "data_flow": deepcopy(finding.get("data_flow") or []),
        "dependency": _dependency(finding.get("dependency")),
        "dependency_scope": finding.get("dependency_scope"),
        "reachability": finding.get("reachability") or "unknown",
        "environment": deepcopy(finding.get("environment") or {}),
        "introduced_commit": _nullable_string(finding.get("introduced_commit")),
        "first_seen": finding.get("first_seen") or observed_timestamp,
        "last_seen": finding.get("last_seen") or observed_timestamp,
        "status": finding.get("status") or "open",
        "evidence": deepcopy(finding.get("evidence") or []),
        "remediation": deepcopy(finding.get("remediation")),
        "raw_report_reference": deepcopy(raw_report_reference),
    }
    migrated["evidence"].extend(
        _normalisation_evidence(normalisation_records, migrated)
    )
    try:
        validate_instance("finding", migrated)
    except (SchemaValidationError, SchemaVersionError) as error:
        raise SchemaMigrationError(str(error)) from error
    return migrated


def migrate_fingerprint(
    finding: dict[str, Any],
    *,
    repository_root: str | Path | None = None,
) -> dict[str, Any]:
    """Explicitly migrate a canonical finding to the current fingerprint."""

    if not isinstance(finding, dict):
        raise SchemaMigrationError("finding must be an object")
    migrated = deepcopy(finding)
    try:
        validate_instance("finding", migrated)
    except (SchemaValidationError, SchemaVersionError) as error:
        raise SchemaMigrationError(str(error)) from error
    prefix = f"{FINGERPRINT_ALGORITHM_VERSION}:sha256:"
    if str(migrated["fingerprint"]).startswith(prefix):
        return migrated

    previous_fingerprint = str(migrated["fingerprint"])
    finding_id, fingerprint = fingerprint_finding(
        migrated,
        repository_root=repository_root,
    )
    migrated["finding_id"] = finding_id
    migrated["fingerprint"] = fingerprint
    migrated["file"] = normalise_repository_path(
        migrated.get("file"),
        repository_root=repository_root,
    )
    migrated["evidence"].append(
        {
            "kind": "fingerprint_migration",
            "summary": (
                f"Migrated finding identity to "
                f"{FINGERPRINT_ALGORITHM_VERSION}:sha256."
            ),
            "reference": FINGERPRINT_ALGORITHM_VERSION,
            "excerpt": previous_fingerprint,
        }
    )
    try:
        validate_instance("finding", migrated)
    except (SchemaValidationError, SchemaVersionError) as error:
        raise SchemaMigrationError(str(error)) from error
    return migrated


def _scanner_document(result: dict[str, Any]) -> dict[str, Any]:
    state = str(result.get("state") or "FAILED_SCANNER")
    if state not in _SCANNER_STATES:
        state = "FAILED_SCANNER"
    started_at = str(result.get("started_at"))
    ended_at = str(result.get("ended_at"))
    duration = result.get("duration_seconds", 0)
    if not isinstance(duration, (int, float)) or isinstance(duration, bool):
        duration = 0
    return {
        "scanner": str(result.get("scanner") or "unknown"),
        "scanner_version": _nullable_string(
            result.get("scanner_version", result.get("version"))
        ),
        "state": state,
        "healthy": state in {"CLEAN", "FINDINGS"},
        "required": bool(result.get("required", True)),
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": max(0, duration),
        "exit_code": (
            result.get("exit_code")
            if isinstance(result.get("exit_code"), int)
            and not isinstance(result.get("exit_code"), bool)
            else None
        ),
        "timed_out": bool(result.get("timed_out", False)),
        "report_path": str(result.get("report_path") or ""),
        "report_produced": bool(result.get("report_produced", False)),
        "parser_status": str(result.get("parser_status") or "NOT_RUN"),
        "stdout_path": _nullable_string(result.get("stdout_path")),
        "stderr_path": _nullable_string(result.get("stderr_path")),
        "finding_count": max(0, int(result.get("finding_count") or 0)),
        "error": _nullable_string(result.get("error")),
    }


def _count_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in _SEVERITIES}
    for finding in findings:
        severity = str(finding["normalised_severity"])
        counts[severity if severity in counts else "unknown"] += 1
    return counts


def _count_scanners(scanners: list[dict[str, Any]]) -> dict[str, int]:
    counts = {state: 0 for state in _SCANNER_STATES}
    for scanner in scanners:
        counts[str(scanner["state"])] += 1
    return counts


def migrate_scan_run(
    scan_run: dict[str, Any],
    *,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Migrate the legacy aggregate envelope into a canonical scan run."""

    if not isinstance(scan_run, dict):
        raise SchemaMigrationError("scan run must be an object")
    source_version = scan_run.get("schema_version")
    if source_version is not None:
        if source_version != CURRENT_SCHEMA_VERSION:
            raise SchemaMigrationError(
                f"unsupported scan-run schema version {source_version!r}"
            )
        migrated = deepcopy(scan_run)
        try:
            validate_instance("scan-run", migrated)
        except (SchemaValidationError, SchemaVersionError) as error:
            raise SchemaMigrationError(str(error)) from error
        return migrated

    observed = observed_at or datetime.now(timezone.utc)
    observed_timestamp = _timestamp(observed)
    legacy_findings = scan_run.get("findings", [])
    if not isinstance(legacy_findings, list):
        raise SchemaMigrationError("legacy scan run findings must be a list")
    findings = [
        migrate_finding(finding, observed_at=observed)
        for finding in legacy_findings
    ]

    legacy_scanners = scan_run.get("scanner_results", [])
    if not isinstance(legacy_scanners, list):
        raise SchemaMigrationError("legacy scanner_results must be a list")
    scanners = [
        _scanner_document(result)
        for result in legacy_scanners
        if isinstance(result, dict)
    ]
    starts = [scanner["started_at"] for scanner in scanners]
    ends = [scanner["ended_at"] for scanner in scanners]
    started_at = min(starts) if starts else observed_timestamp
    ended_at = max(ends) if ends else observed_timestamp
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
    identity = {
        "target": scan_run.get("target", "."),
        "started_at": started_at,
        "ended_at": ended_at,
        "findings": [finding["finding_id"] for finding in findings],
    }
    run_digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    trigger = scan_run.get("trigger") or "unknown"
    if trigger not in {
        "local",
        "push",
        "pull_request",
        "schedule",
        "manual",
        "api",
        "unknown",
    }:
        trigger = "unknown"
    migrated = {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "run_id": f"run-{run_digest[:24]}",
        "status": status,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": sum(
            float(scanner["duration_seconds"]) for scanner in scanners
        ),
        "target": str(scan_run.get("target") or "."),
        "repository": _nullable_string(scan_run.get("repository")),
        "ref": _nullable_string(scan_run.get("ref")),
        "commit": _nullable_string(scan_run.get("commit")),
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
            "severity_counts": _count_findings(findings),
            "scanner_state_counts": _count_scanners(scanners),
        },
        "errors": errors,
    }
    try:
        validate_instance("scan-run", migrated)
    except (SchemaValidationError, SchemaVersionError) as error:
        raise SchemaMigrationError(str(error)) from error
    return migrated
