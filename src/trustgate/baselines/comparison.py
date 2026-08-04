"""Deterministic finding transitions from a verified default-branch baseline."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime, time, timezone
import hashlib
import json
from typing import Any

from trustgate.schema import validate_instance

from .creation import BaselineCompatibilityError, BaselineError, verify_baseline


_SEVERITY_RANK = {
    "unknown": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise BaselineError("compared_at must include a timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BaselineError(f"timestamp {value!r} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _digest(value: Mapping[str, Any]) -> str:
    payload = {
        key: item for key, item in value.items() if key != "comparison_digest"
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _finding_index(scan_run: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    for finding in scan_run.get("findings", ()):
        fingerprint = str(finding.get("fingerprint") or "")
        if fingerprint in indexed:
            raise BaselineError(f"duplicate fingerprint {fingerprint!r}")
        indexed[fingerprint] = finding
    return indexed


def _worsened(previous: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    previous_rank = _SEVERITY_RANK.get(str(previous.get("normalised_severity")), 0)
    current_rank = _SEVERITY_RANK.get(str(current.get("normalised_severity")), 0)
    return current_rank > previous_rank


def _newly_reachable(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
) -> bool:
    return (
        current.get("reachability") == "reachable"
        and previous.get("reachability") != "reachable"
    )


def _exploited(finding: Mapping[str, Any]) -> bool:
    threat_value = finding.get("threat_intelligence")
    threat = threat_value if isinstance(threat_value, Mapping) else {}
    environment_value = finding.get("environment")
    environment = (
        environment_value if isinstance(environment_value, Mapping) else {}
    )
    return (
        threat.get("kev_status") is True
        or bool(threat.get("known_exploitation_date"))
        or environment.get("public_exploit_availability") is True
    )


def _newly_exploited_dependency(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
) -> bool:
    return (
        isinstance(current.get("dependency"), Mapping)
        and not _exploited(previous)
        and _exploited(current)
    )


def _expiry(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    if value.lower() == "expired":
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        if "T" in value:
            return _parse_timestamp(value)
        parsed_date = date.fromisoformat(value)
        return datetime.combine(parsed_date, time.min, tzinfo=timezone.utc)
    except ValueError:
        return None


def _expired_suppression(
    finding: Mapping[str, Any],
    compared_at: datetime,
) -> bool:
    history = finding.get("state_history")
    history_expiry: object = None
    if isinstance(history, list) and history:
        latest = history[-1]
        if isinstance(latest, Mapping) and latest.get("to_state") == "suppressed":
            history_expiry = latest.get("expires_at")
    environment_value = finding.get("environment")
    environment = (
        environment_value if isinstance(environment_value, Mapping) else {}
    )
    expires_at = _expiry(
        history_expiry
        if history_expiry is not None
        else environment.get("suppression_expiry")
    )
    return (
        finding.get("status") == "suppressed"
        and expires_at is not None
        and expires_at <= compared_at
    )


def _scanner_regressions(
    baseline: Mapping[str, Any],
    scan_run: Mapping[str, Any],
) -> list[dict[str, Any]]:
    current: dict[str, Mapping[str, Any]] = {}
    for scanner in scan_run.get("scanners", ()):
        name = str(scanner.get("scanner") or "")
        if name in current:
            raise BaselineError(f"duplicate scanner coverage record {name!r}")
        current[name] = scanner

    regressions: list[dict[str, Any]] = []
    for name, previous in sorted(baseline["scanners"].items()):
        if previous.get("healthy") is not True:
            continue
        current_scanner = current.get(name)
        if current_scanner is None:
            regressions.append(
                {
                    "scanner": name,
                    "baseline_state": previous["state"],
                    "current_state": None,
                    "reason": "previously healthy scanner is missing",
                }
            )
        elif current_scanner.get("healthy") is not True:
            regressions.append(
                {
                    "scanner": name,
                    "baseline_state": previous["state"],
                    "current_state": current_scanner.get("state"),
                    "reason": "previously healthy scanner is now unhealthy",
                }
            )
    return regressions


def compare_to_baseline(
    baseline: Mapping[str, Any],
    scan_run: Mapping[str, Any],
    *,
    compared_at: datetime | None = None,
) -> dict[str, Any]:
    """Compare a canonical pull-request scan with a verified baseline."""

    verify_baseline(baseline)
    validate_instance("scan-run", scan_run)
    if baseline.get("source_schema_version") != scan_run.get("schema_version"):
        raise BaselineCompatibilityError(
            "baseline and pull-request scan schema versions are incompatible"
        )
    if scan_run.get("repository") != baseline.get("repository"):
        raise BaselineCompatibilityError(
            "pull-request repository does not match baseline"
        )
    if scan_run.get("trigger") != "pull_request":
        raise BaselineError("comparison input must be a pull-request scan")
    if not isinstance(scan_run.get("ref"), str) or not scan_run["ref"]:
        raise BaselineError("pull-request ref is required")
    if not isinstance(scan_run.get("commit"), str) or not scan_run["commit"]:
        raise BaselineError("pull-request commit is required")

    comparison_time = compared_at or datetime.now(timezone.utc)
    compared_at_value = _timestamp(comparison_time)
    baseline_time = _parse_timestamp(str(baseline["generated_at"]))
    age = (comparison_time.astimezone(timezone.utc) - baseline_time).total_seconds()
    if age < 0:
        raise BaselineError("comparison time cannot precede baseline generation")

    previous = baseline["findings"]
    current = _finding_index(scan_run)
    previous_keys = set(previous)
    current_keys = set(current)
    persisting = previous_keys & current_keys

    result: dict[str, Any] = {
        "schema_version": "1.0.0",
        "version": 1,
        "repository": baseline["repository"],
        "baseline_digest": baseline["baseline_digest"],
        "baseline_generated_at": baseline["generated_at"],
        "baseline_ref": baseline["ref"],
        "baseline_commit": baseline["commit"],
        "current_run_id": scan_run["run_id"],
        "current_ref": scan_run["ref"],
        "current_commit": scan_run["commit"],
        "compared_at": compared_at_value,
        "baseline_age_seconds": age,
        "new_findings": sorted(current_keys - previous_keys),
        "removed_findings": sorted(previous_keys - current_keys),
        "persisting_findings": sorted(persisting),
        "worsened_findings": sorted(
            fingerprint
            for fingerprint in persisting
            if _worsened(previous[fingerprint], current[fingerprint])
        ),
        "newly_reachable_findings": sorted(
            fingerprint
            for fingerprint in persisting
            if _newly_reachable(previous[fingerprint], current[fingerprint])
        ),
        "newly_exploited_dependencies": sorted(
            fingerprint
            for fingerprint in persisting
            if _newly_exploited_dependency(
                previous[fingerprint], current[fingerprint]
            )
        ),
        "expired_suppressions": sorted(
            fingerprint
            for fingerprint, finding in current.items()
            if _expired_suppression(finding, comparison_time)
        ),
        "scanner_coverage_regressions": _scanner_regressions(
            baseline,
            scan_run,
        ),
    }
    result["summary"] = {
        key: len(result[key])
        for key in (
            "new_findings",
            "removed_findings",
            "persisting_findings",
            "worsened_findings",
            "newly_reachable_findings",
            "newly_exploited_dependencies",
            "expired_suppressions",
            "scanner_coverage_regressions",
        )
    }
    result["comparison_digest"] = _digest(result)
    validate_instance("baseline-diff", result)
    return result


__all__ = ["compare_to_baseline"]
