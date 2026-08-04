"""Build canonical values for every public policy predicate."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any


POLICY_FIELDS = (
    "severity",
    "cwe",
    "cve",
    "epss",
    "kev",
    "reachability",
    "environment",
    "repository",
    "branch",
    "asset_criticality",
    "confidence_lower_bound",
    "finding_status",
    "introduced_in_pull_request",
    "fix_availability",
    "scanner_health",
    "secret_validation_status",
    "suppression_expiry",
)


@dataclass(frozen=True)
class PolicyContext:
    finding_id: str
    values: dict[str, Any]
    evidence_sources: dict[str, str | None]

    def __post_init__(self) -> None:
        if not self.finding_id:
            raise ValueError("finding_id is required")
        if set(self.values) != set(POLICY_FIELDS):
            raise ValueError("policy context must contain all supported fields")
        if set(self.evidence_sources) != set(POLICY_FIELDS):
            raise ValueError("policy context must record every evidence source")

    def value(self, field: str) -> Any:
        return deepcopy(self.values[field])

    def evidence(self, field: str) -> str | None:
        return self.evidence_sources[field]

    def unresolved_fields(self) -> list[str]:
        return [field for field in POLICY_FIELDS if self.values[field] is None]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "values": {
                field: deepcopy(self.values[field]) for field in POLICY_FIELDS
            },
            "evidence_sources": {
                field: self.evidence_sources[field] for field in POLICY_FIELDS
            },
            "unresolved_fields": self.unresolved_fields(),
        }


def _confidence(finding: Mapping[str, Any]) -> tuple[float | None, str | None]:
    component = finding.get("finding_validity_confidence")
    if isinstance(component, Mapping):
        for name in ("conservative_bound", "estimate"):
            value = component.get(name)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return float(value), f"finding.finding_validity_confidence.{name}"
    value = finding.get("confidence")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value), "finding.confidence"
    return None, None


def _reachability(finding: Mapping[str, Any]) -> tuple[str | None, str | None]:
    dynamic = finding.get("dynamic_correlation")
    if isinstance(dynamic, Mapping) and dynamic.get("status") == "confirmed":
        return "confirmed", "finding.dynamic_correlation.status"
    value = finding.get("reachability")
    mapping = {
        "reachable": "confirmed",
        "potentially_reachable": "likely",
        "unreachable": "unreachable",
        "unknown": "unknown",
        "not_applicable": "not_applicable",
    }
    return mapping.get(str(value)) if value is not None else None, (
        "finding.reachability" if value is not None else None
    )


def _scanner_health(
    scan_run: Mapping[str, Any],
    finding: Mapping[str, Any],
) -> tuple[str | None, str | None]:
    scanner_name = str(finding.get("scanner") or "")
    for scanner in scan_run.get("scanners", ()):
        if not isinstance(scanner, Mapping):
            continue
        if str(scanner.get("scanner") or "") != scanner_name:
            continue
        if scanner.get("healthy") is True:
            return "healthy", f"scan_run.scanners[{scanner_name}].healthy"
        state = str(scanner.get("state") or "").lower()
        mapping = {
            "partial": "partial",
            "failed_scanner": "failed",
            "skipped": "skipped",
        }
        return mapping.get(state, "unhealthy"), (
            f"scan_run.scanners[{scanner_name}].state"
        )
    return "missing", "scan_run.scanners"


def _branch(ref: Any) -> str | None:
    if not isinstance(ref, str) or not ref:
        return None
    prefix = "refs/heads/"
    return ref[len(prefix):] if ref.startswith(prefix) else ref


def _suppression_expiry(
    finding: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> tuple[Any, str | None]:
    history = finding.get("state_history")
    if finding.get("status") == "suppressed" and isinstance(history, list) and history:
        latest = history[-1]
        if isinstance(latest, Mapping) and latest.get("to_state") == "suppressed":
            return latest.get("expires_at"), "finding.state_history[-1].expires_at"
    if "suppression_expiry" in environment:
        return (
            environment.get("suppression_expiry"),
            "finding.environment.suppression_expiry",
        )
    return None, None


def build_policy_context(
    scan_run: Mapping[str, Any],
    finding: Mapping[str, Any],
    *,
    runtime_context: Mapping[str, Any] | None = None,
) -> PolicyContext:
    """Capture policy selectors with provenance and explicit unknowns."""

    runtime = runtime_context or {}
    environment_value = finding.get("environment")
    environment = environment_value if isinstance(environment_value, Mapping) else {}
    threat_value = finding.get("threat_intelligence")
    threat = threat_value if isinstance(threat_value, Mapping) else {}

    confidence, confidence_source = _confidence(finding)
    reachability, reachability_source = _reachability(finding)
    scanner_health, scanner_source = _scanner_health(scan_run, finding)
    suppression_expiry, suppression_expiry_source = _suppression_expiry(
        finding,
        environment,
    )
    fixed_versions = threat.get("fixed_versions")
    fix_value: bool | None = None
    fix_source: str | None = None
    if isinstance(fixed_versions, list) and fixed_versions:
        fix_value = True
        fix_source = "finding.threat_intelligence.fixed_versions"
    elif isinstance(finding.get("remediation"), Mapping):
        fix_value = True
        fix_source = "finding.remediation"

    defaults: dict[str, tuple[Any, str | None]] = {
        "severity": (
            finding.get("normalised_severity"),
            "finding.normalised_severity" if "normalised_severity" in finding else None,
        ),
        "cwe": (sorted(str(value) for value in finding.get("cwe", ())), "finding.cwe"),
        "cve": (sorted(str(value) for value in finding.get("cve", ())), "finding.cve"),
        "epss": (
            threat.get("epss_probability"),
            (
                "finding.threat_intelligence.epss_probability"
                if "epss_probability" in threat
                else None
            ),
        ),
        "kev": (
            threat.get("kev_status"),
            "finding.threat_intelligence.kev_status" if "kev_status" in threat else None,
        ),
        "reachability": (reachability, reachability_source),
        "environment": (
            environment.get("runtime_environment"),
            (
                "finding.environment.runtime_environment"
                if "runtime_environment" in environment
                else None
            ),
        ),
        "repository": (
            scan_run.get("repository"),
            "scan_run.repository" if scan_run.get("repository") is not None else None,
        ),
        "branch": (
            _branch(scan_run.get("ref")),
            "scan_run.ref" if scan_run.get("ref") is not None else None,
        ),
        "asset_criticality": (
            environment.get("asset_criticality"),
            "finding.environment.asset_criticality" if "asset_criticality" in environment else None,
        ),
        "confidence_lower_bound": (confidence, confidence_source),
        "finding_status": (
            finding.get("status"),
            "finding.status" if "status" in finding else None,
        ),
        "introduced_in_pull_request": (None, None),
        "fix_availability": (fix_value, fix_source),
        "scanner_health": (scanner_health, scanner_source),
        "secret_validation_status": (
            environment.get("secret_validation_status"),
            (
                "finding.environment.secret_validation_status"
                if "secret_validation_status" in environment
                else None
            ),
        ),
        "suppression_expiry": (
            suppression_expiry,
            suppression_expiry_source,
        ),
    }
    values: dict[str, Any] = {}
    sources: dict[str, str | None] = {}
    for field in POLICY_FIELDS:
        if field in runtime:
            values[field] = deepcopy(runtime[field])
            sources[field] = f"runtime_context.{field}"
        else:
            values[field], sources[field] = defaults[field]
    return PolicyContext(
        finding_id=str(finding.get("finding_id") or ""),
        values=values,
        evidence_sources=sources,
    )


__all__ = ["POLICY_FIELDS", "PolicyContext", "build_policy_context"]
