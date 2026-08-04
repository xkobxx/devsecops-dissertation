"""Build an auditable snapshot of every Phase 10 decision component."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import COMPONENT_NAMES, DecisionComponent, DecisionContext


DECISION_COMPONENTS = COMPONENT_NAMES


def _component(
    name: str,
    value: Any,
    evidence: str | None,
    *,
    uncertainty: str | None = None,
) -> DecisionComponent:
    if value is None and uncertainty is None:
        uncertainty = f"{name.replace('_', ' ').capitalize()} is not available."
    if isinstance(value, str) and value.lower() in {"unknown", "not_applicable"}:
        uncertainty = uncertainty or (
            f"{name.replace('_', ' ').capitalize()} remains {value}."
        )
    return DecisionComponent(
        name=name,
        value=value,
        evidence=(evidence,) if evidence else (),
        uncertainty=uncertainty,
    )


def _runtime_value(
    runtime_context: Mapping[str, Any],
    environment: Mapping[str, Any],
    component: str,
    environment_key: str,
) -> tuple[Any, str | None]:
    if component in runtime_context:
        return runtime_context[component], f"runtime_context.{component}"
    if environment_key in runtime_context:
        return runtime_context[environment_key], f"runtime_context.{environment_key}"
    if environment_key in environment:
        return environment[environment_key], f"finding.environment.{environment_key}"
    if component in environment:
        return environment[component], f"finding.environment.{component}"
    return None, None


def _confidence(finding: Mapping[str, Any]) -> tuple[float | None, str | None]:
    component = finding.get("finding_validity_confidence")
    if isinstance(component, Mapping):
        for field in ("conservative_bound", "estimate"):
            value = component.get(field)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return float(value), f"finding.finding_validity_confidence.{field}"
    value = finding.get("confidence")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value), "finding.confidence"
    return None, None


def _normalise_controls(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, (list, tuple, set)):
        raise ValueError("existing_controls must be a collection of control names")
    return tuple(sorted({str(control) for control in value if str(control)}))


def build_decision_context(
    finding: Mapping[str, Any],
    *,
    runtime_context: Mapping[str, Any] | None = None,
) -> DecisionContext:
    """Capture all decision inputs without turning missing data into low risk."""

    finding_id = str(finding.get("finding_id") or "")
    if not finding_id:
        raise ValueError("finding_id is required for decision evaluation")
    runtime = runtime_context or {}
    environment_value = finding.get("environment")
    environment = (
        environment_value
        if isinstance(environment_value, Mapping)
        else {}
    )
    threat_value = finding.get("threat_intelligence")
    threat = threat_value if isinstance(threat_value, Mapping) else {}

    confidence, confidence_source = _confidence(finding)
    epss_value = runtime.get("epss", threat.get("epss_probability"))
    epss_source = (
        "runtime_context.epss"
        if "epss" in runtime
        else (
            "finding.threat_intelligence.epss_probability"
            if "epss_probability" in threat
            else None
        )
    )
    kev_value = runtime.get("cisa_kev", threat.get("kev_status"))
    kev_source = (
        "runtime_context.cisa_kev"
        if "cisa_kev" in runtime
        else (
            "finding.threat_intelligence.kev_status"
            if "kev_status" in threat
            else None
        )
    )
    components = [
        _component(
            "finding_validity_confidence",
            confidence,
            confidence_source,
        ),
        _component(
            "original_severity",
            finding.get("original_severity"),
            "finding.original_severity" if "original_severity" in finding else None,
        ),
        _component(
            "normalised_severity",
            finding.get("normalised_severity"),
            "finding.normalised_severity" if "normalised_severity" in finding else None,
        ),
        _component(
            "reachability",
            finding.get("reachability"),
            "finding.reachability" if "reachability" in finding else None,
        ),
        _component(
            "epss",
            epss_value,
            epss_source,
        ),
        _component(
            "cisa_kev",
            kev_value,
            kev_source,
        ),
    ]

    contextual_fields = (
        ("public_exploit_availability", "public_exploit_available"),
        ("internet_exposure", "internet_exposed"),
        ("authentication_requirements", "authentication_required"),
        ("data_sensitivity", "data_sensitivity"),
        ("asset_criticality", "asset_criticality"),
        ("runtime_environment", "runtime_environment"),
        ("existing_controls", "existing_controls"),
    )
    for component_name, environment_key in contextual_fields:
        value, source = _runtime_value(
            runtime,
            environment,
            component_name,
            environment_key,
        )
        if component_name == "existing_controls":
            value = _normalise_controls(value)
        components.append(_component(component_name, value, source))

    fix_value, fix_source = _runtime_value(
        runtime,
        environment,
        "fix_availability",
        "fix_available",
    )
    fixed_versions = threat.get("fixed_versions")
    if fix_value is None and isinstance(fixed_versions, list) and fixed_versions:
        fix_value = True
        fix_source = "finding.threat_intelligence.fixed_versions"
    if fix_value is None and isinstance(finding.get("remediation"), Mapping):
        fix_value = True
        fix_source = "finding.remediation"
    components.append(_component("fix_availability", fix_value, fix_source))

    change_value, change_source = _runtime_value(
        runtime,
        environment,
        "new_existing_status",
        "change_status",
    )
    components.append(
        _component("new_existing_status", change_value, change_source)
    )
    triage_value, triage_source = _runtime_value(
        runtime,
        environment,
        "human_triage_state",
        "human_triage_state",
    )
    if triage_value is None and "status" in finding:
        triage_value = finding.get("status")
        triage_source = "finding.status"
    components.append(
        _component("human_triage_state", triage_value, triage_source)
    )

    return DecisionContext(
        finding_id=finding_id,
        components=tuple(components),
    )
