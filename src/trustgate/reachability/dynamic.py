"""Conservative correlation of DAST observations with static findings."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable
from urllib.parse import urlsplit

from .models import DynamicOutcome


_PRECEDENCE = {
    DynamicOutcome.CONFIRMED.value: 4,
    DynamicOutcome.BLOCKED_AUTHENTICATION.value: 3,
    DynamicOutcome.FAILED_REPRODUCTION.value: 2,
    DynamicOutcome.INCONCLUSIVE.value: 1,
    DynamicOutcome.NOT_ATTEMPTED.value: 0,
}


def correlate_dynamic_evidence(
    findings: Iterable[dict[str, Any]],
    observations: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach matching runtime evidence without suppressing static evidence."""

    validated = tuple(_validate_observation(value) for value in observations)
    correlated = []
    for original in findings:
        finding = deepcopy(original)
        matches = []
        for observation in validated:
            match = _match(finding, observation)
            if match is not None:
                matches.append((observation, match))
        if matches:
            strongest = max(
                matches,
                key=lambda item: _PRECEDENCE[item[0]["outcome"]],
            )[0]
            outcome = strongest["outcome"]
            confirmed = outcome == DynamicOutcome.CONFIRMED.value
            finding["dynamic_correlation"] = {
                "status": outcome,
                "matched_observation_ids": sorted(
                    str(observation["observation_id"])
                    for observation, _ in matches
                ),
                "endpoint_matched": any(
                    match["endpoint_matched"] for _, match in matches
                ),
                "parameter_matched": any(
                    match["parameter_matched"] for _, match in matches
                ),
                "sink_matched": any(
                    match["sink_matched"] for _, match in matches
                ),
                "priority_adjustment": "increased" if confirmed else "unchanged",
                "priority_reason": (
                    "Static source-to-sink evidence was dynamically confirmed."
                    if confirmed
                    else "Runtime evidence was not a successful confirmation."
                ),
                "authentication_state": str(
                    strongest.get("authentication_state") or "unknown"
                ),
                "failed_reproduction_attempts": [
                    {
                        "observation_id": str(observation["observation_id"]),
                        "evidence": [str(value) for value in observation["evidence"]],
                    }
                    for observation, _ in matches
                    if observation["outcome"]
                    == DynamicOutcome.FAILED_REPRODUCTION.value
                ],
                "static_evidence": deepcopy(finding.get("data_flow", [])),
                "runtime_evidence": [
                    str(value)
                    for observation, _ in matches
                    for value in observation["evidence"]
                ],
                "limitations": [
                    "A failed or inconclusive runtime attempt does not disprove "
                    "the static finding or suppress it."
                ],
            }
        correlated.append(finding)
    return correlated


def _match(
    finding: dict[str, Any],
    observation: dict[str, Any],
) -> dict[str, bool] | None:
    analysis = finding.get("source_to_sink_analysis")
    if not isinstance(analysis, dict):
        return None
    routes = analysis.get("framework_routes", [])
    endpoint = _endpoint(str(observation.get("endpoint") or ""))
    endpoint_matched = any(
        _endpoint(str(route.get("endpoint") or "")) == endpoint
        for route in routes
        if isinstance(route, dict)
    )
    parameter = str(observation.get("parameter") or "").lower()
    source_values = [str(finding.get("source") or "")]
    source_values.extend(
        str(source.get("symbol") or "")
        for source in analysis.get("identified_sources", [])
        if isinstance(source, dict)
    )
    parameter_matched = bool(parameter) and any(
        parameter in value.lower() for value in source_values
    )
    sink = str(observation.get("sink") or "").lower()
    sink_values = [str(finding.get("sink") or "")]
    sink_values.extend(
        str(value.get("symbol") or "")
        for value in analysis.get("identified_sinks", [])
        if isinstance(value, dict)
    )
    sink_matched = bool(sink) and any(
        sink == value.lower()
        or sink.rsplit(".", 1)[-1] == value.lower().rsplit(".", 1)[-1]
        for value in sink_values
    )
    if not endpoint_matched or not (parameter_matched or sink_matched):
        return None
    return {
        "endpoint_matched": endpoint_matched,
        "parameter_matched": parameter_matched,
        "sink_matched": sink_matched,
    }


def _validate_observation(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("dynamic observation must be an object")
    required = {"observation_id", "endpoint", "outcome", "evidence"}
    missing = sorted(required - set(value))
    if missing:
        raise ValueError(
            "dynamic observation is missing: " + ", ".join(missing)
        )
    try:
        DynamicOutcome(str(value["outcome"]))
    except ValueError as error:
        raise ValueError(
            f"unsupported dynamic outcome: {value['outcome']}"
        ) from error
    evidence = value["evidence"]
    if not isinstance(evidence, list):
        raise ValueError("dynamic observation evidence must be a list")
    return deepcopy(value)


def _endpoint(value: str) -> str:
    parsed = urlsplit(value)
    path = parsed.path or value
    normalized = "/" + path.strip("/")
    return normalized if normalized != "/" else "/"
