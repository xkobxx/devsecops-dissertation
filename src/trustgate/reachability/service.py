"""Canonical scan-run orchestration for Phase 8 analyses."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable, Mapping

from .dependency import analyze_dependency_reachability
from .dynamic import correlate_dynamic_evidence
from .sast import apply_source_to_sink_analysis


def analyze_scan_run(
    scan_run: dict[str, Any],
    *,
    repository_root: Path,
    vulnerable_symbols: Mapping[str, Iterable[str]] | None = None,
    deployed_packages: Iterable[str] | None = None,
    dynamic_observations: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Analyze defensive copies and validate the resulting scan-run."""

    from trustgate.schema import validate_instance

    validate_instance("scan-run", scan_run)
    analyzed = deepcopy(scan_run)
    symbols = {
        _normalise_name(name): tuple(values)
        for name, values in (vulnerable_symbols or {}).items()
    }
    for finding in analyzed["findings"]:
        dependency = finding.get("dependency")
        if not isinstance(dependency, dict) or not dependency.get("name"):
            continue
        result = analyze_dependency_reachability(
            finding,
            repository_root=repository_root,
            vulnerable_symbols=symbols.get(
                _normalise_name(str(dependency["name"])), ()
            ),
            deployed_packages=deployed_packages,
        )
        finding["dependency_reachability"] = result
        if result["status"] == "CONFIRMED_REACHABLE":
            finding["reachability"] = "reachable"
        elif result["status"] == "LIKELY_REACHABLE":
            finding["reachability"] = "potentially_reachable"
        else:
            finding["reachability"] = "unknown"

    source_indexes = [
        index
        for index, finding in enumerate(analyzed["findings"])
        if not isinstance(finding.get("dependency"), dict)
    ]
    if source_indexes:
        source_findings = [analyzed["findings"][index] for index in source_indexes]
        source_results = apply_source_to_sink_analysis(
            source_findings, repository_root
        )
        for index, result in zip(source_indexes, source_results):
            analyzed["findings"][index] = result

    analyzed["findings"] = correlate_dynamic_evidence(
        analyzed["findings"], dynamic_observations
    )
    analyzed["summary"]["reachability_analysis"] = _summary(
        analyzed["findings"]
    )
    validate_instance("scan-run", analyzed)
    return analyzed


def _summary(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    values = tuple(findings)
    dependencies = [
        finding["dependency_reachability"]
        for finding in values
        if isinstance(finding.get("dependency_reachability"), dict)
    ]
    sources = [
        finding["source_to_sink_analysis"]
        for finding in values
        if isinstance(finding.get("source_to_sink_analysis"), dict)
    ]
    dynamics = [
        finding["dynamic_correlation"]
        for finding in values
        if isinstance(finding.get("dynamic_correlation"), dict)
    ]
    return {
        "dependency_findings_analyzed": len(dependencies),
        "source_findings_analyzed": sum(
            1 for item in sources if item["support"] != "unsupported"
        ),
        "source_paths_found": sum(
            1 for item in sources if item["status"] == "path-found"
        ),
        "unsupported_findings": sum(
            1 for item in sources if item["support"] == "unsupported"
        ),
        "incomplete_findings": sum(
            1 for item in dependencies if item["analysis_incomplete"]
        )
        + sum(1 for item in sources if item["analysis_incomplete"]),
        "confirmed_reachable": sum(
            1 for item in dependencies if item["status"] == "CONFIRMED_REACHABLE"
        ),
        "dynamically_confirmed": sum(
            1 for item in dynamics if item["status"] == "confirmed"
        ),
    }


def _normalise_name(value: str) -> str:
    return value.strip().lower().replace("_", "-")
