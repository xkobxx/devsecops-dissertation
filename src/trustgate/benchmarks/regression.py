"""Benchmark regression detection across scanner versions.

Compares two benchmark metrics evaluations and detects regressions in
precision, recall, runtime, and conservative gating bounds.  Designed
to block releases when scanner upgrades silently degrade detection
quality.
"""

from __future__ import annotations

from typing import Any

REGRESSION_SCHEMA_VERSION = "1.0.0"

# ponytail: flat thresholds, per-tool override config when someone needs it
DEFAULT_THRESHOLDS = {
    "max_precision_drop": 0.05,
    "max_recall_drop": 0.05,
    "max_f1_drop": 0.05,
    "max_gating_estimate_drop": 0.05,
    "max_runtime_increase_factor": 2.0,
}


class BenchmarkRegressionError(ValueError):
    """Raised when a benchmark regression is detected."""


def _tool_delta(
    tool: str,
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    """Compare one tool's metrics between baseline and current."""
    delta = {
        "tool": tool,
        "precision": {
            "baseline": baseline["precision"],
            "current": current["precision"],
            "delta": round(current["precision"] - baseline["precision"], 6),
        },
        "recall": {
            "baseline": baseline["recall"],
            "current": current["recall"],
            "delta": round(current["recall"] - baseline["recall"], 6),
        },
        "f1": {
            "baseline": baseline["f1"],
            "current": current["f1"],
            "delta": round(current["f1"] - baseline["f1"], 6),
        },
        "sample_size": {
            "baseline": baseline["sample_size"],
            "current": current["sample_size"],
        },
    }
    # Gating estimate from posterior precision
    bp = baseline.get("posterior_precision", {})
    cp = current.get("posterior_precision", {})
    if bp and cp:
        delta["gating_estimate"] = {
            "baseline": bp.get("gating_estimate", 0.0),
            "current": cp.get("gating_estimate", 0.0),
            "delta": round(
                cp.get("gating_estimate", 0.0) - bp.get("gating_estimate", 0.0),
                6,
            ),
        }
    return delta


def _scanner_version_diff(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, dict[str, str]]:
    """Extract scanner version changes between two evaluations."""
    b_runs = baseline.get("evidence", {}).get("runs_considered", [])
    c_runs = current.get("evidence", {}).get("runs_considered", [])

    b_versions: dict[str, str] = {}
    c_versions: dict[str, str] = {}
    for run in b_runs:
        for tool, version in (run.get("scanner_versions") or {}).items():
            b_versions[tool] = version
    for run in c_runs:
        for tool, version in (run.get("scanner_versions") or {}).items():
            c_versions[tool] = version

    changes: dict[str, dict[str, str]] = {}
    for tool in sorted(set(b_versions) | set(c_versions)):
        old = b_versions.get(tool, "absent")
        new = c_versions.get(tool, "absent")
        if old != new:
            changes[tool] = {"baseline": old, "current": new}
    return changes


def compare_evaluations(
    baseline: dict[str, Any],
    current: dict[str, Any],
    *,
    thresholds: dict[str, float] | None = None,
    runtime_baseline: dict[str, float] | None = None,
    runtime_current: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Compare two benchmark metrics and detect regressions.

    Args:
        baseline: Metrics from the previous (known-good) evaluation.
        current: Metrics from the new evaluation to validate.
        thresholds: Override default regression thresholds.
        runtime_baseline: Tool -> seconds for the baseline run.
        runtime_current: Tool -> seconds for the current run.

    Returns:
        Regression report with pass/fail, per-tool deltas, and
        identified regressions.
    """
    t = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    regressions: list[dict[str, Any]] = []
    tool_deltas: dict[str, dict[str, Any]] = {}

    b_tools = baseline.get("tools", {})
    c_tools = current.get("tools", {})
    all_tools = sorted(set(b_tools) | set(c_tools))

    for tool in all_tools:
        if tool not in b_tools:
            # New tool — no regression possible
            continue
        if tool not in c_tools:
            regressions.append({
                "tool": tool,
                "metric": "coverage",
                "detail": f"{tool} was evaluated in baseline but missing from current",
            })
            continue

        delta = _tool_delta(tool, b_tools[tool], c_tools[tool])
        tool_deltas[tool] = delta

        if delta["precision"]["delta"] < -t["max_precision_drop"]:
            regressions.append({
                "tool": tool,
                "metric": "precision",
                "baseline": delta["precision"]["baseline"],
                "current": delta["precision"]["current"],
                "delta": delta["precision"]["delta"],
                "threshold": -t["max_precision_drop"],
            })
        if delta["recall"]["delta"] < -t["max_recall_drop"]:
            regressions.append({
                "tool": tool,
                "metric": "recall",
                "baseline": delta["recall"]["baseline"],
                "current": delta["recall"]["current"],
                "delta": delta["recall"]["delta"],
                "threshold": -t["max_recall_drop"],
            })
        if delta["f1"]["delta"] < -t["max_f1_drop"]:
            regressions.append({
                "tool": tool,
                "metric": "f1",
                "baseline": delta["f1"]["baseline"],
                "current": delta["f1"]["current"],
                "delta": delta["f1"]["delta"],
                "threshold": -t["max_f1_drop"],
            })
        ge = delta.get("gating_estimate")
        if ge and ge["delta"] < -t["max_gating_estimate_drop"]:
            regressions.append({
                "tool": tool,
                "metric": "gating_estimate",
                "baseline": ge["baseline"],
                "current": ge["current"],
                "delta": ge["delta"],
                "threshold": -t["max_gating_estimate_drop"],
            })

    # Overall metrics comparison
    b_overall = baseline.get("overall", {})
    c_overall = current.get("overall", {})
    if b_overall and c_overall:
        overall_delta = _tool_delta("overall", b_overall, c_overall)
        tool_deltas["overall"] = overall_delta

    # Runtime regressions (optional — only when timing data is provided)
    runtime_regressions: list[dict[str, Any]] = []
    if runtime_baseline and runtime_current:
        max_factor = t["max_runtime_increase_factor"]
        for tool in sorted(set(runtime_baseline) & set(runtime_current)):
            b_time = runtime_baseline[tool]
            c_time = runtime_current[tool]
            if b_time > 0 and c_time / b_time > max_factor:
                runtime_regressions.append({
                    "tool": tool,
                    "baseline_seconds": b_time,
                    "current_seconds": c_time,
                    "factor": round(c_time / b_time, 2),
                    "threshold_factor": max_factor,
                })
                regressions.append({
                    "tool": tool,
                    "metric": "runtime",
                    "baseline_seconds": b_time,
                    "current_seconds": c_time,
                    "factor": round(c_time / b_time, 2),
                    "threshold_factor": max_factor,
                })

    passed = len(regressions) == 0
    scanner_changes = _scanner_version_diff(baseline, current)

    return {
        "schema_version": REGRESSION_SCHEMA_VERSION,
        "passed": passed,
        "baseline_id": baseline.get("benchmark_id", "unknown"),
        "baseline_version": baseline.get("benchmark_version", "unknown"),
        "current_id": current.get("benchmark_id", "unknown"),
        "current_version": current.get("benchmark_version", "unknown"),
        "dataset_versions": {
            "baseline": baseline.get("evidence", {})
            .get("dataset", {})
            .get("version", "unknown"),
            "current": current.get("evidence", {})
            .get("dataset", {})
            .get("version", "unknown"),
        },
        "scanner_version_changes": scanner_changes,
        "thresholds": t,
        "tool_deltas": tool_deltas,
        "regressions": regressions,
        "runtime_regressions": runtime_regressions,
        "regression_count": len(regressions),
    }


def render_regression_report(report: dict[str, Any]) -> str:
    """Render a human-readable regression report."""
    lines: list[str] = []
    status = "PASSED" if report["passed"] else "FAILED"
    lines.append(f"Benchmark regression check: {status}")
    lines.append(
        f"Baseline: {report['baseline_id']} {report['baseline_version']}  "
        f"→  Current: {report['current_id']} {report['current_version']}"
    )

    changes = report.get("scanner_version_changes", {})
    if changes:
        lines.append("")
        lines.append("Scanner version changes:")
        for tool, versions in sorted(changes.items()):
            lines.append(
                f"  {tool}: {versions['baseline']} → {versions['current']}"
            )

    deltas = report.get("tool_deltas", {})
    if deltas:
        lines.append("")
        lines.append(
            "| Tool | Precision Δ | Recall Δ | F1 Δ | Gating Δ |"
        )
        lines.append("|---|---:|---:|---:|---:|")
        for tool, delta in sorted(deltas.items()):
            ge = delta.get("gating_estimate", {})
            ge_str = f"{ge.get('delta', 0):+.3f}" if ge else "n/a"
            lines.append(
                f"| {tool} "
                f"| {delta['precision']['delta']:+.3f} "
                f"| {delta['recall']['delta']:+.3f} "
                f"| {delta['f1']['delta']:+.3f} "
                f"| {ge_str} |"
            )

    if report["regressions"]:
        lines.append("")
        lines.append(f"Regressions detected ({report['regression_count']}):")
        for reg in report["regressions"]:
            lines.append(f"  ✗ {reg['tool']}: {reg['metric']} regression")
    else:
        lines.append("")
        lines.append("No regressions detected.")

    return "\n".join(lines)


__all__ = [
    "BenchmarkRegressionError",
    "DEFAULT_THRESHOLDS",
    "REGRESSION_SCHEMA_VERSION",
    "compare_evaluations",
    "render_regression_report",
]
