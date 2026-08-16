"""Reliability targets and dashboards.

Performance benchmarks, regression thresholds, reliability
dashboards, and failure-rate reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .execution import PERFORMANCE_SCHEMA_VERSION


@dataclass
class PerformanceBenchmark:
    """Performance benchmark with regression thresholds."""

    name: str
    target_seconds: float
    threshold_factor: float = 1.5  # fail if > 1.5x target
    current_seconds: float | None = None

    @property
    def passed(self) -> bool:
        if self.current_seconds is None:
            return True  # not yet measured
        return self.current_seconds <= self.target_seconds * self.threshold_factor

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "target_seconds": self.target_seconds,
            "threshold_factor": self.threshold_factor,
            "current_seconds": self.current_seconds,
            "passed": self.passed,
        }


@dataclass
class ReliabilityDashboard:
    """Reliability metrics dashboard."""

    scanner_runs: list[dict[str, Any]] = field(default_factory=list)
    benchmarks: list[PerformanceBenchmark] = field(default_factory=list)

    def add_run(self, scanner: str, *, success: bool, duration: float) -> None:
        self.scanner_runs.append({
            "scanner": scanner,
            "success": success,
            "duration_seconds": duration,
        })

    def failure_rate(self, scanner: str | None = None) -> float:
        runs = self.scanner_runs
        if scanner:
            runs = [r for r in runs if r["scanner"] == scanner]
        if not runs:
            return 0.0
        failures = sum(1 for r in runs if not r["success"])
        return failures / len(runs)

    def to_dict(self) -> dict[str, Any]:
        scanners = {r["scanner"] for r in self.scanner_runs}
        return {
            "schema_version": PERFORMANCE_SCHEMA_VERSION,
            "type": "reliability_dashboard",
            "total_runs": len(self.scanner_runs),
            "overall_failure_rate": self.failure_rate(),
            "by_scanner": {
                s: {
                    "runs": sum(1 for r in self.scanner_runs if r["scanner"] == s),
                    "failure_rate": self.failure_rate(s),
                }
                for s in sorted(scanners)
            },
            "benchmarks": [b.to_dict() for b in self.benchmarks],
        }


def regression_threshold_check(
    benchmarks: list[PerformanceBenchmark],
) -> dict[str, Any]:
    """Check performance benchmarks against regression thresholds."""
    results = []
    all_passed = True

    for b in benchmarks:
        results.append(b.to_dict())
        if not b.passed:
            all_passed = False

    return {
        "schema_version": PERFORMANCE_SCHEMA_VERSION,
        "type": "regression_threshold_check",
        "passed": all_passed,
        "benchmarks": results,
    }


def failure_rate_report(
    scanner_runs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate a failure rate report from scanner run data."""
    dashboard = ReliabilityDashboard(scanner_runs=scanner_runs)
    return dashboard.to_dict()
