"""Tests for benchmark regression detection."""

from __future__ import annotations

import unittest

from trustgate.benchmarks.regression import (
    DEFAULT_THRESHOLDS,
    REGRESSION_SCHEMA_VERSION,
    compare_evaluations,
    render_regression_report,
)


def _make_tool_metrics(
    precision: float = 0.8,
    recall: float = 0.8,
    f1: float = 0.8,
    sample_size: int = 10,
    gating_estimate: float = 0.5,
) -> dict:
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "sample_size": sample_size,
        "true_positives": int(precision * sample_size),
        "false_positives": sample_size - int(precision * sample_size),
        "false_negatives": 2,
        "posterior_precision": {
            "gating_estimate": gating_estimate,
            "displayed_estimate": precision,
            "maturity": "Directional",
        },
    }


def _make_metrics(
    tools: dict | None = None,
    benchmark_id: str = "test-benchmark",
    benchmark_version: str = "1.0.0",
    scanner_versions: dict | None = None,
) -> dict:
    if tools is None:
        tools = {
            "Bandit": _make_tool_metrics(),
            "Semgrep": _make_tool_metrics(precision=0.9, recall=0.85),
        }
    evidence = {
        "dataset": {"version": "1.0.0"},
        "runs_considered": [],
    }
    if scanner_versions:
        evidence["runs_considered"] = [
            {"scanner_versions": scanner_versions}
        ]
    return {
        "benchmark_id": benchmark_id,
        "benchmark_version": benchmark_version,
        "overall": _make_tool_metrics(precision=0.85, recall=0.82),
        "tools": tools,
        "evidence": evidence,
    }


class BenchmarkRegressionTests(unittest.TestCase):

    def test_identical_evaluations_pass(self):
        metrics = _make_metrics()
        report = compare_evaluations(metrics, metrics)
        self.assertTrue(report["passed"])
        self.assertEqual(report["regression_count"], 0)
        self.assertEqual(report["schema_version"], REGRESSION_SCHEMA_VERSION)

    def test_improved_metrics_pass(self):
        baseline = _make_metrics()
        current = _make_metrics(tools={
            "Bandit": _make_tool_metrics(precision=0.9, recall=0.9),
            "Semgrep": _make_tool_metrics(precision=0.95, recall=0.9),
        })
        report = compare_evaluations(baseline, current)
        self.assertTrue(report["passed"])
        self.assertEqual(report["regression_count"], 0)

    def test_precision_regression_detected(self):
        baseline = _make_metrics()
        current = _make_metrics(tools={
            "Bandit": _make_tool_metrics(precision=0.7),  # -0.1 drop
            "Semgrep": _make_tool_metrics(precision=0.9, recall=0.85),
        })
        report = compare_evaluations(baseline, current)
        self.assertFalse(report["passed"])
        precision_regs = [
            r for r in report["regressions"] if r["metric"] == "precision"
        ]
        self.assertEqual(len(precision_regs), 1)
        self.assertEqual(precision_regs[0]["tool"], "Bandit")

    def test_recall_regression_detected(self):
        baseline = _make_metrics()
        current = _make_metrics(tools={
            "Bandit": _make_tool_metrics(recall=0.7),  # -0.1 drop
            "Semgrep": _make_tool_metrics(precision=0.9, recall=0.85),
        })
        report = compare_evaluations(baseline, current)
        self.assertFalse(report["passed"])
        recall_regs = [
            r for r in report["regressions"] if r["metric"] == "recall"
        ]
        self.assertEqual(len(recall_regs), 1)
        self.assertEqual(recall_regs[0]["tool"], "Bandit")

    def test_gating_estimate_regression_detected(self):
        baseline = _make_metrics(tools={
            "Bandit": _make_tool_metrics(gating_estimate=0.6),
        })
        current = _make_metrics(tools={
            "Bandit": _make_tool_metrics(gating_estimate=0.5),  # -0.1 drop
        })
        report = compare_evaluations(baseline, current)
        self.assertFalse(report["passed"])
        ge_regs = [
            r for r in report["regressions"]
            if r["metric"] == "gating_estimate"
        ]
        self.assertEqual(len(ge_regs), 1)

    def test_small_drops_within_threshold_pass(self):
        baseline = _make_metrics()
        current = _make_metrics(tools={
            "Bandit": _make_tool_metrics(precision=0.76),  # -0.04, within 0.05
            "Semgrep": _make_tool_metrics(precision=0.9, recall=0.85),
        })
        report = compare_evaluations(baseline, current)
        self.assertTrue(report["passed"])

    def test_custom_thresholds_respected(self):
        baseline = _make_metrics()
        current = _make_metrics(tools={
            "Bandit": _make_tool_metrics(precision=0.76),  # -0.04 drop
            "Semgrep": _make_tool_metrics(precision=0.9, recall=0.85),
        })
        # Default threshold 0.05 passes, but stricter 0.03 fails
        report = compare_evaluations(
            baseline, current,
            thresholds={"max_precision_drop": 0.03},
        )
        self.assertFalse(report["passed"])

    def test_missing_tool_in_current_is_regression(self):
        baseline = _make_metrics()
        current = _make_metrics(tools={
            "Semgrep": _make_tool_metrics(precision=0.9, recall=0.85),
        })
        report = compare_evaluations(baseline, current)
        self.assertFalse(report["passed"])
        coverage_regs = [
            r for r in report["regressions"] if r["metric"] == "coverage"
        ]
        self.assertEqual(len(coverage_regs), 1)
        self.assertEqual(coverage_regs[0]["tool"], "Bandit")

    def test_new_tool_in_current_is_not_regression(self):
        baseline = _make_metrics(tools={
            "Bandit": _make_tool_metrics(),
        })
        current = _make_metrics(tools={
            "Bandit": _make_tool_metrics(),
            "Trivy": _make_tool_metrics(precision=0.7, recall=0.6),
        })
        report = compare_evaluations(baseline, current)
        self.assertTrue(report["passed"])

    def test_runtime_regression_detected(self):
        baseline = _make_metrics()
        current = _make_metrics()
        report = compare_evaluations(
            baseline, current,
            runtime_baseline={"Bandit": 10.0, "Semgrep": 20.0},
            runtime_current={"Bandit": 25.0, "Semgrep": 20.0},  # 2.5x
        )
        self.assertFalse(report["passed"])
        runtime_regs = [
            r for r in report["regressions"] if r["metric"] == "runtime"
        ]
        self.assertEqual(len(runtime_regs), 1)
        self.assertEqual(runtime_regs[0]["tool"], "Bandit")
        self.assertGreater(runtime_regs[0]["factor"], 2.0)

    def test_runtime_within_threshold_passes(self):
        baseline = _make_metrics()
        current = _make_metrics()
        report = compare_evaluations(
            baseline, current,
            runtime_baseline={"Bandit": 10.0},
            runtime_current={"Bandit": 18.0},  # 1.8x, under 2.0
        )
        self.assertTrue(report["passed"])

    def test_scanner_version_changes_tracked(self):
        baseline = _make_metrics(scanner_versions={
            "Bandit": "1.9.4",
            "Semgrep": "1.165.0",
        })
        current = _make_metrics(scanner_versions={
            "Bandit": "1.10.0",
            "Semgrep": "1.170.0",
        })
        report = compare_evaluations(baseline, current)
        changes = report["scanner_version_changes"]
        self.assertIn("Bandit", changes)
        self.assertEqual(changes["Bandit"]["baseline"], "1.9.4")
        self.assertEqual(changes["Bandit"]["current"], "1.10.0")

    def test_dataset_versions_recorded(self):
        baseline = _make_metrics(benchmark_version="1.0.0")
        current = _make_metrics(benchmark_version="1.1.0")
        report = compare_evaluations(baseline, current)
        self.assertIn("dataset_versions", report)

    def test_multiple_regressions_all_reported(self):
        baseline = _make_metrics()
        current = _make_metrics(tools={
            "Bandit": _make_tool_metrics(precision=0.6, recall=0.6),
            "Semgrep": _make_tool_metrics(precision=0.7, recall=0.7),
        })
        report = compare_evaluations(baseline, current)
        self.assertFalse(report["passed"])
        self.assertGreater(report["regression_count"], 1)

    def test_report_rendering_includes_status(self):
        baseline = _make_metrics()
        report = compare_evaluations(baseline, baseline)
        text = render_regression_report(report)
        self.assertIn("PASSED", text)
        self.assertIn("No regressions detected", text)

    def test_failed_report_rendering(self):
        baseline = _make_metrics()
        current = _make_metrics(tools={
            "Bandit": _make_tool_metrics(precision=0.5),
        })
        report = compare_evaluations(baseline, current)
        text = render_regression_report(report)
        self.assertIn("FAILED", text)
        self.assertIn("precision regression", text)

    def test_report_rendering_shows_scanner_changes(self):
        baseline = _make_metrics(scanner_versions={"Bandit": "1.9.4"})
        current = _make_metrics(scanner_versions={"Bandit": "1.10.0"})
        report = compare_evaluations(baseline, current)
        text = render_regression_report(report)
        self.assertIn("1.9.4", text)
        self.assertIn("1.10.0", text)

    def test_default_thresholds_are_sensible(self):
        self.assertGreater(DEFAULT_THRESHOLDS["max_precision_drop"], 0)
        self.assertLessEqual(DEFAULT_THRESHOLDS["max_precision_drop"], 0.1)
        self.assertGreater(DEFAULT_THRESHOLDS["max_runtime_increase_factor"], 1.0)


if __name__ == "__main__":
    unittest.main()
