"""Tests for reliability targets and dashboards."""

from __future__ import annotations

import unittest

from trustgate.performance.reliability import (
    PerformanceBenchmark,
    ReliabilityDashboard,
    failure_rate_report,
    regression_threshold_check,
)


class PerformanceBenchmarkTests(unittest.TestCase):

    def test_passes_when_under_target(self):
        b = PerformanceBenchmark(
            name="scan", target_seconds=10.0, current_seconds=5.0,
        )
        self.assertTrue(b.passed)

    def test_fails_when_over_threshold(self):
        b = PerformanceBenchmark(
            name="scan", target_seconds=10.0, threshold_factor=1.5,
            current_seconds=20.0,
        )
        self.assertFalse(b.passed)

    def test_passes_when_not_measured(self):
        b = PerformanceBenchmark(name="scan", target_seconds=10.0)
        self.assertTrue(b.passed)


class ReliabilityDashboardTests(unittest.TestCase):

    def test_failure_rate_all_success(self):
        dash = ReliabilityDashboard()
        dash.add_run("Bandit", success=True, duration=1.0)
        dash.add_run("Bandit", success=True, duration=2.0)
        self.assertAlmostEqual(dash.failure_rate(), 0.0)

    def test_failure_rate_mixed(self):
        dash = ReliabilityDashboard()
        dash.add_run("Bandit", success=True, duration=1.0)
        dash.add_run("Bandit", success=False, duration=2.0)
        self.assertAlmostEqual(dash.failure_rate(), 0.5)

    def test_failure_rate_by_scanner(self):
        dash = ReliabilityDashboard()
        dash.add_run("Bandit", success=True, duration=1.0)
        dash.add_run("Semgrep", success=False, duration=1.0)
        self.assertAlmostEqual(dash.failure_rate("Bandit"), 0.0)
        self.assertAlmostEqual(dash.failure_rate("Semgrep"), 1.0)

    def test_to_dict(self):
        dash = ReliabilityDashboard()
        dash.add_run("Bandit", success=True, duration=1.0)
        d = dash.to_dict()
        self.assertEqual(d["total_runs"], 1)
        self.assertIn("by_scanner", d)


class RegressionThresholdCheckTests(unittest.TestCase):

    def test_all_pass(self):
        benchmarks = [
            PerformanceBenchmark(
                name="scan", target_seconds=10.0, current_seconds=5.0,
            ),
        ]
        result = regression_threshold_check(benchmarks)
        self.assertTrue(result["passed"])

    def test_one_fails(self):
        benchmarks = [
            PerformanceBenchmark(
                name="scan", target_seconds=10.0, current_seconds=5.0,
            ),
            PerformanceBenchmark(
                name="slow", target_seconds=1.0, current_seconds=100.0,
            ),
        ]
        result = regression_threshold_check(benchmarks)
        self.assertFalse(result["passed"])


class FailureRateReportTests(unittest.TestCase):

    def test_report_structure(self):
        runs = [
            {"scanner": "Bandit", "success": True, "duration_seconds": 1.0},
            {"scanner": "Bandit", "success": False, "duration_seconds": 2.0},
        ]
        report = failure_rate_report(runs)
        self.assertEqual(report["total_runs"], 2)
        self.assertAlmostEqual(report["overall_failure_rate"], 0.5)


if __name__ == "__main__":
    unittest.main()
