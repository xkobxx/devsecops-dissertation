"""Tests for performance execution infrastructure."""

from __future__ import annotations

import unittest

from trustgate.performance.execution import (
    CacheConfig,
    PerformanceError,
    ResourceLimits,
    ScannerDuration,
    build_scan_plan,
    changed_file_filter,
    incremental_scan_filter,
)


class ResourceLimitsTests(unittest.TestCase):

    def test_defaults_valid(self):
        limits = ResourceLimits()
        limits.validate()  # should not raise

    def test_zero_memory_rejected(self):
        limits = ResourceLimits(max_memory_mb=0)
        with self.assertRaises(PerformanceError):
            limits.validate()

    def test_zero_cpu_rejected(self):
        limits = ResourceLimits(max_cpu_seconds=0)
        with self.assertRaises(PerformanceError):
            limits.validate()

    def test_zero_parallel_rejected(self):
        limits = ResourceLimits(max_parallel_scanners=0)
        with self.assertRaises(PerformanceError):
            limits.validate()


class BuildScanPlanTests(unittest.TestCase):

    def test_single_scanner(self):
        plan = build_scan_plan(["Bandit"])
        self.assertEqual(plan["total_scanners"], 1)
        self.assertEqual(len(plan["parallel_groups"]), 1)

    def test_parallel_groups_respect_limits(self):
        limits = ResourceLimits(max_parallel_scanners=2)
        plan = build_scan_plan(
            ["Bandit", "Semgrep", "Trivy", "Grype"], limits=limits,
        )
        self.assertEqual(len(plan["parallel_groups"]), 2)
        self.assertEqual(len(plan["parallel_groups"][0]["scanners"]), 2)

    def test_changed_files_flag(self):
        plan = build_scan_plan(["Bandit"], changed_files=["app.py"])
        self.assertTrue(plan["changed_files_only"])
        self.assertEqual(plan["changed_file_count"], 1)

    def test_no_changed_files(self):
        plan = build_scan_plan(["Bandit"])
        self.assertFalse(plan["changed_files_only"])


class ChangedFileFilterTests(unittest.TestCase):

    def test_filters_to_changed(self):
        result = changed_file_filter(
            ["a.py", "b.py", "c.py"], ["b.py"],
        )
        self.assertEqual(result, ["b.py"])

    def test_empty_changed_list(self):
        result = changed_file_filter(["a.py"], [])
        self.assertEqual(result, [])


class IncrementalScanFilterTests(unittest.TestCase):

    def test_no_baseline_scans_everything(self):
        packages = [{"name": "pkg-a", "checksum": "abc"}]
        result = incremental_scan_filter(packages)
        self.assertEqual(len(result), 1)

    def test_unchanged_package_skipped(self):
        packages = [
            {"name": "pkg-a", "checksum": "abc"},
            {"name": "pkg-b", "checksum": "xyz"},
        ]
        result = incremental_scan_filter(
            packages, previous_checksums={"pkg-a": "abc"},
        )
        # pkg-a unchanged, pkg-b new
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "pkg-b")


class CacheConfigTests(unittest.TestCase):

    def test_defaults(self):
        config = CacheConfig()
        self.assertTrue(config.cache_scanner_installations)
        self.assertTrue(config.cache_threat_data)
        self.assertTrue(config.cache_dependency_graphs)

    def test_to_dict(self):
        config = CacheConfig(cache_dir="/tmp/cache")
        d = config.to_dict()
        self.assertEqual(d["cache_dir"], "/tmp/cache")


class ScannerDurationTests(unittest.TestCase):

    def test_to_dict(self):
        d = ScannerDuration(
            scanner="Bandit", duration_seconds=1.234,
            success=True, files_scanned=10, findings_count=3,
        )
        result = d.to_dict()
        self.assertEqual(result["scanner"], "Bandit")
        self.assertEqual(result["duration_seconds"], 1.234)


if __name__ == "__main__":
    unittest.main()
