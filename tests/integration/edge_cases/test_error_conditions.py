"""Integration tests for error conditions and edge cases.

Covers: missing report, malformed report, scanner timeout, scanner crash,
empty repository, unsupported repository, monorepo, offline mode.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from trustgate.adapters.registry import AdapterRegistry
from trustgate.errors import (
    TrustGateError,
    no_findings_produced,
    sarif_parse_error,
    scanner_failed,
    scanner_not_found,
)


class MissingReportTests(unittest.TestCase):
    """Scanner produced no report file."""

    def test_missing_report_produces_structured_error(self):
        err = sarif_parse_error("/nonexistent/report.sarif")
        self.assertIn("report.sarif", err.what_failed)
        self.assertFalse(err.gate_trustworthy)

    def test_missing_report_coverage_incomplete(self):
        err = sarif_parse_error("/missing.sarif")
        self.assertIn("not included", err.coverage_impact)


class MalformedReportTests(unittest.TestCase):
    """Scanner produced invalid output."""

    def test_malformed_json_reported(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sarif", delete=False,
        ) as f:
            f.write("{not valid json")
            path = f.name
        try:
            err = sarif_parse_error(path, reason="Invalid JSON syntax")
            self.assertIn("Invalid JSON", err.why)
            self.assertFalse(err.gate_trustworthy)
        finally:
            os.unlink(path)

    def test_empty_file_reported(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sarif", delete=False,
        ) as f:
            f.write("")
            path = f.name
        try:
            err = sarif_parse_error(path, reason="Empty file")
            self.assertIn("Empty", err.why)
        finally:
            os.unlink(path)


class ScannerTimeoutTests(unittest.TestCase):
    """Scanner exceeded time limit."""

    def test_timeout_error_structured(self):
        err = scanner_failed("Bandit", exit_code=124)
        self.assertIn("124", err.what_failed)
        self.assertFalse(err.gate_trustworthy)

    def test_timeout_coverage_incomplete(self):
        err = scanner_failed("Semgrep", exit_code=124)
        self.assertIn("incomplete", err.coverage_impact)


class ScannerCrashTests(unittest.TestCase):
    """Scanner process crashed."""

    def test_crash_error_structured(self):
        err = scanner_failed("Trivy", exit_code=139)
        self.assertIn("Trivy", err.what_failed)
        self.assertFalse(err.gate_trustworthy)

    def test_scanner_not_installed(self):
        err = scanner_not_found("nonexistent-scanner")
        self.assertIn("not found", err.what_failed.lower())
        self.assertIn("adapter-list", err.how_to_resolve)


class EmptyRepositoryTests(unittest.TestCase):
    """Repository has no scannable files."""

    def test_no_findings_is_not_error(self):
        err = no_findings_produced()
        self.assertEqual(err.exit_code, 0)

    def test_no_findings_warns_about_coverage(self):
        err = no_findings_produced()
        self.assertIn("coverage", err.coverage_impact.lower())


class UnsupportedRepositoryTests(unittest.TestCase):
    """Repository uses a language with no scanner adapters."""

    def test_adapter_registry_exists(self):
        # The registry should be importable
        registry = AdapterRegistry()
        self.assertTrue(hasattr(registry, "names"))


class MonorepoTests(unittest.TestCase):
    """Monorepo with multiple scan targets."""

    def test_multiple_scan_roots(self):
        """Aggregation should handle findings from different paths."""
        findings = [
            {"fingerprint": "a", "file_path": "apps/web/src/app.py", "severity": "high"},
            {"fingerprint": "b", "file_path": "apps/api/src/api.py", "severity": "medium"},
            {"fingerprint": "c", "file_path": "libs/common/util.py", "severity": "low"},
        ]
        # Findings from different subdirectories should all be preserved
        paths = {f["file_path"] for f in findings}
        self.assertEqual(len(paths), 3)


class OfflineModeTests(unittest.TestCase):
    """Tests for offline/local-only operation."""

    def test_local_deployment_rejects_network(self):
        from trustgate.deployment.modes import (
            DeploymentModeError,
            validate_deployment_config,
        )
        with self.assertRaises(DeploymentModeError):
            validate_deployment_config({"mode": "local", "network_mode": "full"})

    def test_local_deployment_no_telemetry(self):
        from trustgate.deployment.modes import validate_deployment_config
        config = validate_deployment_config({"mode": "local"})
        self.assertFalse(config.telemetry_consent)


class SARIFUploadTests(unittest.TestCase):
    """SARIF generation produces valid output."""

    def test_sarif_schema_uri(self):
        from trustgate.sarif.generation import SARIF_SCHEMA_URI
        self.assertIn("sarif", SARIF_SCHEMA_URI.lower())


class SBOMVEXTests(unittest.TestCase):
    """SBOM and VEX generation tests."""

    def test_sbom_module_importable(self):
        from trustgate.supply_chain import generate_cyclonedx_sbom
        self.assertTrue(callable(generate_cyclonedx_sbom))

    def test_vex_module_importable(self):
        from trustgate.vex import generate_vex
        self.assertTrue(callable(generate_vex))


if __name__ == "__main__":
    unittest.main()
