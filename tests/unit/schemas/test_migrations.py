"""Tests for backward-compatible canonical-document migrations."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.schema import (
    SchemaMigrationError,
    migrate_finding,
    migrate_scan_run,
    validate_instance,
)

from .test_schema_contracts import valid_finding


OBSERVED_AT = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)


class SchemaMigrationTests(unittest.TestCase):
    def test_migrates_a_legacy_finding_without_discarding_source_values(self) -> None:
        legacy = {
            "tool": "Bandit",
            "rule_id": "B608",
            "severity": "MEDIUM",
            "description": "Possible SQL injection vector.",
            "file": "src/app.py",
            "line": 42,
        }

        migrated = migrate_finding(
            legacy,
            observed_at=OBSERVED_AT,
            category="sast",
            raw_report_reference={
                "path": "reports/bandit_report.json",
                "sha256": "a" * 64,
                "scanner_finding_id": None,
            },
        )

        validate_instance("finding", migrated)
        self.assertEqual(migrated["scanner"], "Bandit")
        self.assertEqual(migrated["rule_id"], "B608")
        self.assertEqual(migrated["original_severity"], "MEDIUM")
        self.assertEqual(migrated["normalised_severity"], "medium")
        self.assertEqual(migrated["description"], legacy["description"])
        self.assertEqual(migrated["start_line"], 42)
        self.assertTrue(str(migrated["fingerprint"]).startswith("v2:sha256:"))

    def test_every_supported_severity_mapping_is_explainable(self) -> None:
        cases = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "ERROR": "high",
            "MEDIUM": "medium",
            "WARNING": "medium",
            "LOW": "low",
            "INFO": "info",
            "UNKNOWN": "unknown",
            "vendor-specific": "unknown",
            None: "unknown",
        }

        for original, expected in cases.items():
            with self.subTest(original=original):
                migrated = migrate_finding(
                    {
                        "tool": "ExampleScanner",
                        "rule_id": "RULE-1",
                        "severity": original,
                        "description": "Example finding.",
                        "file": "app.py",
                        "line": 1,
                    },
                    observed_at=OBSERVED_AT,
                    normalisation_records=[
                        {
                            "canonical_field": "normalised_severity",
                            "source": "$.severity",
                            "original": original,
                            "transformation": (
                                "mapped scanner severity to Trust Gate severity"
                            ),
                        }
                    ],
                )

                self.assertEqual(migrated["original_severity"], original)
                self.assertEqual(migrated["normalised_severity"], expected)
                self.assertIn(
                    original if original is not None else "missing",
                    migrated["severity_reason"],
                )
                self.assertIn(expected, migrated["severity_reason"])
                severity_record = next(
                    item
                    for item in migrated["evidence"]
                    if item["kind"] == "normalisation"
                )
                self.assertIn(expected, severity_record["summary"] or "")

    def test_current_finding_migration_is_idempotent(self) -> None:
        current = valid_finding()

        migrated = migrate_finding(current, observed_at=OBSERVED_AT)

        self.assertEqual(migrated, current)
        self.assertIsNot(migrated, current)

    def test_rejects_an_unsupported_version_instead_of_guessing(self) -> None:
        future = valid_finding()
        future["schema_version"] = "2.0.0"

        with self.assertRaisesRegex(SchemaMigrationError, "unsupported"):
            migrate_finding(future, observed_at=OBSERVED_AT)

    def test_invalid_legacy_finding_is_a_migration_error(self) -> None:
        with self.assertRaisesRegex(SchemaMigrationError, "rule_id"):
            migrate_finding(
                {
                    "tool": "Bandit",
                    "severity": "HIGH",
                    "description": "Missing rule identifier.",
                    "file": "app.py",
                    "line": 3,
                },
                observed_at=OBSERVED_AT,
            )

    def test_migrates_a_legacy_aggregate_to_a_valid_scan_run(self) -> None:
        legacy = {
            "target": ".",
            "total": 1,
            "findings": [
                {
                    "tool": "Bandit",
                    "rule_id": "B608",
                    "severity": "MEDIUM",
                    "description": "Possible SQL injection vector.",
                    "file": "src/app.py",
                    "line": 42,
                }
            ],
            "scanner_results": [
                {
                    "scanner": "bandit",
                    "state": "FINDINGS",
                    "started_at": "2026-07-25T12:00:00+00:00",
                    "ended_at": "2026-07-25T12:00:02+00:00",
                    "duration_seconds": 2.0,
                    "exit_code": 1,
                    "timed_out": False,
                    "report_path": "reports/bandit_report.json",
                    "report_produced": True,
                    "parser_status": "SUCCESS",
                    "version": "1.9.4",
                    "stdout_path": None,
                    "stderr_path": None,
                    "finding_count": 1,
                    "error": None,
                    "required": True,
                }
            ],
        }

        migrated = migrate_scan_run(legacy, observed_at=OBSERVED_AT)

        validate_instance("scan-run", migrated)
        self.assertEqual(migrated["summary"]["total_findings"], 1)
        self.assertEqual(migrated["scanners"][0]["scanner_version"], "1.9.4")
        self.assertTrue(migrated["scanners"][0]["healthy"])
        self.assertNotIn("scanner_results", migrated)

    def test_migration_does_not_depend_on_the_current_working_directory(self) -> None:
        with TemporaryDirectory() as directory:
            current = Path.cwd()
            try:
                import os

                os.chdir(directory)
                migrated = migrate_finding(
                    {
                        "tool": "Gitleaks",
                        "rule_id": "generic-api-key",
                        "severity": "HIGH",
                        "description": "Secret detected.",
                        "file": "config.py",
                        "line": 9,
                    },
                    observed_at=OBSERVED_AT,
                    category="secrets",
                )
            finally:
                os.chdir(current)

        validate_instance("finding", migrated)


if __name__ == "__main__":
    unittest.main()
