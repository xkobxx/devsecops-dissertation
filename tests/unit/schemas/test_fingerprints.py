"""Stable finding fingerprint and correlation acceptance tests."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.aggregation import parse_pip_audit, parse_trivy
from trustgate.fingerprints import (
    FINGERPRINT_ALGORITHM_VERSION,
    fingerprint_finding,
    normalise_repository_path,
)
from trustgate.schema import migrate_finding, migrate_fingerprint, validate_instance


OBSERVED_AT = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)


def legacy_finding(**overrides: object) -> dict[str, object]:
    finding: dict[str, object] = {
        "tool": "Bandit",
        "rule_id": "B608",
        "severity": "MEDIUM",
        "description": "Possible SQL injection vector.",
        "file": "./src/app.py",
        "line": 42,
        "cwe": ["CWE-89"],
    }
    finding.update(overrides)
    return finding


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_algorithm_is_versioned(self) -> None:
        finding_id, fingerprint = fingerprint_finding(legacy_finding())

        self.assertTrue(finding_id.startswith("finding-v2-"))
        self.assertTrue(
            fingerprint.startswith(
                f"{FINGERPRINT_ALGORITHM_VERSION}:sha256:"
            )
        )

    def test_line_and_description_changes_do_not_change_identity(self) -> None:
        first = legacy_finding(line=42, description="First scanner wording.")
        shifted = legacy_finding(line=97, description="Updated scanner wording.")

        self.assertEqual(fingerprint_finding(first), fingerprint_finding(shifted))

    def test_unrelated_rules_in_the_same_file_do_not_merge(self) -> None:
        first = legacy_finding(rule_id="B608")
        unrelated = legacy_finding(rule_id="B602")

        self.assertNotEqual(
            fingerprint_finding(first)[1],
            fingerprint_finding(unrelated)[1],
        )

    def test_repository_paths_are_normalised_before_fingerprinting(self) -> None:
        with TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            absolute = root / "src" / "app.py"
            absolute.parent.mkdir()
            absolute.touch()

            self.assertEqual(
                normalise_repository_path(absolute, repository_root=root),
                "src/app.py",
            )
            self.assertEqual(
                normalise_repository_path(r".\src\app.py"),
                "src/app.py",
            )
            self.assertEqual(
                fingerprint_finding(
                    legacy_finding(file=str(absolute)),
                    repository_root=root,
                ),
                fingerprint_finding(legacy_finding(file="src/app.py")),
            )
            migrated = migrate_finding(
                legacy_finding(file=str(absolute)),
                observed_at=OBSERVED_AT,
                repository_root=root,
            )
            self.assertEqual(migrated["file"], "src/app.py")

    def test_migration_upgrades_an_old_fingerprint_with_audit_evidence(self) -> None:
        current = migrate_finding(
            legacy_finding(),
            observed_at=OBSERVED_AT,
        )
        current["finding_id"] = "finding-old"
        current["fingerprint"] = "legacy-v1:" + "a" * 64

        migrated = migrate_fingerprint(current)

        validate_instance("finding", migrated)
        self.assertNotEqual(migrated["fingerprint"], current["fingerprint"])
        self.assertTrue(migrated["fingerprint"].startswith("v2:sha256:"))
        migration_evidence = [
            item
            for item in migrated["evidence"]
            if item["kind"] == "fingerprint_migration"
        ]
        self.assertEqual(len(migration_evidence), 1)
        self.assertEqual(
            migration_evidence[0]["excerpt"],
            current["fingerprint"],
        )

    def test_current_fingerprint_migration_is_idempotent(self) -> None:
        current = migrate_finding(
            legacy_finding(),
            observed_at=OBSERVED_AT,
        )

        migrated = migrate_fingerprint(current)

        self.assertEqual(migrated, current)
        self.assertIsNot(migrated, current)

    def test_dependency_reports_from_different_scanners_correlate(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            pip_report = directory / "pip.json"
            pip_report.write_text(
                json.dumps(
                    {
                        "dependencies": [
                            {
                                "name": "example",
                                "version": "1.0.0",
                                "vulns": [
                                    {
                                        "id": "CVE-2026-12345",
                                        "description": "Dependency issue.",
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            trivy_report = directory / "trivy.json"
            trivy_report.write_text(
                json.dumps(
                    {
                        "Results": [
                            {
                                "Target": "requirements.lock",
                                "Type": "pypi",
                                "Vulnerabilities": [
                                    {
                                        "VulnerabilityID": "CVE-2026-12345",
                                        "Severity": "HIGH",
                                        "Description": "Different wording.",
                                        "PkgName": "example",
                                        "InstalledVersion": "1.0.0",
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            pip_finding = parse_pip_audit(pip_report)[0]
            trivy_finding = parse_trivy(trivy_report)[0]

            self.assertNotEqual(pip_finding["finding_id"], trivy_finding["finding_id"])
            self.assertEqual(
                pip_finding["fingerprint"],
                trivy_finding["fingerprint"],
            )

    def test_collision_sample_keeps_unrelated_findings_distinct(self) -> None:
        fingerprints = {
            fingerprint_finding(
                legacy_finding(
                    rule_id=f"RULE-{index}",
                    file=f"src/module_{index % 17}.py",
                )
            )[1]
            for index in range(1000)
        }

        self.assertEqual(len(fingerprints), 1000)

    def test_same_issue_survives_nearby_code_edits_after_migration(self) -> None:
        before = migrate_finding(
            legacy_finding(line=10),
            observed_at=OBSERVED_AT,
        )
        after = migrate_finding(
            legacy_finding(line=13),
            observed_at=OBSERVED_AT,
        )

        self.assertEqual(before["finding_id"], after["finding_id"])
        self.assertEqual(before["fingerprint"], after["fingerprint"])

    def test_fingerprint_input_is_not_mutated(self) -> None:
        finding = legacy_finding()
        original = deepcopy(finding)

        fingerprint_finding(finding)

        self.assertEqual(finding, original)


if __name__ == "__main__":
    unittest.main()
