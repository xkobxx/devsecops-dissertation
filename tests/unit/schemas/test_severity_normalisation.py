"""Regression tests for scanner-native and CVSS-aware severity handling."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.aggregation import (
    parse_bandit,
    parse_gitleaks,
    parse_pip_audit,
    parse_semgrep,
    parse_trivy,
)
from trustgate.schema import validate_instance
from trustgate.severity import normalise_scanner_severity


class SeverityNormalisationTests(unittest.TestCase):
    def _report(self, directory: Path, name: str, document: object) -> Path:
        path = directory / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_dependency_without_severity_remains_unknown_not_high(self) -> None:
        with TemporaryDirectory() as directory_name:
            finding = parse_pip_audit(
                self._report(
                    Path(directory_name),
                    "pip-audit.json",
                    {
                        "dependencies": [
                            {
                                "name": "example",
                                "version": "1.0.0",
                                "vulns": [
                                    {
                                        "id": "CVE-2026-12345",
                                        "description": "Dependency vulnerability.",
                                    }
                                ],
                            }
                        ]
                    },
                )
            )[0]

            validate_instance("finding", finding)
            self.assertIsNone(finding["original_severity"])
            self.assertEqual(finding["normalised_severity"], "unknown")
            self.assertNotEqual(finding["normalised_severity"], "high")
            self.assertIn("missing", finding["severity_reason"])

    def test_secret_without_severity_remains_unknown_not_high(self) -> None:
        with TemporaryDirectory() as directory_name:
            finding = parse_gitleaks(
                self._report(
                    Path(directory_name),
                    "gitleaks.json",
                    [
                        {
                            "RuleID": "unclassified-secret",
                            "Description": "Unclassified secret.",
                            "File": "settings.py",
                            "StartLine": 8,
                        }
                    ],
                )
            )[0]

            validate_instance("finding", finding)
            self.assertIsNone(finding["original_severity"])
            self.assertEqual(finding["normalised_severity"], "unknown")
            self.assertNotEqual(finding["normalised_severity"], "high")
            self.assertIn("missing", finding["severity_reason"])

    def test_trivy_cvss_is_recorded_and_used_when_severity_is_unknown(self) -> None:
        with TemporaryDirectory() as directory_name:
            finding = parse_trivy(
                self._report(
                    Path(directory_name),
                    "trivy.json",
                    {
                        "Results": [
                            {
                                "Target": "requirements.lock",
                                "Type": "pip",
                                "Vulnerabilities": [
                                    {
                                        "VulnerabilityID": "CVE-2026-54321",
                                        "Severity": "UNKNOWN",
                                        "Description": "Package vulnerability.",
                                        "PkgName": "example",
                                        "InstalledVersion": "1.0.0",
                                        "CVSS": {
                                            "redhat": {
                                                "V3Vector": (
                                                    "CVSS:3.1/AV:N/AC:L/PR:N/"
                                                    "UI:N/S:U/C:H/I:H/A:H"
                                                ),
                                                "V3Score": 9.8,
                                            },
                                            "nvd": {
                                                "V2Vector": (
                                                    "AV:N/AC:L/Au:N/C:P/I:P/A:P"
                                                ),
                                                "V2Score": 7.5,
                                            },
                                        },
                                    }
                                ],
                            }
                        ]
                    },
                )
            )[0]

            validate_instance("finding", finding)
            self.assertEqual(finding["original_severity"], "UNKNOWN")
            self.assertEqual(finding["normalised_severity"], "critical")
            self.assertIn("CVSS v3", finding["severity_reason"])
            self.assertIn("9.8", finding["severity_reason"])
            cvss_evidence = [
                item for item in finding["evidence"] if item["kind"] == "cvss"
            ]
            self.assertEqual(len(cvss_evidence), 2)
            self.assertTrue(
                any(
                    item["reference"].endswith(".CVSS.redhat")
                    and "9.8" in (item["summary"] or "")
                    and "CVSS:3.1" in (item["excerpt"] or "")
                    for item in cvss_evidence
                )
            )

    def test_trivy_scanner_severity_takes_precedence_over_cvss_fallback(self) -> None:
        with TemporaryDirectory() as directory_name:
            finding = parse_trivy(
                self._report(
                    Path(directory_name),
                    "trivy.json",
                    {
                        "Results": [
                            {
                                "Target": "image",
                                "Vulnerabilities": [
                                    {
                                        "VulnerabilityID": "CVE-2026-54321",
                                        "Severity": "LOW",
                                        "Description": "Package vulnerability.",
                                        "PkgName": "example",
                                        "CVSS": {
                                            "nvd": {
                                                "V3Score": 9.8,
                                                "V3Vector": "CVSS:3.1/example",
                                            }
                                        },
                                    }
                                ],
                            }
                        ]
                    },
                )
            )[0]

            self.assertEqual(finding["original_severity"], "LOW")
            self.assertEqual(finding["normalised_severity"], "low")
            self.assertIn("LOW", finding["severity_reason"])
            self.assertEqual(
                len(
                    [
                        item
                        for item in finding["evidence"]
                        if item["kind"] == "cvss"
                    ]
                ),
                1,
            )

    def test_invalid_cvss_does_not_turn_unknown_into_low(self) -> None:
        with TemporaryDirectory() as directory_name:
            finding = parse_trivy(
                self._report(
                    Path(directory_name),
                    "trivy.json",
                    {
                        "Results": [
                            {
                                "Target": "image",
                                "Vulnerabilities": [
                                    {
                                        "VulnerabilityID": "CVE-2026-54321",
                                        "Severity": "UNKNOWN",
                                        "Description": "Package vulnerability.",
                                        "PkgName": "example",
                                        "CVSS": {
                                            "nvd": {
                                                "V3Score": 11.0,
                                                "V3Vector": "invalid",
                                            }
                                        },
                                    }
                                ],
                            }
                        ]
                    },
                )
            )[0]

            self.assertEqual(finding["original_severity"], "UNKNOWN")
            self.assertEqual(finding["normalised_severity"], "unknown")
            self.assertNotEqual(finding["normalised_severity"], "low")

    def test_each_scanner_has_a_source_specific_mapping(self) -> None:
        cases = (
            ("bandit", "HIGH", "high"),
            ("bandit", "MEDIUM", "medium"),
            ("bandit", "LOW", "low"),
            ("semgrep", "ERROR", "high"),
            ("semgrep", "WARNING", "medium"),
            ("semgrep", "INFO", "info"),
            ("pip-audit", "MODERATE", "medium"),
            ("trivy", "CRITICAL", "critical"),
            ("trivy", "UNKNOWN", "unknown"),
            ("gitleaks", "HIGH", "high"),
        )

        for scanner, original, expected in cases:
            with self.subTest(scanner=scanner, original=original):
                decision = normalise_scanner_severity(scanner, original)
                self.assertEqual(decision.original, original)
                self.assertEqual(decision.normalised, expected)
                self.assertIn(scanner, decision.rule)
                self.assertIn(original, decision.reason)

    def test_unrecognised_and_missing_values_stay_unknown_not_low(self) -> None:
        for scanner, value in (
            ("bandit", None),
            ("semgrep", "EXPERIMENT"),
            ("pip-audit", None),
            ("trivy", "UNRATED"),
            ("gitleaks", None),
        ):
            with self.subTest(scanner=scanner, value=value):
                decision = normalise_scanner_severity(scanner, value)
                self.assertEqual(decision.normalised, "unknown")
                self.assertEqual(decision.quality, "low")

    def test_every_adapter_emits_a_severity_quality_indicator(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            cases = [
                parse_bandit(
                    self._report(
                        directory,
                        "bandit-quality.json",
                        {
                            "results": [
                                {
                                    "test_id": "B101",
                                    "issue_severity": "LOW",
                                    "issue_text": "Assert used.",
                                    "filename": "app.py",
                                    "line_number": 1,
                                }
                            ]
                        },
                    )
                )[0],
                parse_semgrep(
                    self._report(
                        directory,
                        "semgrep-quality.json",
                        {
                            "results": [
                                {
                                    "check_id": "python.eval",
                                    "extra": {
                                        "severity": "ERROR",
                                        "message": "Eval used.",
                                    },
                                    "path": "app.py",
                                    "start": {"line": 1},
                                }
                            ]
                        },
                    )
                )[0],
                parse_pip_audit(
                    self._report(
                        directory,
                        "pip-quality.json",
                        {
                            "dependencies": [
                                {
                                    "name": "example",
                                    "version": "1.0.0",
                                    "vulns": [
                                        {
                                            "id": "CVE-2026-1000",
                                            "description": "Dependency issue.",
                                        }
                                    ],
                                }
                            ]
                        },
                    )
                )[0],
                parse_trivy(
                    self._report(
                        directory,
                        "trivy-quality.json",
                        {
                            "Results": [
                                {
                                    "Target": "image",
                                    "Vulnerabilities": [
                                        {
                                            "VulnerabilityID": "CVE-2026-1001",
                                            "Severity": "HIGH",
                                            "Description": "Dependency issue.",
                                            "PkgName": "example",
                                        }
                                    ],
                                }
                            ]
                        },
                    )
                )[0],
                parse_gitleaks(
                    self._report(
                        directory,
                        "gitleaks-quality.json",
                        [
                            {
                                "RuleID": "private-key",
                                "Description": "Private key.",
                                "File": "key.pem",
                                "StartLine": 1,
                                "Verified": True,
                            }
                        ],
                    )
                )[0],
            ]

            for finding in cases:
                with self.subTest(scanner=finding["scanner"]):
                    indicators = [
                        item
                        for item in finding["evidence"]
                        if item["kind"] == "severity_quality"
                    ]
                    self.assertEqual(len(indicators), 1)
                    self.assertRegex(
                        indicators[0]["summary"] or "",
                        r"quality=(high|medium|low);",
                    )
                    self.assertIn("rule=", indicators[0]["summary"] or "")

    def test_enriched_dependency_cvss_drives_severity_when_label_is_missing(
        self,
    ) -> None:
        with TemporaryDirectory() as directory_name:
            finding = parse_pip_audit(
                self._report(
                    Path(directory_name),
                    "pip-audit.json",
                    {
                        "dependencies": [
                            {
                                "name": "example",
                                "version": "1.0.0",
                                "vulns": [
                                    {
                                        "id": "CVE-2026-12345",
                                        "description": "Dependency vulnerability.",
                                        "cvss_score": 8.2,
                                        "cvss_version": 3,
                                        "severity_source": "nvd",
                                    }
                                ],
                            }
                        ]
                    },
                )
            )[0]

            self.assertIsNone(finding["original_severity"])
            self.assertEqual(finding["normalised_severity"], "high")
            self.assertIn("nvd CVSS v3", finding["severity_reason"])
            self.assertTrue(
                any(item["kind"] == "cvss" for item in finding["evidence"])
            )

    def test_secret_severity_considers_type_and_validation_status(self) -> None:
        with TemporaryDirectory() as directory_name:
            findings = parse_gitleaks(
                self._report(
                    Path(directory_name),
                    "gitleaks.json",
                    [
                        {
                            "RuleID": "private-key",
                            "Description": "Verified private key.",
                            "File": "verified.pem",
                            "StartLine": 1,
                            "Verified": True,
                        },
                        {
                            "RuleID": "private-key",
                            "Description": "Unverified private key.",
                            "File": "unverified.pem",
                            "StartLine": 1,
                            "Verified": False,
                        },
                        {
                            "RuleID": "generic-api-key",
                            "Description": "Unvalidated API key.",
                            "File": "settings.py",
                            "StartLine": 2,
                        },
                        {
                            "RuleID": "unclassified-secret",
                            "Description": "Unknown secret.",
                            "File": "notes.txt",
                            "StartLine": 3,
                        },
                        {
                            "RuleID": "private-key",
                            "Severity": "LOW",
                            "Description": "Scanner-labelled key.",
                            "File": "labelled.pem",
                            "StartLine": 4,
                            "Verified": True,
                        },
                    ],
                )
            )

            self.assertEqual(
                [finding["normalised_severity"] for finding in findings],
                ["high", "medium", "medium", "unknown", "low"],
            )
            self.assertEqual(findings[-1]["original_severity"], "LOW")
            self.assertIn("verified", findings[0]["severity_reason"])
            self.assertIn("unverified", findings[1]["severity_reason"])


if __name__ == "__main__":
    unittest.main()
