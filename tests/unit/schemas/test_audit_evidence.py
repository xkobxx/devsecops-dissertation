"""Audit-evidence guarantees shared by every scanner adapter."""

from __future__ import annotations

import hashlib
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


class AuditEvidenceTests(unittest.TestCase):
    def _report(self, directory: Path, name: str, document: object) -> Path:
        path = directory / name
        path.write_text(
            json.dumps(document, separators=(",", ":")),
            encoding="utf-8",
        )
        return path

    def test_every_adapter_uses_a_content_addressed_raw_report_copy(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            cases = [
                (
                    parse_bandit,
                    self._report(
                        directory,
                        "bandit.json",
                        {
                            "results": [
                                {
                                    "test_id": "B608",
                                    "issue_severity": "MEDIUM",
                                    "issue_text": "Possible SQL injection.",
                                    "filename": "app.py",
                                    "line_number": 11,
                                }
                            ]
                        },
                    ),
                ),
                (
                    parse_semgrep,
                    self._report(
                        directory,
                        "semgrep.json",
                        {
                            "results": [
                                {
                                    "check_id": "python.lang.security.audit.eval",
                                    "extra": {
                                        "severity": "ERROR",
                                        "message": "User input reaches eval.",
                                    },
                                    "path": "service.py",
                                    "start": {"line": 22},
                                }
                            ]
                        },
                    ),
                ),
                (
                    parse_pip_audit,
                    self._report(
                        directory,
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
                    ),
                ),
                (
                    parse_trivy,
                    self._report(
                        directory,
                        "trivy.json",
                        {
                            "Results": [
                                {
                                    "Target": "requirements.lock",
                                    "Vulnerabilities": [
                                        {
                                            "VulnerabilityID": "CVE-2026-54321",
                                            "Severity": "CRITICAL",
                                            "Description": "Package vulnerability.",
                                            "PkgName": "example",
                                        }
                                    ],
                                }
                            ]
                        },
                    ),
                ),
                (
                    parse_gitleaks,
                    self._report(
                        directory,
                        "gitleaks.json",
                        [
                            {
                                "RuleID": "generic-api-key",
                                "Description": "Generic API key.",
                                "File": "settings.py",
                                "StartLine": 8,
                            }
                        ],
                    ),
                ),
            ]

            for parser, source_path in cases:
                with self.subTest(parser=parser.__name__):
                    source_bytes = source_path.read_bytes()
                    digest = hashlib.sha256(source_bytes).hexdigest()

                    finding = parser(source_path)[0]

                    validate_instance("finding", finding)
                    reference = finding["raw_report_reference"]
                    audit_path = Path(reference["path"])
                    self.assertEqual(reference["sha256"], digest)
                    self.assertEqual(audit_path.parent, directory / "raw")
                    self.assertIn(digest, audit_path.name)
                    self.assertEqual(audit_path.read_bytes(), source_bytes)
                    self.assertNotEqual(audit_path, source_path)

    def test_a_new_source_report_does_not_overwrite_prior_audit_evidence(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            source_path = self._report(
                directory,
                "bandit.json",
                {
                    "results": [
                        {
                            "test_id": "B101",
                            "issue_severity": "LOW",
                            "issue_text": "First report.",
                            "filename": "app.py",
                            "line_number": 1,
                        }
                    ]
                },
            )
            first_source_bytes = source_path.read_bytes()
            first_reference = parse_bandit(source_path)[0]["raw_report_reference"]
            first_audit_path = Path(first_reference["path"])

            self._report(
                directory,
                "bandit.json",
                {
                    "results": [
                        {
                            "test_id": "B602",
                            "issue_severity": "HIGH",
                            "issue_text": "Second report.",
                            "filename": "app.py",
                            "line_number": 2,
                        }
                    ]
                },
            )
            second_reference = parse_bandit(source_path)[0]["raw_report_reference"]

            self.assertNotEqual(first_reference["sha256"], second_reference["sha256"])
            self.assertNotEqual(first_reference["path"], second_reference["path"])
            self.assertEqual(first_audit_path.read_bytes(), first_source_bytes)
            self.assertTrue(Path(second_reference["path"]).is_file())

    def test_severity_transformation_is_recorded_separately_from_raw_value(self) -> None:
        with TemporaryDirectory() as directory_name:
            report_path = self._report(
                Path(directory_name),
                "semgrep.json",
                {
                    "results": [
                        {
                            "check_id": "python.lang.security.audit.eval",
                            "extra": {
                                "severity": "ERROR",
                                "message": "User input reaches eval.",
                            },
                            "path": "service.py",
                            "start": {"line": 22},
                        }
                    ]
                },
            )

            finding = parse_semgrep(report_path)[0]
            records = [
                item
                for item in finding["evidence"]
                if item["kind"] == "normalisation"
            ]

            self.assertEqual(finding["original_severity"], "ERROR")
            self.assertEqual(finding["normalised_severity"], "high")
            self.assertTrue(
                any(
                    item["reference"] == "$.results[0].extra.severity"
                    and item["excerpt"] == "ERROR"
                    and "normalised_severity" in (item["summary"] or "")
                    and "high" in (item["summary"] or "")
                    for item in records
                )
            )

    def test_an_empty_report_is_still_preserved_for_audit(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            report_path = self._report(directory, "bandit.json", {"results": []})
            source_bytes = report_path.read_bytes()

            self.assertEqual(parse_bandit(report_path), [])

            audit_reports = list((directory / "raw").glob("bandit-*.json"))
            self.assertEqual(len(audit_reports), 1)
            self.assertEqual(audit_reports[0].read_bytes(), source_bytes)

    def test_optional_redaction_creates_a_safe_view_without_altering_raw_audit(
        self,
    ) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            report_path = self._report(
                directory,
                "gitleaks.json",
                [
                    {
                        "RuleID": "generic-api-key",
                        "Description": "Generic API key.",
                        "File": "settings.py",
                        "StartLine": 8,
                        "Secret": "super-secret-value",
                        "Match": "api_key=super-secret-value",
                        "Fingerprint": "settings.py:generic-api-key:8",
                    }
                ],
            )

            finding = parse_gitleaks(
                report_path,
                redact_sensitive_content=True,
            )[0]

            raw_document = json.loads(
                Path(finding["raw_report_reference"]["path"]).read_text(
                    encoding="utf-8"
                )
            )
            redaction_evidence = [
                item
                for item in finding["evidence"]
                if item["kind"] == "redacted_report"
            ]
            self.assertEqual(len(redaction_evidence), 1)
            redacted_path = Path(redaction_evidence[0]["reference"])
            redacted_document = json.loads(redacted_path.read_text(encoding="utf-8"))

            self.assertEqual(raw_document[0]["Secret"], "super-secret-value")
            self.assertEqual(
                raw_document[0]["Match"],
                "api_key=super-secret-value",
            )
            self.assertEqual(redacted_document[0]["Secret"], "[REDACTED]")
            self.assertEqual(redacted_document[0]["Match"], "[REDACTED]")
            self.assertEqual(
                redacted_document[0]["RuleID"],
                "generic-api-key",
            )
            self.assertEqual(redacted_path.parent, directory / "redacted")
            self.assertNotIn(
                "super-secret-value",
                redacted_path.read_text(encoding="utf-8"),
            )

    def test_redaction_is_disabled_by_default(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            report_path = self._report(
                directory,
                "gitleaks.json",
                [
                    {
                        "RuleID": "generic-api-key",
                        "Description": "Generic API key.",
                        "File": "settings.py",
                        "StartLine": 8,
                        "Secret": "super-secret-value",
                    }
                ],
            )

            finding = parse_gitleaks(report_path)[0]

            self.assertFalse((directory / "redacted").exists())
            self.assertFalse(
                any(
                    item["kind"] == "redacted_report"
                    for item in finding["evidence"]
                )
            )

    def test_every_scanner_derived_field_has_source_provenance(self) -> None:
        with TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            cases = [
                (
                    parse_bandit,
                    self._report(
                        directory,
                        "bandit-trace.json",
                        {
                            "results": [
                                {
                                    "test_id": "B608",
                                    "issue_severity": "MEDIUM",
                                    "issue_text": "Possible SQL injection.",
                                    "filename": "app.py",
                                    "line_number": 11,
                                    "issue_cwe": {"id": 89},
                                }
                            ]
                        },
                    ),
                    {
                        "rule_id",
                        "description",
                        "original_severity",
                        "normalised_severity",
                        "file",
                        "start_line",
                        "end_line",
                        "cwe",
                    },
                ),
                (
                    parse_semgrep,
                    self._report(
                        directory,
                        "semgrep-trace.json",
                        {
                            "results": [
                                {
                                    "check_id": "python.lang.security.audit.eval",
                                    "extra": {
                                        "severity": "ERROR",
                                        "message": "User input reaches eval.",
                                        "metadata": {"cwe": ["CWE-95"]},
                                    },
                                    "path": "service.py",
                                    "start": {"line": 22},
                                    "end": {"line": 23},
                                }
                            ]
                        },
                    ),
                    {
                        "rule_id",
                        "description",
                        "original_severity",
                        "normalised_severity",
                        "file",
                        "start_line",
                        "end_line",
                        "cwe",
                    },
                ),
                (
                    parse_pip_audit,
                    self._report(
                        directory,
                        "pip-audit-trace.json",
                        {
                            "dependencies": [
                                {
                                    "name": "example",
                                    "version": "1.0.0",
                                    "vulns": [
                                        {
                                            "id": "CVE-2026-12345",
                                            "aliases": [
                                                "GHSA-abcd-1234-5678",
                                                "PYSEC-2026-123",
                                            ],
                                            "description": "Dependency vulnerability.",
                                        }
                                    ],
                                }
                            ]
                        },
                    ),
                    {
                        "rule_id",
                        "description",
                        "original_severity",
                        "normalised_severity",
                        "file",
                        "cve",
                        "ghsa",
                        "osv",
                        "dependency",
                    },
                ),
                (
                    parse_trivy,
                    self._report(
                        directory,
                        "trivy-trace.json",
                        {
                            "Results": [
                                {
                                    "Target": "requirements.lock",
                                    "Type": "pip",
                                    "Vulnerabilities": [
                                        {
                                            "VulnerabilityID": "CVE-2026-54321",
                                            "Severity": "CRITICAL",
                                            "Title": "Critical package vulnerability.",
                                            "Description": "Package vulnerability.",
                                            "PkgName": "example",
                                            "InstalledVersion": "1.0.0",
                                        }
                                    ],
                                }
                            ]
                        },
                    ),
                    {
                        "rule_id",
                        "title",
                        "description",
                        "original_severity",
                        "normalised_severity",
                        "file",
                        "cve",
                        "ghsa",
                        "osv",
                        "dependency",
                    },
                ),
                (
                    parse_gitleaks,
                    self._report(
                        directory,
                        "gitleaks-trace.json",
                        [
                            {
                                "RuleID": "generic-api-key",
                                "Description": "Generic API key.",
                                "File": "settings.py",
                                "StartLine": 8,
                                "Fingerprint": "settings.py:generic-api-key:8",
                            }
                        ],
                    ),
                    {
                        "rule_id",
                        "description",
                        "original_severity",
                        "normalised_severity",
                        "file",
                        "start_line",
                        "end_line",
                    },
                ),
            ]

            for parser, report_path, expected_fields in cases:
                with self.subTest(parser=parser.__name__):
                    finding = parser(report_path)[0]
                    records = [
                        item
                        for item in finding["evidence"]
                        if item["kind"] == "normalisation"
                    ]
                    traced_fields = {
                        (item["summary"] or "").split(":", 1)[0]
                        for item in records
                    }
                    self.assertTrue(expected_fields <= traced_fields)
                    self.assertTrue(
                        all(
                            item["reference"]
                            and item["reference"].startswith("$")
                            for item in records
                        )
                    )

    def test_severity_explanation_matches_original_and_normalised_values(self) -> None:
        with TemporaryDirectory() as directory_name:
            report_path = self._report(
                Path(directory_name),
                "trivy.json",
                {
                    "Results": [
                        {
                            "Target": "image",
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-2026-54321",
                                    "Severity": "CRITICAL",
                                    "Description": "Package vulnerability.",
                                    "PkgName": "example",
                                }
                            ],
                        }
                    ]
                },
            )

            finding = parse_trivy(report_path)[0]

            self.assertEqual(finding["original_severity"], "CRITICAL")
            self.assertEqual(finding["normalised_severity"], "critical")
            self.assertIn("CRITICAL", finding["severity_reason"])
            self.assertIn("critical", finding["severity_reason"])
            severity_records = [
                item
                for item in finding["evidence"]
                if item["kind"] == "normalisation"
                and (item["summary"] or "").startswith("normalised_severity:")
            ]
            self.assertEqual(len(severity_records), 1)
            self.assertEqual(severity_records[0]["excerpt"], "CRITICAL")
            self.assertIn("critical", severity_records[0]["summary"] or "")


if __name__ == "__main__":
    unittest.main()
