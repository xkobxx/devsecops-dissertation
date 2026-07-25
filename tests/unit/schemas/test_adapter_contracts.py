"""Every scanner adapter must emit canonical, validated findings."""

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
from trustgate.schema import SchemaMigrationError, validate_instance


class AdapterSchemaContractTests(unittest.TestCase):
    def _report(self, name: str, document: object) -> Path:
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        path = Path(self.directory.name) / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_bandit_findings_validate(self) -> None:
        findings = parse_bandit(
            self._report(
                "bandit.json",
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
            )
        )

        validate_instance("finding", findings[0])
        self.assertEqual(findings[0]["cwe"], ["CWE-89"])
        self.assertEqual(findings[0]["category"], "sast")
        self.assertEqual(findings[0]["original_severity"], "MEDIUM")
        self.assertEqual(findings[0]["description"], "Possible SQL injection.")
        self.assertEqual(findings[0]["rule_id"], "B608")

    def test_semgrep_findings_validate(self) -> None:
        findings = parse_semgrep(
            self._report(
                "semgrep.json",
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
                            "end": {"line": 22},
                        }
                    ]
                },
            )
        )

        validate_instance("finding", findings[0])
        self.assertEqual(findings[0]["original_severity"], "ERROR")
        self.assertEqual(findings[0]["normalised_severity"], "high")
        self.assertEqual(findings[0]["description"], "User input reaches eval.")
        self.assertEqual(
            findings[0]["rule_id"],
            "python.lang.security.audit.eval",
        )
        self.assertEqual(findings[0]["end_line"], 22)

    def test_pip_audit_findings_validate(self) -> None:
        findings = parse_pip_audit(
            self._report(
                "pip-audit.json",
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
                                    "fix_versions": ["1.0.1"],
                                }
                            ],
                        }
                    ]
                },
            )
        )

        validate_instance("finding", findings[0])
        self.assertIsNone(findings[0]["original_severity"])
        self.assertEqual(
            findings[0]["description"],
            "Dependency vulnerability.",
        )
        self.assertEqual(findings[0]["rule_id"], "CVE-2026-12345")
        self.assertEqual(findings[0]["cve"], ["CVE-2026-12345"])
        self.assertEqual(findings[0]["ghsa"], ["GHSA-abcd-1234-5678"])
        self.assertEqual(findings[0]["osv"], ["PYSEC-2026-123"])
        self.assertEqual(findings[0]["dependency"]["name"], "example")
        self.assertEqual(findings[0]["category"], "sca")

    def test_trivy_findings_validate(self) -> None:
        findings = parse_trivy(
            self._report(
                "trivy.json",
                {
                    "Results": [
                        {
                            "Target": "requirements.lock",
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-2026-54321",
                                    "Severity": "CRITICAL",
                                    "Title": "Critical package vulnerability.",
                                    "Description": "Original advisory description.",
                                    "PkgName": "example",
                                    "InstalledVersion": "1.0.0",
                                }
                            ],
                            "Misconfigurations": [
                                {
                                    "ID": "AVD-AWS-0001",
                                    "Severity": "HIGH",
                                    "Title": "Public storage.",
                                    "Description": "Original misconfiguration description.",
                                }
                            ],
                        }
                    ]
                },
            )
        )

        self.assertEqual(len(findings), 2)
        for finding in findings:
            validate_instance("finding", finding)
        self.assertEqual(findings[0]["category"], "sca")
        self.assertEqual(findings[0]["original_severity"], "CRITICAL")
        self.assertEqual(findings[0]["title"], "Critical package vulnerability.")
        self.assertEqual(
            findings[0]["description"],
            "Original advisory description.",
        )
        self.assertEqual(findings[0]["rule_id"], "CVE-2026-54321")
        self.assertEqual(findings[0]["cve"], ["CVE-2026-54321"])
        self.assertEqual(findings[1]["category"], "iac")
        self.assertEqual(findings[1]["original_severity"], "HIGH")
        self.assertEqual(
            findings[1]["description"],
            "Original misconfiguration description.",
        )

    def test_gitleaks_findings_validate(self) -> None:
        findings = parse_gitleaks(
            self._report(
                "gitleaks.json",
                [
                    {
                        "RuleID": "generic-api-key",
                        "Description": "Generic API key.",
                        "File": "settings.py",
                        "StartLine": 8,
                        "Fingerprint": "settings.py:generic-api-key:8",
                    }
                ],
            )
        )

        validate_instance("finding", findings[0])
        self.assertEqual(findings[0]["category"], "secrets")
        self.assertIsNone(findings[0]["original_severity"])
        self.assertEqual(findings[0]["description"], "Generic API key.")
        self.assertEqual(findings[0]["rule_id"], "generic-api-key")
        self.assertEqual(
            findings[0]["raw_report_reference"]["scanner_finding_id"],
            "settings.py:generic-api-key:8",
        )

    def test_invalid_adapter_finding_is_a_parser_error(self) -> None:
        path = self._report(
            "bandit.json",
            {
                "results": [
                    {
                        "issue_severity": "HIGH",
                        "issue_text": "Missing Bandit test ID.",
                        "filename": "app.py",
                        "line_number": 2,
                    }
                ]
            },
        )

        with self.assertRaisesRegex(SchemaMigrationError, "rule_id"):
            parse_bandit(path)


if __name__ == "__main__":
    unittest.main()
