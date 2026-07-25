import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.adapters import AdapterConfig, AdapterContext, RepositoryContext
from trustgate.adapters.builtin.catalog import builtin_registry
from trustgate.schema import validate_instance


SUCCESS_REPORTS = {
    "zap": {
        "site": [{
            "@name": "https://example.test",
            "alerts": [{
                "pluginid": "10021",
                "riskdesc": "High (Medium)",
                "alert": "X-Content-Type-Options missing",
                "desc": "Header is absent.",
                "cweid": "693",
                "instances": [{"uri": "https://example.test/api", "method": "GET"}],
            }],
        }]
    },
    "osv-scanner": {
        "results": [{
            "source": {"path": "package-lock.json"},
            "packages": [{
                "package": {"name": "demo", "ecosystem": "npm"},
                "version": "1.0.0",
                "vulnerabilities": [{
                    "id": "GHSA-abcd-1234-5678",
                    "aliases": ["CVE-2026-12345"],
                    "summary": "Vulnerable package.",
                    "database_specific": {"severity": "HIGH"},
                }],
            }],
        }]
    },
    "syft": {"artifacts": [], "source": {"type": "directory"}},
    "grype": {
        "matches": [{
            "vulnerability": {
                "id": "CVE-2026-12345",
                "severity": "High",
                "description": "Vulnerable package.",
            },
            "artifact": {
                "name": "demo",
                "version": "1.0.0",
                "type": "npm",
                "purl": "pkg:npm/demo@1.0.0",
                "locations": [{"path": "package-lock.json"}],
            },
        }]
    },
    "checkov": {
        "results": {
            "failed_checks": [{
                "check_id": "CKV_AWS_1",
                "check_name": "Storage is public.",
                "file_path": "/infra/main.tf",
                "file_line_range": [1, 4],
                "severity": "HIGH",
            }]
        }
    },
    "hadolint": [{
        "code": "DL3000",
        "level": "warning",
        "message": "Use absolute WORKDIR.",
        "file": "Dockerfile",
        "line": 2,
    }],
    "gosec": {
        "Issues": [{
            "rule_id": "G101",
            "severity": "HIGH",
            "details": "Potential hardcoded credentials.",
            "file": "main.go",
            "line": "9",
            "cwe": {"id": "798"},
        }]
    },
    "brakeman": {
        "warnings": [{
            "warning_code": 0,
            "warning_type": "SQL Injection",
            "confidence": "High",
            "message": "Possible SQL injection.",
            "file": "app/models/user.rb",
            "line": 12,
            "cwe_id": ["89"],
            "fingerprint": "abc123",
        }]
    },
    "eslint-security": [{
        "filePath": "src/app.ts",
        "messages": [{
            "ruleId": "security/detect-eval-with-expression",
            "severity": 2,
            "message": "eval with expression",
            "line": 8,
            "endLine": 8,
        }],
    }],
    "codeql-sarif": {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "CodeQL",
                "rules": [{
                    "id": "js/sql-injection",
                    "name": "SQL injection",
                    "properties": {
                        "security-severity": "HIGH",
                        "tags": ["external/cwe/cwe-089"],
                    },
                }],
            }},
            "results": [{
                "ruleId": "js/sql-injection",
                "level": "error",
                "message": {"text": "Untrusted input reaches SQL."},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/db.ts"},
                    "region": {"startLine": 5, "endLine": 5},
                }}],
            }],
        }],
    },
}
EXPECTED_SEVERITIES = {
    "zap": "high",
    "osv-scanner": "high",
    "grype": "high",
    "checkov": "high",
    "hadolint": "medium",
    "gosec": "high",
    "brakeman": "unknown",
    "eslint-security": "high",
    "codeql-sarif": "high",
}


class BuiltinParserTests(unittest.TestCase):
    def _parse(self, name: str, document: object):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        extension = "xml" if name == "spotbugs" else "jsonl" if name == "trufflehog" else "json"
        report = root / f"{name}.{extension}"
        if name == "spotbugs":
            report.write_text(str(document), encoding="utf-8")
        elif name == "trufflehog":
            report.write_text(json.dumps(document) + "\n", encoding="utf-8")
        else:
            report.write_text(json.dumps(document), encoding="utf-8")
        adapter = builtin_registry().get(name)
        context = AdapterContext.create(
            repository=RepositoryContext.from_path(root),
            reports_dir=root,
            config=AdapterConfig(),
            metadata=adapter.metadata(),
        )
        return list(adapter.parse(report, context))

    def test_new_json_adapters_emit_canonical_findings(self) -> None:
        for name, document in SUCCESS_REPORTS.items():
            with self.subTest(adapter=name):
                findings = self._parse(name, document)
                if name == "syft":
                    self.assertEqual(findings, [])
                else:
                    self.assertEqual(len(findings), 1)
                    validate_instance("finding", findings[0])
                    self.assertEqual(findings[0]["scanner"], name)
                    self.assertEqual(
                        findings[0]["normalised_severity"],
                        EXPECTED_SEVERITIES[name],
                    )

    def test_spotbugs_xml_emits_canonical_finding(self) -> None:
        findings = self._parse(
            "spotbugs",
            """<BugCollection><BugInstance type="SQL_INJECTION" priority="1"
            category="SECURITY" cweid="89"><LongMessage>SQL injection.</LongMessage>
            <SourceLine sourcepath="src/App.java" start="8" end="8"/>
            </BugInstance></BugCollection>""",
        )

        self.assertEqual(len(findings), 1)
        validate_instance("finding", findings[0])
        self.assertEqual(findings[0]["cwe"], ["CWE-89"])
        self.assertEqual(findings[0]["normalised_severity"], "high")

    def test_trufflehog_json_lines_emits_canonical_finding(self) -> None:
        findings = self._parse(
            "trufflehog",
            {
                "DetectorName": "AWS",
                "Verified": True,
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": "config.env", "line": 3}}
                },
            },
        )

        self.assertEqual(len(findings), 1)
        validate_instance("finding", findings[0])
        self.assertEqual(findings[0]["normalised_severity"], "high")

    def test_trufflehog_redaction_never_publishes_raw_secret_as_identifier(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            secret = "raw-super-secret-value"
            report = root / "trufflehog.jsonl"
            report.write_text(
                json.dumps(
                    {
                        "DetectorName": "AWS",
                        "Verified": True,
                        "Raw": secret,
                        "SourceMetadata": {
                            "Data": {
                                "Filesystem": {
                                    "file": "config.env",
                                    "line": 3,
                                }
                            }
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            adapter = builtin_registry().get("trufflehog")
            context = AdapterContext.create(
                repository=RepositoryContext.from_path(root),
                reports_dir=root,
                config=AdapterConfig(
                    options={"redact_sensitive_content": True}
                ),
                metadata=adapter.metadata(),
            )

            finding = list(adapter.parse(report, context))[0]

            self.assertNotEqual(
                finding["raw_report_reference"]["scanner_finding_id"],
                secret,
            )
            redacted_reference = next(
                evidence["reference"]
                for evidence in finding["evidence"]
                if evidence["kind"] == "redacted_report"
            )
            self.assertNotIn(
                secret,
                Path(redacted_reference).read_text(encoding="utf-8"),
            )

    def test_every_new_parser_rejects_a_malformed_report(self) -> None:
        for name in (
            "zap", "osv-scanner", "syft", "grype", "checkov", "hadolint",
            "gosec", "brakeman", "spotbugs", "eslint-security",
            "trufflehog", "codeql-sarif",
        ):
            with self.subTest(adapter=name), self.assertRaises(
                (ValueError, TypeError, json.JSONDecodeError)
            ):
                self._parse(name, "{not valid")


if __name__ == "__main__":
    unittest.main()
