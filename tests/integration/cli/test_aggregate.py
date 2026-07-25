import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from trustgate.schema import validate_instance


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class TrustGateAggregateTests(unittest.TestCase):
    def test_cli_redaction_publishes_a_safe_scanner_report_view(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            reports = workspace / "reports"
            reports.mkdir()
            secret = "super-secret-value"
            (reports / "gitleaks_report.json").write_text(
                json.dumps(
                    [
                        {
                            "RuleID": "generic-api-key",
                            "Description": "Generic API key.",
                            "File": "settings.py",
                            "StartLine": 8,
                            "Secret": secret,
                            "Match": f"api_key={secret}",
                        }
                    ]
                )
            )
            output = workspace / "findings.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "aggregate",
                    "--reports-dir",
                    str(reports),
                    "--output",
                    str(output),
                    "--fail-on",
                    "none",
                    "--required-scanner",
                    "gitleaks",
                    "--redact-sensitive-content",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            scan_run = json.loads(output.read_text(encoding="utf-8"))
            validate_instance("scan-run", scan_run)
            scanner_report = Path(
                next(
                    scanner
                    for scanner in scan_run["scanners"]
                    if scanner["scanner"] == "gitleaks"
                )["report_path"]
            )
            self.assertEqual(scanner_report.parent, reports / "redacted")
            self.assertNotIn(secret, scanner_report.read_text(encoding="utf-8"))
            raw_report = Path(
                scan_run["findings"][0]["raw_report_reference"]["path"]
            )
            self.assertEqual(raw_report.parent, reports / "raw")
            self.assertIn(secret, raw_report.read_text(encoding="utf-8"))

    def test_cli_aggregates_reports_outside_the_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            reports = workspace / "scanner-output"
            reports.mkdir()
            (reports / "bandit_report.json").write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "test_id": "B602",
                                "issue_severity": "HIGH",
                                "issue_text": "subprocess call with shell=True",
                                "filename": "app.py",
                                "line_number": 12,
                            }
                        ]
                    }
                )
            )
            output = workspace / "trustgate-output" / "findings.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "aggregate",
                    "--reports-dir",
                    str(reports),
                    "--output",
                    str(output),
                    "--fail-on",
                    "none",
                    "--required-scanner",
                    "bandit",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            data = json.loads(output.read_text())
            validate_instance("scan-run", data)
            self.assertEqual(data["summary"]["total_findings"], 1)
            self.assertEqual(data["findings"][0]["scanner"], "Bandit")
            self.assertEqual(data["scanners"][0]["state"], "FINDINGS")
            self.assertTrue(
                all(
                    result["state"] == "SKIPPED"
                    for result in data["scanners"][1:]
                )
            )
            policy = json.loads(
                (output.parent / "policy-result.json").read_text()
            )
            validate_instance("policy-result", policy)
            self.assertEqual(policy["run_id"], data["run_id"])
            self.assertIn("Aggregated 1 total findings.", completed.stdout)

    def test_legacy_action_wrapper_works_outside_the_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            reports = workspace / "reports"
            reports.mkdir()
            (reports / "semgrep_report.json").write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "python.lang.security.audit.eval",
                                "extra": {
                                    "severity": "ERROR",
                                    "message": "User input reaches eval",
                                },
                                "path": "service.py",
                                "start": {"line": 22},
                            }
                        ]
                    }
                )
            )
            output = workspace / "findings.json"

            completed = subprocess.run(
                [
                    sys.executable,
                    str(REPOSITORY_ROOT / "scripts" / "aggregate_results.py"),
                    "--reports-dir",
                    str(reports),
                    "--output",
                    str(output),
                    "--fail-on",
                    "none",
                    "--required-scanner",
                    "semgrep",
                ],
                cwd=workspace,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            data = json.loads(output.read_text())
            validate_instance("scan-run", data)
            self.assertEqual(data["summary"]["total_findings"], 1)
            self.assertEqual(data["findings"][0]["scanner"], "Semgrep")

    def test_nonexistent_output_directory_keeps_legacy_path_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            reports = workspace / "reports"
            reports.mkdir()
            output_directory = workspace / "new-output-directory"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "aggregate",
                    "--reports-dir",
                    str(reports),
                    "--output",
                    str(output_directory) + os.sep,
                    "--fail-on",
                    "none",
                    "--scanner-failure-policy",
                    "ignore",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue((output_directory / "findings.json").is_file())

    def test_missing_required_report_fails_scanner_health_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            reports = workspace / "reports"
            reports.mkdir()
            output = workspace / "findings.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "aggregate",
                    "--reports-dir",
                    str(reports),
                    "--output",
                    str(output),
                    "--required-scanner",
                    "bandit",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            data = json.loads(output.read_text())
            self.assertEqual(data["scanners"][0]["state"], "FAILED_SCANNER")
            self.assertFalse(data["scanners"][0]["report_produced"])
            self.assertIn("required scanner failure", completed.stdout.lower())

    def test_malformed_required_report_fails_scanner_health_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            reports = workspace / "reports"
            reports.mkdir()
            malformed_report = b"{not-json"
            (reports / "bandit_report.json").write_bytes(malformed_report)
            output = workspace / "findings.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "aggregate",
                    "--reports-dir",
                    str(reports),
                    "--output",
                    str(output),
                    "--required-scanner",
                    "bandit",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            data = json.loads(output.read_text())
            raw_reports = list((reports / "raw").glob("bandit-*.json"))
            self.assertEqual(len(raw_reports), 1)
            self.assertEqual(raw_reports[0].read_bytes(), malformed_report)
            result = data["scanners"][0]
            self.assertEqual(result["state"], "FAILED_SCANNER")
            self.assertEqual(result["parser_status"], "FAILED")
            self.assertTrue(result["report_produced"])

    def test_authoritative_execution_metadata_is_preserved_after_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            reports = workspace / "reports"
            reports.mkdir()
            (reports / "bandit_report.json").write_text('{"results":[]}')
            stdout_path = reports / "logs" / "bandit.stdout.log"
            stderr_path = reports / "logs" / "bandit.stderr.log"
            (reports / "bandit_execution.json").write_text(
                json.dumps(
                    {
                        "scanner": "bandit",
                        "state": "CLEAN",
                        "started_at": "2026-07-24T10:00:00+00:00",
                        "ended_at": "2026-07-24T10:00:02+00:00",
                        "duration_seconds": 2.0,
                        "exit_code": 0,
                        "timed_out": False,
                        "report_path": str(reports / "bandit_report.json"),
                        "report_produced": True,
                        "parser_status": "NOT_RUN",
                        "version": "1.9.4",
                        "stdout_path": str(stdout_path),
                        "stderr_path": str(stderr_path),
                        "finding_count": 0,
                        "error": None,
                        "required": True,
                    }
                )
            )
            output = workspace / "findings.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "aggregate",
                    "--reports-dir",
                    str(reports),
                    "--output",
                    str(output),
                    "--required-scanner",
                    "bandit",
                    "--require-execution-metadata",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(output.read_text())["scanners"][0]
            self.assertEqual(result["started_at"], "2026-07-24T10:00:00+00:00")
            self.assertEqual(result["duration_seconds"], 2.0)
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["scanner_version"], "1.9.4")
            self.assertEqual(result["stdout_path"], str(stdout_path))
            self.assertEqual(result["parser_status"], "SUCCESS")

    def test_required_execution_metadata_cannot_be_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            reports = workspace / "reports"
            reports.mkdir()
            (reports / "bandit_report.json").write_text('{"results":[]}')
            output = workspace / "findings.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "aggregate",
                    "--reports-dir",
                    str(reports),
                    "--output",
                    str(output),
                    "--required-scanner",
                    "bandit",
                    "--require-execution-metadata",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            result = json.loads(output.read_text())["scanners"][0]
            self.assertEqual(result["state"], "FAILED_SCANNER")
            self.assertIn("metadata", result["error"].lower())

    def test_crashed_execution_metadata_cannot_become_clean_after_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            reports = workspace / "reports"
            reports.mkdir()
            (reports / "bandit_report.json").write_text('{"results":[]}')
            (reports / "bandit_execution.json").write_text(
                json.dumps(
                    {
                        "scanner": "bandit",
                        "state": "FAILED_SCANNER",
                        "started_at": "2026-07-24T10:00:00+00:00",
                        "ended_at": "2026-07-24T10:00:01+00:00",
                        "exit_code": 2,
                        "timed_out": False,
                        "report_path": str(reports / "bandit_report.json"),
                        "report_produced": True,
                        "parser_status": "NOT_RUN",
                        "version": "1.9.4",
                        "stdout_path": str(reports / "logs/bandit.stdout.log"),
                        "stderr_path": str(reports / "logs/bandit.stderr.log"),
                        "finding_count": 0,
                        "error": "Unexpected scanner exit code 2.",
                        "required": True,
                    }
                )
            )
            output = workspace / "findings.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "aggregate",
                    "--reports-dir",
                    str(reports),
                    "--output",
                    str(output),
                    "--required-scanner",
                    "bandit",
                    "--require-execution-metadata",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            result = json.loads(output.read_text())["scanners"][0]
            self.assertEqual(result["state"], "FAILED_SCANNER")
            self.assertEqual(result["exit_code"], 2)
            self.assertEqual(result["parser_status"], "SUCCESS")

    def test_invalid_adapter_finding_is_reported_as_a_parser_error(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            reports = workspace / "reports"
            reports.mkdir()
            (reports / "bandit_report.json").write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "issue_severity": "HIGH",
                                "issue_text": "Missing Bandit test ID.",
                                "filename": "app.py",
                                "line_number": 7,
                            }
                        ]
                    }
                )
            )
            output = workspace / "findings.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "aggregate",
                    "--reports-dir",
                    str(reports),
                    "--output",
                    str(output),
                    "--required-scanner",
                    "bandit",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            scan_run = json.loads(output.read_text())
            validate_instance("scan-run", scan_run)
            result = scan_run["scanners"][0]
            self.assertEqual(result["parser_status"], "FAILED")
            self.assertEqual(result["state"], "FAILED_SCANNER")
            self.assertIn("rule_id", result["error"])
            self.assertEqual(scan_run["findings"], [])


if __name__ == "__main__":
    unittest.main()
