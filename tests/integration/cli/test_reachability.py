from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from trustgate.scanners.models import ScannerState
from trustgate.schema import build_scan_run, validate_instance

from tests.unit.schemas.test_documents import scanner_result
from tests.unit.schemas.test_schema_contracts import valid_finding


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class ReachabilityCliTests(unittest.TestCase):
    def test_cli_analyzes_dependency_and_dynamic_evidence(self) -> None:
        finding = valid_finding()
        finding.update(
            {
                "category": "dependency",
                "file": "requirements.txt",
                "dependency": {
                    "name": "demo",
                    "version": "1.0.0",
                    "ecosystem": "PyPI",
                    "purl": "pkg:pypi/demo@1.0.0",
                    "direct": None,
                },
                "dependency_scope": "unknown",
                "reachability": "unknown",
            }
        )
        scan_run = build_scan_run(
            target=".",
            findings=[finding],
            scanner_results=[scanner_result(ScannerState.FINDINGS)],
        )
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "requirements.txt").write_text("demo==1.0.0\n")
            (workspace / "app.py").write_text("import demo\ndemo.danger()\n")
            input_path = workspace / "scan.json"
            output_path = workspace / "analyzed.json"
            symbols_path = workspace / "symbols.json"
            deployment_path = workspace / "deployment.json"
            input_path.write_text(json.dumps(scan_run))
            symbols_path.write_text(json.dumps({"demo": ["danger"]}))
            deployment_path.write_text(json.dumps({"packages": ["demo"]}))
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "reachability",
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                    "--repository-root",
                    str(workspace),
                    "--vulnerable-symbols",
                    str(symbols_path),
                    "--deployment-inventory",
                    str(deployment_path),
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            analyzed = json.loads(output_path.read_text())
            validate_instance("scan-run", analyzed)
            self.assertEqual(
                analyzed["findings"][0]["dependency_reachability"]["status"],
                "CONFIRMED_REACHABLE",
            )
            self.assertIn("Reachability analysis completed", completed.stdout)

    def test_aggregate_can_publish_reachability_before_policy_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            reports = workspace / "reports"
            reports.mkdir()
            (workspace / "requirements.txt").write_text("demo==1.0.0\n")
            (workspace / "app.py").write_text("import demo\ndemo.danger()\n")
            (reports / "pip_audit_report.json").write_text(
                json.dumps(
                    {
                        "dependencies": [
                            {
                                "name": "demo",
                                "version": "1.0.0",
                                "vulns": [
                                    {
                                        "id": "CVE-2026-1234",
                                        "severity": "HIGH",
                                        "description": "Vulnerable package.",
                                        "aliases": [],
                                    }
                                ],
                            }
                        ]
                    }
                )
            )
            symbols = workspace / "symbols.json"
            deployment = workspace / "deployment.json"
            symbols.write_text(json.dumps({"demo": ["danger"]}))
            deployment.write_text(json.dumps({"packages": ["demo"]}))
            output = reports / "findings.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "aggregate",
                    "--target",
                    str(workspace),
                    "--reports-dir",
                    str(reports),
                    "--output",
                    str(output),
                    "--required-scanner",
                    "pip-audit",
                    "--fail-on",
                    "none",
                    "--analyse-reachability",
                    "--vulnerable-symbols",
                    str(symbols),
                    "--deployment-inventory",
                    str(deployment),
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            scan_run = json.loads(output.read_text())
            self.assertEqual(
                scan_run["findings"][0]["dependency_reachability"]["status"],
                "CONFIRMED_REACHABLE",
            )
            self.assertEqual(
                scan_run["summary"]["reachability_analysis"]["confirmed_reachable"],
                1,
            )

    def test_report_shows_explainable_static_and_runtime_evidence(self) -> None:
        finding = valid_finding()
        finding.update(
            {
                "file": "app.py",
                "start_line": 5,
                "end_line": 5,
                "source": "request.args['q']",
                "sink": "cursor.execute",
            }
        )
        scan_run = build_scan_run(
            target=".",
            findings=[finding],
            scanner_results=[scanner_result(ScannerState.FINDINGS)],
        )
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "app.py").write_text(
                "from flask import request\n"
                "@app.get('/search')\n"
                "def search():\n"
                "    value = request.args['q']\n"
                "    cursor.execute(value)\n"
            )
            from trustgate.reachability.service import analyze_scan_run

            analyzed = analyze_scan_run(
                scan_run,
                repository_root=workspace,
                dynamic_observations=[
                    {
                        "observation_id": "dast-1",
                        "endpoint": "/search",
                        "parameter": "q",
                        "sink": "cursor.execute",
                        "outcome": "confirmed",
                        "authentication_state": "not-required",
                        "evidence": ["Database error reproduced."],
                    }
                ],
            )
            input_path = workspace / "scan.json"
            output_path = workspace / "report.html"
            input_path.write_text(json.dumps(analyzed))
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "report",
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                    "--no-benchmark-ground-truth",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = output_path.read_text()
            self.assertIn("Source-to-sink evidence", report)
            self.assertIn("request.args", report)
            self.assertIn("cursor.execute", report)
            self.assertIn("/search", report)
            self.assertIn("Dynamically confirmed", report)


if __name__ == "__main__":
    unittest.main()
