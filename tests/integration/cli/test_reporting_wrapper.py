import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from trustgate.schema import migrate_scan_run


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class ReportingWrapperTests(unittest.TestCase):
    def test_legacy_report_generator_works_outside_the_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            reports = workspace / "reports"
            reports.mkdir()
            (reports / "findings.json").write_text(
                json.dumps(
                    {
                        "target": ".",
                        "total": 1,
                        "findings": [
                            {
                                "tool": "Bandit",
                                "rule_id": "B602",
                                "severity": "HIGH",
                                "description": "<script>unsafe()</script>",
                                "file": "app.py",
                                "line": 12,
                            }
                        ],
                    }
                )
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(REPOSITORY_ROOT / "scripts" / "generate_report.py"),
                ],
                cwd=workspace,
                capture_output=True,
                text=True,
                check=False,
            )

            dashboard = reports / "dashboard.html"
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(dashboard.is_file())
            rendered = dashboard.read_text()
            self.assertIn("&lt;script&gt;unsafe()&lt;/script&gt;", rendered)
            self.assertNotIn("<script>unsafe()</script>", rendered)

    def test_cli_report_accepts_explicit_paths_outside_the_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            findings = workspace / "inputs" / "findings.json"
            findings.parent.mkdir()
            findings.write_text(
                json.dumps(
                    {
                        "target": ".",
                        "total": 0,
                        "findings": [],
                    }
                )
            )
            dashboard = workspace / "outputs" / "trustgate.html"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "report",
                    "--input",
                    str(findings),
                    "--output",
                    str(dashboard),
                    "--no-benchmark-ground-truth",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(dashboard.is_file())
            self.assertIn("Security Dashboard", dashboard.read_text())

    def test_report_reads_canonical_scanner_severity_and_line_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            findings = workspace / "findings.json"
            findings.write_text(
                json.dumps(
                    migrate_scan_run(
                        {
                            "target": ".",
                            "total": 1,
                            "findings": [
                                {
                                    "tool": "Bandit",
                                    "rule_id": "B608",
                                    "severity": "MEDIUM",
                                    "description": "Canonical finding.",
                                    "file": "app.py",
                                    "line": 18,
                                }
                            ],
                        }
                    )
                ),
                encoding="utf-8",
            )
            dashboard = workspace / "dashboard.html"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "report",
                    "--input",
                    str(findings),
                    "--output",
                    str(dashboard),
                    "--no-benchmark-ground-truth",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            rendered = dashboard.read_text(encoding="utf-8")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("Bandit", rendered)
            self.assertIn("MEDIUM", rendered)
            self.assertIn(">18</td>", rendered)


if __name__ == "__main__":
    unittest.main()
