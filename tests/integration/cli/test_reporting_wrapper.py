import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from trustgate.benchmarks.statistics import posterior_precision
from trustgate.confidence import build_confidence_components
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

    def test_report_displays_every_confidence_component_and_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            scan_run = migrate_scan_run(
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
                            "reachability": "reachable",
                        }
                    ],
                }
            )
            finding = scan_run["findings"][0]
            components = build_confidence_components(
                finding,
                posterior_precision(8, 2),
            )
            finding.update(components)
            finding["confidence"] = components[
                "overall_decision_confidence"
            ]["estimate"]
            findings = workspace / "findings.json"
            findings.write_text(json.dumps(scan_run), encoding="utf-8")
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
            for label in (
                "Scanner rule reliability",
                "Finding validity",
                "Reachability",
                "Exploitability",
                "Remediation",
                "Overall decision",
            ):
                self.assertIn(label, rendered)
            self.assertIn(
                "Scanner reliability is not exploitability evidence",
                rendered,
            )

    def test_dashboard_reads_accuracy_from_the_canonical_metrics_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            findings = workspace / "findings.json"
            findings.write_text(
                json.dumps(
                    {
                        "target": ".",
                        "total": 0,
                        "findings": [],
                    }
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
                    "--benchmark-ground-truth",
                    str(
                        REPOSITORY_ROOT
                        / "benchmarks/ground_truth/flask-vulnerable-v1.json"
                    ),
                    "--benchmark-metrics",
                    str(
                        REPOSITORY_ROOT
                        / "benchmarks/reports/flask-vulnerable-v1.metrics.json"
                    ),
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            rendered = dashboard.read_text(encoding="utf-8")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("flask-vulnerable v1.0.0", rendered)
            self.assertGreaterEqual(rendered.count(">80%</span>"), 3)
            self.assertIn('<div class="matrix-val">12</div>', rendered)
            self.assertIn('<div class="matrix-val">3</div>', rendered)
            self.assertIn('<div class="matrix-val">2</div>', rendered)


if __name__ == "__main__":
    unittest.main()
