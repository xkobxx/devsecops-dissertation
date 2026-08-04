from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from trustgate.reachability.service import analyze_scan_run
from trustgate.scanners.models import ScannerState
from trustgate.schema import build_scan_run, validate_instance

from tests.unit.schemas.test_documents import scanner_result
from tests.unit.schemas.test_schema_contracts import valid_finding


class ReachabilityServiceTests(unittest.TestCase):
    def test_analyzes_scan_run_and_publishes_valid_summary(self) -> None:
        finding = valid_finding()
        finding.update(
            {
                "category": "dependency",
                "cve": ["CVE-2026-1234"],
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
            root = Path(directory)
            (root / "requirements.txt").write_text("demo==1.0.0\n")
            (root / "app.py").write_text("import demo\ndemo.danger()\n")

            analyzed = analyze_scan_run(
                scan_run,
                repository_root=root,
                vulnerable_symbols={"demo": ("danger",)},
                deployed_packages=("demo",),
            )

        validate_instance("scan-run", analyzed)
        reachability = analyzed["findings"][0]["dependency_reachability"]
        self.assertEqual(reachability["status"], "CONFIRMED_REACHABLE")
        self.assertEqual(analyzed["findings"][0]["reachability"], "reachable")
        summary = analyzed["summary"]["reachability_analysis"]
        self.assertEqual(summary["dependency_findings_analyzed"], 1)
        self.assertEqual(summary["confirmed_reachable"], 1)

    def test_service_does_not_mutate_input_scan_run(self) -> None:
        scan_run = build_scan_run(
            target=".",
            findings=[valid_finding()],
            scanner_results=[scanner_result(ScannerState.FINDINGS)],
        )
        with tempfile.TemporaryDirectory() as directory:
            analyze_scan_run(scan_run, repository_root=Path(directory))

        self.assertNotIn("reachability_analysis", scan_run["summary"])
        self.assertNotIn("source_to_sink_analysis", scan_run["findings"][0])

    def test_source_and_dynamic_evidence_validate_together(self) -> None:
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
            root = Path(directory)
            (root / "app.py").write_text(
                "from flask import request\n"
                "@app.get('/search')\n"
                "def search():\n"
                "    value = request.args['q']\n"
                "    cursor.execute(value)\n"
            )
            analyzed = analyze_scan_run(
                scan_run,
                repository_root=root,
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

        validate_instance("scan-run", analyzed)
        self.assertEqual(
            analyzed["findings"][0]["dynamic_correlation"]["status"],
            "confirmed",
        )
        self.assertEqual(
            analyzed["summary"]["reachability_analysis"]["dynamically_confirmed"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
