from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from trustgate.schema import validate_instance

from tests.unit.decisions.test_persistence import runtime_context, scan_run


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class DecisionCliTests(unittest.TestCase):
    def test_cli_evaluates_and_persists_contextual_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            input_path = workspace / "scan.json"
            context_path = workspace / "context.json"
            output_path = workspace / "decided.json"
            input_path.write_text(json.dumps(scan_run()), encoding="utf-8")
            context_path.write_text(
                json.dumps({"shared": runtime_context()}),
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "decide",
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                    "--runtime-context",
                    str(context_path),
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            decided = json.loads(output_path.read_text(encoding="utf-8"))
            validate_instance("scan-run", decided)
            self.assertEqual(
                decided["findings"][0]["contextual_decision"]["outcome"],
                "BLOCK_IMMEDIATELY",
            )
            self.assertIn("BLOCK_IMMEDIATELY=1", completed.stdout)
            self.assertIn("trustgate-contextual-default@1.0.0", completed.stdout)

    def test_report_renders_complete_decision_explanation(self) -> None:
        from trustgate.decisions.service import evaluate_scan_run

        decided = evaluate_scan_run(
            scan_run(),
            runtime_context=runtime_context(),
        )
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            input_path = workspace / "decided.json"
            output_path = workspace / "report.html"
            input_path.write_text(json.dumps(decided), encoding="utf-8")
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
            report = output_path.read_text(encoding="utf-8")
            self.assertIn("BLOCK_IMMEDIATELY", report)
            self.assertIn("trustgate-contextual-default@1.0.0", report)
            self.assertIn("Evidence strength", report)
            self.assertIn("Complete decision explanation", report)
            self.assertIn("Unresolved uncertainty", report)
            self.assertIn("CISA KEV is True", report)


if __name__ == "__main__":
    unittest.main()
