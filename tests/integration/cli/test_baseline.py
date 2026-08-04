from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from trustgate.baselines import create_baseline

from tests.unit.baselines.test_comparison import changed_runs
from tests.unit.baselines.test_creation import GENERATED_AT


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class BaselineCliTests(unittest.TestCase):
    def run_cli(self, workspace: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "trustgate", "baseline", *arguments],
            cwd=workspace,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_create_and_compare_persist_validated_documents(self) -> None:
        baseline_scan, current_scan = changed_runs()
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            source = workspace / "default-branch.json"
            source.write_text(json.dumps(baseline_scan), encoding="utf-8")
            current = workspace / "pull-request.json"
            current.write_text(json.dumps(current_scan), encoding="utf-8")
            baseline = workspace / "baseline.json"
            difference = workspace / "baseline-diff.json"

            created = self.run_cli(
                workspace,
                "create",
                "--input",
                str(source),
                "--output",
                str(baseline),
                "--default-branch",
                "main",
            )
            compared = self.run_cli(
                workspace,
                "compare",
                "--baseline",
                str(baseline),
                "--input",
                str(current),
                "--output",
                str(difference),
            )

            self.assertEqual(created.returncode, 0, created.stderr)
            self.assertIn("Created baseline", created.stdout)
            self.assertEqual(compared.returncode, 0, compared.stderr)
            self.assertIn("new=1", compared.stdout)
            baseline_document = json.loads(baseline.read_text(encoding="utf-8"))
            difference_document = json.loads(difference.read_text(encoding="utf-8"))
            self.assertEqual(len(baseline_document["findings"]), 6)
            self.assertEqual(difference_document["summary"]["new_findings"], 1)

    def test_invalid_default_branch_fails_clearly_without_traceback(self) -> None:
        baseline_scan, _current_scan = changed_runs()
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            source = workspace / "feature.json"
            baseline_scan["ref"] = "refs/heads/feature"
            source.write_text(json.dumps(baseline_scan), encoding="utf-8")

            completed = self.run_cli(
                workspace,
                "create",
                "--input",
                str(source),
                "--output",
                str(workspace / "baseline.json"),
                "--default-branch",
                "main",
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("Baseline error:", completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)

    def test_default_new_gate_blocks_new_high_finding_and_writes_result(self) -> None:
        baseline_scan, current_scan = changed_runs()
        baseline_document = create_baseline(
            baseline_scan,
            default_branch="main",
            generated_at=GENERATED_AT,
        )
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            baseline = workspace / "baseline.json"
            baseline.write_text(json.dumps(baseline_document), encoding="utf-8")
            current = workspace / "pull-request.json"
            current.write_text(json.dumps(current_scan), encoding="utf-8")
            gate_output = workspace / "baseline-gate.json"

            completed = self.run_cli(
                workspace,
                "gate",
                "--baseline",
                str(baseline),
                "--input",
                str(current),
                "--output",
                str(gate_output),
            )

            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertIn("Gate failed", completed.stdout)
            self.assertIn("mode=new", completed.stdout)
            self.assertIn("baseline_age=", completed.stdout)
            gate = json.loads(gate_output.read_text(encoding="utf-8"))
            self.assertFalse(gate["passed"])
            self.assertEqual(gate["summary"]["blocked_findings"], 1)

    def test_gate_help_exposes_all_modes_and_legacy_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            completed = self.run_cli(Path(directory), "gate", "--help")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("{new,all,worsened,policy}", completed.stdout)
        self.assertIn("--enforce-legacy-risk", completed.stdout)
        self.assertIn("--policy", completed.stdout)

    def test_invalid_baseline_gate_fails_clearly_without_traceback(self) -> None:
        baseline_scan, current_scan = changed_runs()
        baseline_document = create_baseline(
            baseline_scan,
            default_branch="main",
            generated_at=GENERATED_AT,
        )
        baseline_document["commit"] = "c" * 40
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            baseline = workspace / "baseline.json"
            baseline.write_text(json.dumps(baseline_document), encoding="utf-8")
            current = workspace / "pull-request.json"
            current.write_text(json.dumps(current_scan), encoding="utf-8")

            completed = self.run_cli(
                workspace,
                "gate",
                "--baseline",
                str(baseline),
                "--input",
                str(current),
                "--output",
                str(workspace / "gate.json"),
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("Baseline error:", completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
