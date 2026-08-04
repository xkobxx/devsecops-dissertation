"""CLI acceptance contracts for GitHub Check summaries."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from trustgate.baselines import compare_to_baseline, create_baseline, evaluate_gate
from trustgate.schema.documents import build_policy_result

from tests.unit.baselines.test_comparison import changed_runs
from tests.unit.baselines.test_creation import GENERATED_AT


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EVALUATED_AT = datetime(2026, 8, 4, 14, 0, tzinfo=timezone.utc)


def documents() -> tuple[dict[str, object], ...]:
    baseline_scan, current = changed_runs()
    baseline = create_baseline(
        baseline_scan,
        default_branch="main",
        generated_at=GENERATED_AT,
    )
    difference = compare_to_baseline(
        baseline,
        current,
        compared_at=EVALUATED_AT,
    )
    gate = evaluate_gate(
        baseline,
        current,
        evaluated_at=EVALUATED_AT,
    )
    policy = build_policy_result(
        current,
        fail_on="high",
        scanner_failure_policy="fail",
        evaluated_at=EVALUATED_AT,
    )
    return current, policy, difference, gate


class CheckSummaryCliTests(unittest.TestCase):
    def test_cli_writes_complete_bounded_release_decision_summary(self) -> None:
        scan_run, policy, difference, gate = documents()
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "scan": root / "findings.json",
                "policy": root / "policy-result.json",
                "difference": root / "baseline-diff.json",
                "gate": root / "baseline-gate.json",
            }
            for name, document in zip(
                paths,
                (scan_run, policy, difference, gate),
                strict=True,
            ):
                paths[name].write_text(json.dumps(document), encoding="utf-8")
            output = root / "nested" / "check-summary.md"

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "checks",
                    "--input",
                    str(paths["scan"]),
                    "--policy-result",
                    str(paths["policy"]),
                    "--baseline-diff",
                    str(paths["difference"]),
                    "--baseline-gate",
                    str(paths["gate"]),
                    "--artifact-url",
                    "https://github.com/example/trustgate/actions/runs/99#artifacts",
                    "--output",
                    str(output),
                ],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = output.read_text(encoding="utf-8")
            self.assertIn("# Trust Gate check", summary)
            self.assertIn("**Release decision: FAIL**", summary)
            self.assertIn("## Scanner health", summary)
            self.assertIn("semgrep", summary)
            self.assertIn("FINDINGS", summary)
            self.assertIn("## Finding overview", summary)
            self.assertIn("| New | 1 |", summary)
            self.assertIn("| Suppressed | 1 |", summary)
            self.assertIn("| Unscored | 6 |", summary)
            self.assertIn("## Suppressed findings", summary)
            self.assertIn("finding-suppressed", summary)
            self.assertIn("## Unscored findings", summary)
            self.assertIn("## New findings", summary)
            self.assertIn("finding-introduced", summary)
            self.assertIn("## Blocking findings", summary)
            self.assertIn("## Evidence explanations", summary)
            self.assertIn("reachable", summary)
            self.assertIn("## Policy", summary)
            self.assertIn("`default@1.0.0`", summary)
            self.assertIn("## Baseline comparison", summary)
            self.assertIn("| Worsened | 1 |", summary)
            self.assertIn(
                "[Detailed workflow artifacts](https://github.com/example/"
                "trustgate/actions/runs/99#artifacts)",
                summary,
            )
            self.assertNotIn("request.args", summary)
            self.assertNotIn("Untrusted input reaches", summary)
            self.assertLess(len(summary.encode("utf-8")), 65_536)

    def test_cli_rejects_evidence_from_a_different_scan_run(self) -> None:
        scan_run, policy, _, _ = documents()
        policy["run_id"] = "run-from-another-scan"
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scan_path = root / "findings.json"
            policy_path = root / "policy-result.json"
            output = root / "check-summary.md"
            scan_path.write_text(json.dumps(scan_run), encoding="utf-8")
            policy_path.write_text(json.dumps(policy), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "checks",
                    "--input",
                    str(scan_path),
                    "--policy-result",
                    str(policy_path),
                    "--output",
                    str(output),
                ],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("belongs to a different scan run", completed.stderr)
            self.assertFalse(output.exists())

    def test_cli_rejects_unsafe_artifact_links(self) -> None:
        scan_run, policy, _, _ = documents()
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scan_path = root / "findings.json"
            policy_path = root / "policy-result.json"
            output = root / "check-summary.md"
            scan_path.write_text(json.dumps(scan_run), encoding="utf-8")
            policy_path.write_text(json.dumps(policy), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "checks",
                    "--input",
                    str(scan_path),
                    "--policy-result",
                    str(policy_path),
                    "--artifact-url",
                    "javascript:alert(1)",
                    "--output",
                    str(output),
                ],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("safe HTTPS URL", completed.stderr)
            self.assertFalse(output.exists())

    def test_cli_rejects_a_baseline_comparison_for_another_run(self) -> None:
        scan_run, policy, difference, _ = documents()
        difference["current_run_id"] = "run-from-another-scan"
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scan_path = root / "findings.json"
            policy_path = root / "policy-result.json"
            difference_path = root / "baseline-diff.json"
            output = root / "check-summary.md"
            scan_path.write_text(json.dumps(scan_run), encoding="utf-8")
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            difference_path.write_text(json.dumps(difference), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "checks",
                    "--input",
                    str(scan_path),
                    "--policy-result",
                    str(policy_path),
                    "--baseline-diff",
                    str(difference_path),
                    "--output",
                    str(output),
                ],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("baseline difference belongs", completed.stderr)
            self.assertFalse(output.exists())

    def test_cli_rejects_a_baseline_gate_for_another_run(self) -> None:
        scan_run, policy, _, gate = documents()
        gate["current_run_id"] = "run-from-another-scan"
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scan_path = root / "findings.json"
            policy_path = root / "policy-result.json"
            gate_path = root / "baseline-gate.json"
            output = root / "check-summary.md"
            scan_path.write_text(json.dumps(scan_run), encoding="utf-8")
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            gate_path.write_text(json.dumps(gate), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "checks",
                    "--input",
                    str(scan_path),
                    "--policy-result",
                    str(policy_path),
                    "--baseline-gate",
                    str(gate_path),
                    "--output",
                    str(output),
                ],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("baseline gate belongs", completed.stderr)
            self.assertFalse(output.exists())

    def test_cli_rejects_baseline_documents_that_do_not_match(self) -> None:
        scan_run, policy, difference, gate = documents()
        gate["comparison_digest"] = "sha256:" + "0" * 64
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "scan": root / "findings.json",
                "policy": root / "policy-result.json",
                "difference": root / "baseline-diff.json",
                "gate": root / "baseline-gate.json",
            }
            for name, document in zip(
                files,
                (scan_run, policy, difference, gate),
                strict=True,
            ):
                files[name].write_text(json.dumps(document), encoding="utf-8")
            files["gate"].write_text(json.dumps(gate), encoding="utf-8")
            output = root / "check-summary.md"

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "checks",
                    "--input",
                    str(files["scan"]),
                    "--policy-result",
                    str(files["policy"]),
                    "--baseline-diff",
                    str(files["difference"]),
                    "--baseline-gate",
                    str(files["gate"]),
                    "--output",
                    str(output),
                ],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("does not match the baseline difference", completed.stderr)
            self.assertFalse(output.exists())

    def test_cli_escapes_markdown_control_characters(self) -> None:
        scan_run, policy, _, _ = documents()
        policy["policy_name"] = "default`unsafe"
        policy["reason"] = "## unsafe [click](javascript:alert(1))"
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scan_path = root / "findings.json"
            policy_path = root / "policy-result.json"
            output = root / "check-summary.md"
            scan_path.write_text(json.dumps(scan_run), encoding="utf-8")
            policy_path.write_text(json.dumps(policy), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "checks",
                    "--input",
                    str(scan_path),
                    "--policy-result",
                    str(policy_path),
                    "--output",
                    str(output),
                ],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = output.read_text(encoding="utf-8")
            self.assertIn("default&#96;unsafe", summary)
            self.assertNotIn("default`unsafe", summary)
            self.assertIn("&#35;&#35; unsafe &#91;click&#93;", summary)
            self.assertNotIn("[click](javascript:", summary)


if __name__ == "__main__":
    unittest.main()
