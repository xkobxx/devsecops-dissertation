"""CLI acceptance contracts for the consolidated pull-request comment."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.unit.checks.test_cli import documents


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
COMMIT = "b" * 40


class PullRequestCommentCliTests(unittest.TestCase):
    def test_cli_writes_one_concise_collapsed_and_safe_comment(self) -> None:
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
            output = root / "nested" / "pr-comment.md"

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "pr-comment",
                    "--input",
                    str(paths["scan"]),
                    "--policy-result",
                    str(paths["policy"]),
                    "--baseline-diff",
                    str(paths["difference"]),
                    "--baseline-gate",
                    str(paths["gate"]),
                    "--repository",
                    "example/trustgate",
                    "--commit",
                    COMMIT,
                    "--artifact-url",
                    "https://github.com/example/trustgate/actions/runs/99#artifacts",
                    "--dashboard-url",
                    "https://example.github.io/trustgate/",
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
            comment = output.read_text(encoding="utf-8")
            self.assertEqual(comment.count("<!-- trustgate-pr-summary -->"), 1)
            self.assertIn("## Trust Gate", comment)
            self.assertIn("**Release decision: FAIL**", comment)
            self.assertIn("| New | 1 |", comment)
            self.assertIn("| Blocking | 5 |", comment)
            self.assertIn("| Suppressed | 1 |", comment)
            self.assertIn("<details>", comment)
            self.assertIn("</details>", comment)
            self.assertIn(
                "https://github.com/example/trustgate/blob/"
                f"{COMMIT}/src/app.py#L42",
                comment,
            )
            self.assertIn("Remediation", comment)
            self.assertIn("available", comment)
            self.assertIn("Detailed workflow artifacts", comment)
            self.assertIn("Open dashboard", comment)
            self.assertNotIn("request.args", comment)
            self.assertNotIn("Untrusted input reaches", comment)
            self.assertNotIn("Use parameterised SQL", comment)
            self.assertNotIn("Potential SQL injection", comment)
            self.assertLess(len(comment.encode("utf-8")), 32_768)

    def test_cli_rejects_unsafe_repository_and_does_not_write_output(self) -> None:
        scan_run, policy, _, _ = documents()
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scan_path = root / "findings.json"
            policy_path = root / "policy-result.json"
            output = root / "pr-comment.md"
            scan_path.write_text(json.dumps(scan_run), encoding="utf-8")
            policy_path.write_text(json.dumps(policy), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "pr-comment",
                    "--input",
                    str(scan_path),
                    "--policy-result",
                    str(policy_path),
                    "--repository",
                    "example/trustgate)\n@everyone",
                    "--commit",
                    COMMIT,
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
            self.assertIn("owner/name", completed.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
