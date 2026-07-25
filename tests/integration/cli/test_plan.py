import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class PlanCliTests(unittest.TestCase):
    def _run(self, *arguments: str, cwd: Path):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "trustgate", *arguments],
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def _repository(self, root: Path) -> None:
        (root / "app.py").write_text("print('hello')\n", encoding="utf-8")
        (root / "requirements.txt").write_text("flask==3.1.0\n", encoding="utf-8")

    def test_plan_json_is_complete_and_does_not_execute_scanners(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._repository(root)

            completed = self._run(
                "plan",
                "--target",
                str(root),
                "--format",
                "json",
                "--dry-run",
                cwd=root,
            )

            self.assertFalse((root / "reports").exists())

        self.assertEqual(completed.returncode, 0, completed.stderr)
        plan = json.loads(completed.stdout)
        self.assertTrue(plan["dry_run"])
        self.assertIn("python", plan["detected_technologies"]["languages"])
        self.assertIn("bandit", plan["enabled_scanners"])
        self.assertIn("gosec", plan["skipped_scanners"])
        self.assertEqual(len(plan["decisions"]), 17)
        self.assertIn("reason", plan["decisions"][0])

    def test_human_plan_explains_detection_selection_and_execution_contract(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._repository(root)
            completed = self._run("plan", "--target", str(root), cwd=root)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        for heading in (
            "Detected technologies",
            "Enabled scanners",
            "Skipped scanners",
            "Target directories",
            "Expected outputs",
            "Timeout",
            "Data handling",
        ):
            self.assertIn(heading, completed.stdout)

    def test_cli_overrides_auto_detection_and_validates_conflicts(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._repository(root)
            completed = self._run(
                "plan",
                "--target",
                str(root),
                "--format",
                "json",
                "--enable-scanner",
                "trufflehog",
                "--disable-scanner",
                "bandit",
                "--timeout",
                "gitleaks=45",
                cwd=root,
            )
            conflict = self._run(
                "plan",
                "--target",
                str(root),
                "--enable-scanner",
                "bandit",
                "--disable-scanner",
                "bandit",
                cwd=root,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        decisions = {
            item["scanner"]: item for item in json.loads(completed.stdout)["decisions"]
        }
        self.assertTrue(decisions["trufflehog"]["enabled"])
        self.assertFalse(decisions["bandit"]["enabled"])
        self.assertEqual(decisions["gitleaks"]["timeout_seconds"], 45.0)
        self.assertEqual(conflict.returncode, 2)
        self.assertIn("both enabled and disabled", conflict.stdout)

    def test_adapter_run_dry_run_never_invokes_scanner(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._repository(root)
            reports = root / "reports"

            completed = self._run(
                "adapter-run",
                "--scanner",
                "bandit",
                "--target",
                str(root),
                "--reports-dir",
                str(reports),
                "--dry-run",
                cwd=root,
            )

            self.assertFalse(reports.exists())

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("DRY RUN", completed.stdout)
        self.assertIn("bandit", completed.stdout)


if __name__ == "__main__":
    unittest.main()
