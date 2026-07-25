import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class AdapterCliTests(unittest.TestCase):
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

    def test_adapter_list_reports_applicability_and_metadata(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.go").write_text("package main\n", encoding="utf-8")
            (root / "go.mod").write_text("module example.test/demo\n", encoding="utf-8")

            completed = self._run(
                "adapter-list", "--target", str(root), "--json", cwd=root
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        catalogue = json.loads(completed.stdout)
        by_name = {entry["name"]: entry for entry in catalogue}
        self.assertTrue(by_name["gosec"]["applicable"])
        self.assertFalse(by_name["bandit"]["applicable"])
        self.assertEqual(len(catalogue), 17)

    def test_adapter_run_skips_an_irrelevant_scanner_without_executing_it(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("demo\n", encoding="utf-8")

            completed = self._run(
                "adapter-run",
                "--scanner",
                "gosec",
                "--target",
                str(root),
                "--reports-dir",
                str(root / "reports"),
                cwd=root,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("SKIPPED", completed.stdout)
        self.assertFalse((root / "reports").exists())

    def test_codeql_sarif_import_runs_without_codeql_runtime(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            sarif = root / "results.sarif"
            sarif.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [{
                            "tool": {"driver": {"name": "CodeQL", "rules": []}},
                            "results": [],
                        }],
                    }
                ),
                encoding="utf-8",
            )
            reports = root / "reports"

            completed = self._run(
                "adapter-run",
                "--scanner",
                "codeql-sarif",
                "--target",
                str(root),
                "--reports-dir",
                str(reports),
                cwd=root,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("CLEAN", completed.stdout)
            self.assertTrue((reports / "codeql_report.sarif").is_file())
            metadata = json.loads(
                (reports / "codeql-sarif_execution.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(metadata["parser_status"], "SUCCESS")


if __name__ == "__main__":
    unittest.main()
