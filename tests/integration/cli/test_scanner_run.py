import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from trustgate.scanners.cli import DEFAULT_FINDING_EXIT_CODES


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class ScannerRunCliTests(unittest.TestCase):
    def test_scanner_exit_code_contracts_are_explicit(self) -> None:
        self.assertEqual(DEFAULT_FINDING_EXIT_CODES["bandit"], {1})
        self.assertEqual(DEFAULT_FINDING_EXIT_CODES["semgrep"], set())
        self.assertEqual(DEFAULT_FINDING_EXIT_CODES["pip-audit"], {1})
        self.assertEqual(DEFAULT_FINDING_EXIT_CODES["trivy"], set())
        self.assertEqual(DEFAULT_FINDING_EXIT_CODES["gitleaks"], {3})

    def test_findings_exit_is_recorded_without_failing_the_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            report = workspace / "reports" / "bandit.json"
            metadata = workspace / "reports" / "bandit_execution.json"
            script = (
                "from pathlib import Path; import sys; "
                "Path(sys.argv[1]).parent.mkdir(parents=True, exist_ok=True); "
                "Path(sys.argv[1]).write_text('{}'); raise SystemExit(1)"
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "scanner-run",
                    "--scanner",
                    "bandit",
                    "--report",
                    str(report),
                    "--metadata",
                    str(metadata),
                    "--timeout",
                    "5",
                    "--version",
                    "1.9.4",
                    "--",
                    sys.executable,
                    "-c",
                    script,
                    str(report),
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(metadata.read_text())["state"], "FINDINGS")

    def test_scanner_crash_is_visible_as_wrapper_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            report = workspace / "reports" / "bandit.json"
            metadata = workspace / "reports" / "bandit_execution.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "scanner-run",
                    "--scanner",
                    "bandit",
                    "--report",
                    str(report),
                    "--metadata",
                    str(metadata),
                    "--timeout",
                    "5",
                    "--",
                    sys.executable,
                    "-c",
                    "raise SystemExit(2)",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertEqual(
                json.loads(metadata.read_text())["state"],
                "FAILED_SCANNER",
            )

    def test_external_scanner_action_outcome_can_be_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            report = workspace / "reports" / "trivy.json"
            report.parent.mkdir()
            report.write_text('{"Results":[]}')
            metadata = workspace / "reports" / "trivy_execution.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    str(REPOSITORY_ROOT / "scripts" / "record_scanner.py"),
                    "--scanner",
                    "trivy",
                    "--report",
                    str(report),
                    "--metadata",
                    str(metadata),
                    "--started-at",
                    "2026-07-24T10:00:00+00:00",
                    "--outcome",
                    "failure",
                    "--version",
                    "0.69.3",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(metadata.read_text())
            self.assertEqual(result["state"], "FAILED_SCANNER")
            self.assertEqual(result["version"], "0.69.3")


if __name__ == "__main__":
    unittest.main()
