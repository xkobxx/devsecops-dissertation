from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class DastCliTests(unittest.TestCase):
    def _environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        return environment

    def test_cli_writes_reusable_safe_baseline_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            plan_path = workspace / "reports" / "dast-plan.yaml"
            completed = subprocess.run(
                [
                    sys.executable, "-m", "trustgate", "dast",
                    "--target-url", "https://preview.example.test",
                    "--environment", "preview",
                    "--scope-host", "preview.example.test",
                    "--public-target-acknowledged",
                    "--plan-output", str(plan_path),
                ],
                cwd=workspace,
                env=self._environment(),
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            plan = json.loads(plan_path.read_text())

        job_types = [job["type"] for job in plan["jobs"]]
        self.assertIn("spider", job_types)
        self.assertNotIn("activeScan", job_types)
        self.assertIn("DAST plan written", completed.stdout)

    def test_authenticated_execution_redacts_secret_from_all_logs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            fake_zap = workspace / "fake-zap"
            fake_zap.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "plan = json.loads(pathlib.Path(sys.argv[-1]).read_text())\n"
                "job = next(item for item in plan['jobs'] if item['type'] == 'report')\n"
                "target = pathlib.Path(job['parameters']['reportDir']) / job['parameters']['reportFile']\n"
                "target.parent.mkdir(parents=True, exist_ok=True)\n"
                "target.write_text('{\"site\": []}')\n"
                "secret = os.environ['TRUSTGATE_DAST_AUTH_SECRET']\n"
                "print('auth=' + secret)\n"
                "print('auth-error=' + secret, file=sys.stderr)\n"
            )
            fake_zap.chmod(0o700)
            secret = "phase-nine-cli-secret"
            environment = self._environment()
            environment["TRUSTGATE_DAST_AUTH_SECRET"] = secret
            plan_path = workspace / "reports" / "dast-plan.yaml"
            report_path = workspace / "reports" / "zap.json"
            metadata_path = workspace / "reports" / "zap-execution.json"
            logs_dir = workspace / "reports" / "logs"

            completed = subprocess.run(
                [
                    sys.executable, "-m", "trustgate", "dast",
                    "--target-url", "https://preview.example.test",
                    "--environment", "preview",
                    "--scope-host", "preview.example.test",
                    "--public-target-acknowledged",
                    "--auth-type", "bearer",
                    "--plan-output", str(plan_path),
                    "--report", str(report_path),
                    "--metadata", str(metadata_path),
                    "--logs-dir", str(logs_dir),
                    "--zap-executable", str(fake_zap),
                    "--execute",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            combined = completed.stdout + completed.stderr
            combined += "".join(
                path.read_text() for path in logs_dir.iterdir() if path.is_file()
            )
            metadata = json.loads(metadata_path.read_text())

        self.assertNotIn(secret, combined)
        self.assertIn("[REDACTED]", combined)
        self.assertEqual(metadata["state"], "CLEAN")


if __name__ == "__main__":
    unittest.main()
