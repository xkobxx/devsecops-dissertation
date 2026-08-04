"""CLI contracts for deterministic SARIF publication."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from trustgate.sarif import validate_sarif

from tests.unit.sarif.test_generation import scan_run
from tests.unit.schemas.test_schema_contracts import valid_finding


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class SarifCliTests(unittest.TestCase):
    def test_cli_generates_valid_sarif_outside_the_repository(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "scan.json"
            output = root / "nested" / "trustgate.sarif"
            source.write_text(
                json.dumps(scan_run(valid_finding())),
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "sarif",
                    "--input",
                    str(source),
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
            self.assertIn("Generated SARIF with 1 result", completed.stdout)
            document = json.loads(output.read_text(encoding="utf-8"))
            validate_sarif(document)

    def test_cli_does_not_publish_invalid_input(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "scan.json"
            output = root / "trustgate.sarif"
            source.write_text("[]", encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "sarif",
                    "--input",
                    str(source),
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
            self.assertIn("SARIF error:", completed.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
