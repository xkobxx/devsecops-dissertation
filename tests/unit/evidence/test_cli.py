from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.cli import main as cli_main

from .test_generation import evidence_fixture


class AuditEvidenceCliTests(unittest.TestCase):
    def test_cli_generates_and_verifies_manifest(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "audit-evidence.json"
            output = root / "reports/audit-evidence.json"
            config.write_text(
                json.dumps(evidence_fixture(root), indent=2) + "\n",
                encoding="utf-8",
            )

            generated = cli_main(
                [
                    "evidence",
                    "generate",
                    "--root",
                    str(root),
                    "--config",
                    str(config),
                    "--output",
                    str(output),
                ]
            )
            verified = cli_main(
                [
                    "evidence",
                    "verify",
                    "--root",
                    str(root),
                    "--manifest",
                    str(output),
                ]
            )

            self.assertEqual(generated, 0)
            self.assertEqual(verified, 0)
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8"))["schema_version"],
                "1.0.0",
            )

            (root / "release/provenance.json").write_text("{}\n", encoding="utf-8")
            self.assertEqual(
                cli_main(
                    [
                        "evidence",
                        "verify",
                        "--root",
                        str(root),
                        "--manifest",
                        str(output),
                    ]
                ),
                2,
            )


if __name__ == "__main__":
    unittest.main()
