from __future__ import annotations

import json
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trustgate.cli import main as cli_main

from .test_generation import analysis_document, dependency_scan_run


class VexCliTests(unittest.TestCase):
    def test_cli_writes_and_signs_a_versioned_vex_document(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            scan_run = root / "scan-run.json"
            analyses = root / "analyses.json"
            output = root / "trustgate.vex.cdx.json"
            fake_cosign = root / "cosign"
            scan_document = dependency_scan_run()
            scan_run.write_text(
                json.dumps(scan_document, indent=2) + "\n", encoding="utf-8"
            )
            analyses.write_text(
                json.dumps(analysis_document(scan_document), indent=2) + "\n",
                encoding="utf-8",
            )
            fake_cosign.write_text(
                "#!/bin/sh\n"
                "bundle=''\n"
                'while [ "$#" -gt 0 ]; do\n'
                "  if [ \"$1\" = '--bundle' ]; then bundle=$2; shift 2; else shift; fi\n"
                "done\n"
                "printf '%s\\n' '{\"verificationMaterial\":{}}' > \"$bundle\"\n",
                encoding="utf-8",
            )
            fake_cosign.chmod(fake_cosign.stat().st_mode | stat.S_IXUSR)

            result = cli_main(
                [
                    "vex",
                    "--input",
                    str(scan_run),
                    "--analyses",
                    str(analyses),
                    "--output",
                    str(output),
                    "--sign",
                    "--cosign",
                    str(fake_cosign),
                ]
            )

            self.assertEqual(result, 0)
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8"))["version"], 3
            )
            self.assertTrue(output.with_name(f"{output.name}.sigstore.json").is_file())


if __name__ == "__main__":
    unittest.main()
