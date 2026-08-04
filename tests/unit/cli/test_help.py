import os
import subprocess
import sys
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class TrustGateHelpTests(unittest.TestCase):
    def test_module_help_describes_the_product(self):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

        completed = subprocess.run(
            [sys.executable, "-m", "trustgate", "--help"],
            cwd=REPOSITORY_ROOT.parent,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("usage: trustgate", completed.stdout)
        self.assertIn(
            "local-first application-security decision platform", completed.stdout
        )
        self.assertIn("aggregate", completed.stdout)
        self.assertIn("enrich", completed.stdout)
        self.assertIn("reachability", completed.stdout)
        self.assertIn("dast", completed.stdout)
        self.assertIn("decide", completed.stdout)
        self.assertIn("policy", completed.stdout)
        self.assertIn("baseline", completed.stdout)
        self.assertIn("suppression", completed.stdout)
        self.assertIn("sarif", completed.stdout)
        self.assertIn("checks", completed.stdout)
        self.assertIn("pr-comment", completed.stdout)
        self.assertIn("sbom", completed.stdout)
        self.assertIn("vex", completed.stdout)
        self.assertIn("report", completed.stdout)

    def test_enrichment_help_documents_all_network_modes(self):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

        completed = subprocess.run(
            [sys.executable, "-m", "trustgate", "enrich", "--help"],
            cwd=REPOSITORY_ROOT.parent,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("disabled", completed.stdout)
        self.assertIn("metadata-only", completed.stdout)
        self.assertIn("full", completed.stdout)
        self.assertIn("metadata-only", completed.stdout)


if __name__ == "__main__":
    unittest.main()
