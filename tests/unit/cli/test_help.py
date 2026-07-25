import os
from pathlib import Path
import subprocess
import sys
import unittest


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
        self.assertIn("local-first application-security decision platform", completed.stdout)
        self.assertIn("aggregate", completed.stdout)
        self.assertIn("report", completed.stdout)


if __name__ == "__main__":
    unittest.main()
