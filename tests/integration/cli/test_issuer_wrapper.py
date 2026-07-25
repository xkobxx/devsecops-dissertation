from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class IssuerWrapperTests(unittest.TestCase):
    def test_legacy_issuer_generates_key_in_the_callers_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(REPOSITORY_ROOT / "scripts" / "issue_license.py"),
                    "generate-keypair",
                ],
                cwd=workspace,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue((workspace / "license_signing_key.pem").is_file())
            self.assertIn("keep this secret", completed.stdout)

    def test_issuer_accepts_an_explicit_private_key_path(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            private_key = workspace / "keys" / "trustgate.pem"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(REPOSITORY_ROOT / "scripts" / "issue_license.py"),
                    "generate-keypair",
                    "--private-key-path",
                    str(private_key),
                ],
                cwd=workspace,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(private_key.is_file())


if __name__ == "__main__":
    unittest.main()
