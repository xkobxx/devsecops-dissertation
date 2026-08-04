from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

try:
    from trustgate.dast.execution import build_zap_container_command
except ImportError:
    build_zap_container_command = None

from trustgate.dast import DastConfigurationError


class DastExecutionTests(unittest.TestCase):
    def test_container_execution_requires_an_immutable_image(self) -> None:
        self.assertIsNotNone(build_zap_container_command)
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            with self.assertRaisesRegex(DastConfigurationError, "digest"):
                build_zap_container_command(
                    "ghcr.io/zaproxy/zaproxy:stable", workspace=workspace
                )

    def test_container_command_mounts_workspace_and_forwards_secret_by_name(self) -> None:
        self.assertIsNotNone(build_zap_container_command)
        digest = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory).resolve()
            command = build_zap_container_command(
                f"ghcr.io/zaproxy/zaproxy@{digest}",
                workspace=workspace,
                auth_secret_environment="TRUSTGATE_DAST_AUTH_SECRET",
            )

        self.assertEqual(command[:3], ("docker", "run", "--rm"))
        self.assertIn(f"{workspace}:/zap/wrk:rw", command)
        self.assertIn("TRUSTGATE_DAST_AUTH_SECRET", command)
        self.assertFalse(any("phase-nine-secret" in value for value in command))


if __name__ == "__main__":
    unittest.main()
