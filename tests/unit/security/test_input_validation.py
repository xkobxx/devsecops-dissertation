import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
VALIDATOR = REPOSITORY_ROOT / "scripts" / "validate_inputs.py"


class ActionInputValidationTests(unittest.TestCase):
    def _run_action(
        self,
        workspace: Path,
        **overrides: str,
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        output = workspace / "github-output.txt"
        environment = os.environ.copy()
        environment.update(
            {
                "GITHUB_WORKSPACE": str(workspace),
                "GITHUB_OUTPUT": str(output),
                "TRUSTGATE_TARGET": ".",
                "TRUSTGATE_FAIL_ON": "high",
                "TRUSTGATE_SCANNER_FAILURE_POLICY": "fail",
                "TRUSTGATE_SEVERITY_BASIS": "normalised",
                "TRUSTGATE_OPTIONAL_SCANNERS": "",
                "TRUSTGATE_SCANNER_TIMEOUT": "300",
                "TRUSTGATE_REDACT_SENSITIVE_CONTENT": "false",
                "TRUSTGATE_ARTIFACT_NAME": "security-dashboard",
                "TRUSTGATE_LICENSE_KEY": "",
                "TRUSTGATE_DAST_ENABLED": "false",
                "TRUSTGATE_DAST_URL": "",
                "TRUSTGATE_DAST_MODE": "baseline",
                "TRUSTGATE_DAST_SCAN_MODE": "safe",
                "TRUSTGATE_DAST_ENVIRONMENT": "preview",
                "TRUSTGATE_DAST_SCOPE_HOSTS": "",
                "TRUSTGATE_DAST_RATE_LIMIT": "5",
                "TRUSTGATE_DAST_REQUEST_LIMIT": "500",
                "TRUSTGATE_DAST_MAX_DURATION": "300",
                "TRUSTGATE_DAST_OPENAPI_PATH": "",
                "TRUSTGATE_DAST_AUTH_TYPE": "none",
                "TRUSTGATE_DAST_AUTH_HEADER": "Authorization",
                "TRUSTGATE_DAST_AUTH_SECRET": "",
                "TRUSTGATE_DAST_PUBLIC_ACK": "false",
                "TRUSTGATE_DAST_ACTIVE_ACK": "false",
                "TRUSTGATE_DAST_PRODUCTION_ACK": "false",
                "TRUSTGATE_DAST_ALLOW_PRIVATE": "false",
            }
        )
        environment.update(overrides)
        completed = subprocess.run(
            [sys.executable, str(VALIDATOR), "action"],
            cwd=workspace,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        return completed, output

    def _run_dast(
        self,
        workspace: Path,
        *,
        url: str,
        rules_file: str,
        allow_private: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "GITHUB_WORKSPACE": str(workspace),
                "TRUSTGATE_DAST_URL": url,
                "TRUSTGATE_DAST_RULES_FILE": rules_file,
            }
        )
        command = [sys.executable, str(VALIDATOR), "dast"]
        if allow_private:
            command.append("--allow-private")
        return subprocess.run(
            command,
            cwd=workspace,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_valid_action_inputs_are_normalised_for_later_steps(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "src").mkdir()

            completed, output = self._run_action(
                workspace,
                TRUSTGATE_TARGET="src/.",
                TRUSTGATE_OPTIONAL_SCANNERS=" semgrep, trivy ",
                TRUSTGATE_SCANNER_TIMEOUT="300.0",
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                output.read_text(encoding="utf-8").splitlines(),
                [
                    "target=src",
                    "fail-on=high",
                    "scanner-failure-policy=fail",
                    "severity-basis=normalised",
                    "optional-scanners=semgrep,trivy",
                    "scanner-timeout-seconds=300",
                    "redact-sensitive-content=false",
                    "artifact-name=security-dashboard",
                    "dast-enabled=false",
                ],
            )

    def test_enabled_dast_inputs_are_validated_without_exporting_secret(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            secret = "action-dast-super-secret"

            completed, output = self._run_action(
                workspace,
                TRUSTGATE_DAST_ENABLED="true",
                TRUSTGATE_DAST_URL="https://preview.example.test",
                TRUSTGATE_DAST_SCOPE_HOSTS="preview.example.test",
                TRUSTGATE_DAST_AUTH_TYPE="bearer",
                TRUSTGATE_DAST_AUTH_SECRET=secret,
                TRUSTGATE_DAST_PUBLIC_ACK="true",
            )

            values = output.read_text()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("dast-enabled=true", values)
        self.assertIn("dast-target-url=https://preview.example.test", values)
        self.assertIn("dast-auth-type=bearer", values)
        self.assertNotIn(secret, values)

    def test_unsafe_dast_action_configuration_fails_before_execution(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            base = {
                "TRUSTGATE_DAST_ENABLED": "true",
                "TRUSTGATE_DAST_URL": "https://preview.example.test",
                "TRUSTGATE_DAST_SCOPE_HOSTS": "preview.example.test",
                "TRUSTGATE_DAST_PUBLIC_ACK": "true",
            }
            cases = (
                {"TRUSTGATE_DAST_SCOPE_HOSTS": "other.example.test"},
                {
                    "TRUSTGATE_DAST_SCAN_MODE": "active",
                    "TRUSTGATE_DAST_ACTIVE_ACK": "false",
                },
                {"TRUSTGATE_DAST_PUBLIC_ACK": "false"},
                {
                    "TRUSTGATE_DAST_ENVIRONMENT": "production",
                    "TRUSTGATE_DAST_PRODUCTION_ACK": "false",
                },
            )
            for overrides in cases:
                with self.subTest(overrides=overrides):
                    completed, _ = self._run_action(
                        workspace, **(base | overrides)
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("dast", completed.stderr.lower())

    def test_target_cannot_escape_the_workspace(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (workspace / "escape").symlink_to(outside, target_is_directory=True)

            for target in ("../outside", str(outside), "escape"):
                with self.subTest(target=target):
                    completed, _ = self._run_action(
                        workspace,
                        TRUSTGATE_TARGET=target,
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("workspace", completed.stderr.lower())

    def test_shell_payload_is_rejected_even_when_that_path_exists(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            payload = "$(touch injected);safe"
            (workspace / payload).mkdir()

            completed, _ = self._run_action(
                workspace,
                TRUSTGATE_TARGET=payload,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("unsafe", completed.stderr.lower())
            self.assertFalse((workspace / "injected").exists())

    def test_policy_inputs_accept_only_documented_values(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            cases = (
                {"TRUSTGATE_FAIL_ON": "high;echo injected"},
                {"TRUSTGATE_SCANNER_FAILURE_POLICY": "permit"},
                {"TRUSTGATE_SEVERITY_BASIS": "derived"},
                {"TRUSTGATE_OPTIONAL_SCANNERS": "bandit,unknown"},
                {"TRUSTGATE_SCANNER_TIMEOUT": "nan"},
                {"TRUSTGATE_SCANNER_TIMEOUT": "3601"},
                {"TRUSTGATE_REDACT_SENSITIVE_CONTENT": "yes"},
            )

            for overrides in cases:
                with self.subTest(overrides=overrides):
                    completed, _ = self._run_action(workspace, **overrides)
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("invalid", completed.stderr.lower())

    def test_license_input_rejects_control_characters_and_excessive_size(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)

            for license_key in ("abc\ndef", "a" * 8193):
                with self.subTest(length=len(license_key)):
                    completed, _ = self._run_action(
                        workspace,
                        TRUSTGATE_LICENSE_KEY=license_key,
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("licence", completed.stderr.lower())

    def test_artifact_name_is_restricted_to_a_safe_portable_form(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)

            for name in ("../report", "bad/name", "report\nsecond", "-report"):
                with self.subTest(name=name):
                    completed, _ = self._run_action(
                        workspace,
                        TRUSTGATE_ARTIFACT_NAME=name,
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("artifact", completed.stderr.lower())

    def test_dast_url_rejects_non_http_credentials_and_private_targets(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "rules.tsv").touch()

            for url in (
                "file:///etc/passwd",
                "javascript:alert(1)",
                "https://user:password@example.com",
                "https://exa mple.com",
                "http://169.254.169.254/latest/meta-data",
                "http://localhost:5000",
            ):
                with self.subTest(url=url):
                    completed = self._run_dast(
                        workspace,
                        url=url,
                        rules_file="rules.tsv",
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("url", completed.stderr.lower())

    def test_dast_rules_file_must_be_a_workspace_file(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            outside = root / "outside.tsv"
            outside.touch()

            completed = self._run_dast(
                workspace,
                url="http://localhost:5000",
                rules_file="../outside.tsv",
                allow_private=True,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("workspace", completed.stderr.lower())

    def test_explicit_private_dast_mode_accepts_the_local_research_target(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "rules.tsv").touch()

            completed = self._run_dast(
                workspace,
                url="http://localhost:5000",
                rules_file="rules.tsv",
                allow_private=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
