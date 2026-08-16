from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.remediation import (
    RemediationError,
    apply_remediation_plan,
    rollback_remediation,
)


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _plan(
    path: Path,
    *,
    rule_id: str,
    framework: str,
    parameters: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "plan_id": "plan-test",
        "requests": [
            {
                "request_id": "request-1",
                "rule_id": rule_id,
                "framework": framework,
                "path": path.name,
                "expected_sha256": _digest(path.read_bytes()),
                "parameters": parameters or {},
            }
        ],
    }


class DeterministicTransformationTests(unittest.TestCase):
    def _apply(
        self,
        root: Path,
        path: Path,
        *,
        rule_id: str,
        framework: str,
        parameters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return apply_remediation_plan(
            root,
            _plan(
                path,
                rule_id=rule_id,
                framework=framework,
                parameters=parameters,
            ),
            backup_root=root / ".trustgate-backups",
        )

    def test_parameterises_supported_sqlite_f_string(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "query.py"
            source.write_text(
                "result = cursor.execute("
                'f"SELECT * FROM users WHERE id = {user_id}")\n',
                encoding="utf-8",
            )

            receipt = self._apply(
                root,
                source,
                rule_id="TG-PY-SQL-001",
                framework="python-sqlite3",
            )

            self.assertEqual(
                source.read_text(encoding="utf-8"),
                "result = cursor.execute('SELECT * FROM users WHERE id = ?', "
                "(user_id,))\n",
            )
            self.assertEqual(receipt["status"], "applied")

    def test_removes_shell_true_from_static_subprocess_argv(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "command.py"
            source.write_text(
                'result = subprocess.run("git status --short", '
                "shell=True, check=True)\n",
                encoding="utf-8",
            )

            self._apply(
                root,
                source,
                rule_id="TG-PY-SHELL-001",
                framework="python-subprocess",
            )

            self.assertEqual(
                source.read_text(encoding="utf-8"),
                "result = subprocess.run(['git', 'status', '--short'], check=True)\n",
            )

    def test_replaces_unsafe_pyyaml_load(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "config.py"
            source.write_text("config = yaml.load(payload)\n", encoding="utf-8")

            self._apply(
                root,
                source,
                rule_id="TG-PY-YAML-001",
                framework="python-pyyaml",
            )

            self.assertEqual(
                source.read_text(encoding="utf-8"),
                "config = yaml.safe_load(payload)\n",
            )

    def test_replaces_security_sensitive_weak_hash(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "digest.py"
            source.write_text(
                "digest = hashlib.sha1(token).hexdigest()\n",
                encoding="utf-8",
            )

            self._apply(
                root,
                source,
                rule_id="TG-PY-HASH-001",
                framework="python-hashlib",
                parameters={"purpose": "security"},
            )

            self.assertEqual(
                source.read_text(encoding="utf-8"),
                "digest = hashlib.sha256(token).hexdigest()\n",
            )

    def test_upgrades_hash_locked_python_dependency(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "requirements.lock"
            source.write_text(
                "requests==2.31.0 \\\n"
                f"    --hash=sha256:{'a' * 64} \\\n"
                f"    --hash=sha256:{'b' * 64}\n"
                "flask==3.1.1\n",
                encoding="utf-8",
            )

            self._apply(
                root,
                source,
                rule_id="TG-DEP-PY-001",
                framework="python-requirements",
                parameters={
                    "name": "requests",
                    "from_version": "2.31.0",
                    "to_version": "2.32.4",
                    "hashes": ["c" * 64, "d" * 64],
                },
            )

            self.assertEqual(
                source.read_text(encoding="utf-8"),
                "requests==2.32.4 \\\n"
                f"    --hash=sha256:{'c' * 64} \\\n"
                f"    --hash=sha256:{'d' * 64}\n"
                "flask==3.1.1\n",
            )

    def test_inserts_numeric_non_root_docker_user(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Dockerfile"
            source.write_text(
                "FROM python:3.13-slim\nCOPY . /app\nCMD [\"python\", \"app.py\"]\n",
                encoding="utf-8",
            )

            self._apply(
                root,
                source,
                rule_id="TG-DOCKER-USER-001",
                framework="dockerfile",
                parameters={"uid": 10001},
            )

            self.assertEqual(
                source.read_text(encoding="utf-8"),
                "FROM python:3.13-slim\nCOPY . /app\nUSER 10001\n"
                "CMD [\"python\", \"app.py\"]\n",
            )

    def test_replaces_literal_secret_with_environment_lookup(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "settings.py"
            source.write_text(
                '"""Service settings."""\n\nAPI_KEY = "exposed-value"\n',
                encoding="utf-8",
            )

            self._apply(
                root,
                source,
                rule_id="TG-PY-SECRET-001",
                framework="python-environment",
                parameters={
                    "symbol": "API_KEY",
                    "environment_variable": "SERVICE_API_KEY",
                },
            )

            self.assertEqual(
                source.read_text(encoding="utf-8"),
                '"""Service settings."""\n\nimport os\n\n'
                'API_KEY = os.environ["SERVICE_API_KEY"]\n',
            )

    def test_secret_remediation_preserves_shebang_and_encoding_cookie(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "settings.py"
            source.write_text(
                "#!/usr/bin/env python3\n"
                "# -*- coding: utf-8 -*-\n\n"
                'API_KEY = "exposed-value"\n',
                encoding="utf-8",
            )

            self._apply(
                root,
                source,
                rule_id="TG-PY-SECRET-001",
                framework="python-environment",
                parameters={
                    "symbol": "API_KEY",
                    "environment_variable": "SERVICE_API_KEY",
                },
            )

            self.assertEqual(
                source.read_text(encoding="utf-8"),
                "#!/usr/bin/env python3\n"
                "# -*- coding: utf-8 -*-\n"
                "import os\n\n"
                'API_KEY = os.environ["SERVICE_API_KEY"]\n',
            )

    def test_adds_flask_security_headers_hook(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.py"
            source.write_text(
                "from flask import Flask\n\n"
                "app = Flask(__name__)\n\n"
                '@app.get("/")\n'
                "def index():\n"
                '    return "ok"\n',
                encoding="utf-8",
            )

            self._apply(
                root,
                source,
                rule_id="TG-FLASK-HEADERS-001",
                framework="python-flask",
                parameters={"application": "app"},
            )

            content = source.read_text(encoding="utf-8")
            self.assertIn("@app.after_request", content)
            self.assertIn(
                'response.headers.setdefault("X-Content-Type-Options", "nosniff")',
                content,
            )
            self.assertIn(
                'response.headers.setdefault("X-Frame-Options", "DENY")',
                content,
            )
            self.assertIn("default-src 'self'; frame-ancestors 'none'", content)
            self.assertLess(
                content.index("@app.after_request"),
                content.index('@app.get("/")'),
            )

    def test_adds_flask_security_headers_when_assignment_is_at_eof(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.py"
            source.write_text(
                "from flask import Flask\n\napp = Flask(__name__)\n",
                encoding="utf-8",
            )

            self._apply(
                root,
                source,
                rule_id="TG-FLASK-HEADERS-001",
                framework="python-flask",
                parameters={"application": "app"},
            )

            self.assertTrue(
                source.read_text(encoding="utf-8").endswith(
                    "    return response\n"
                )
            )


class TransactionSafetyTests(unittest.TestCase):
    def test_framework_rule_does_not_modify_unsupported_file_type(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "config.txt"
            before = b"config = yaml.load(payload)\n"
            source.write_bytes(before)

            with self.assertRaisesRegex(RemediationError, "file type"):
                apply_remediation_plan(
                    root,
                    _plan(
                        source,
                        rule_id="TG-PY-YAML-001",
                        framework="python-pyyaml",
                    ),
                    backup_root=root / ".trustgate-backups",
                )

            self.assertEqual(source.read_bytes(), before)

    def test_dependency_upgrade_does_not_drop_unsupported_lock_options(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "requirements.lock"
            before = (
                "requests==2.31.0 --index-url=https://packages.example.test \\\n"
                f"    --hash=sha256:{'a' * 64}\n"
            ).encode()
            source.write_bytes(before)

            with self.assertRaisesRegex(RemediationError, "unsupported options"):
                apply_remediation_plan(
                    root,
                    _plan(
                        source,
                        rule_id="TG-DEP-PY-001",
                        framework="python-requirements",
                        parameters={
                            "name": "requests",
                            "from_version": "2.31.0",
                            "to_version": "2.32.4",
                            "hashes": ["b" * 64],
                        },
                    ),
                    backup_root=root / ".trustgate-backups",
                )

            self.assertEqual(source.read_bytes(), before)

    def test_unsupported_shell_syntax_is_not_modified(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "command.py"
            before = b'subprocess.run("cat input | grep secret", shell=True)\n'
            source.write_bytes(before)
            backup_root = root / ".trustgate-backups"

            with self.assertRaisesRegex(RemediationError, "shell syntax"):
                apply_remediation_plan(
                    root,
                    _plan(
                        source,
                        rule_id="TG-PY-SHELL-001",
                        framework="python-subprocess",
                    ),
                    backup_root=backup_root,
                )

            self.assertEqual(source.read_bytes(), before)
            self.assertFalse(backup_root.exists())

    def test_shell_environment_assignment_is_not_treated_as_executable(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "command.py"
            before = b'subprocess.run("MODE=safe python app.py", shell=True)\n'
            source.write_bytes(before)

            with self.assertRaisesRegex(RemediationError, "shell syntax"):
                apply_remediation_plan(
                    root,
                    _plan(
                        source,
                        rule_id="TG-PY-SHELL-001",
                        framework="python-subprocess",
                    ),
                    backup_root=root / ".trustgate-backups",
                )

            self.assertEqual(source.read_bytes(), before)

    def test_failed_batch_leaves_every_source_file_unchanged(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            yaml_source = root / "config.py"
            shell_source = root / "command.py"
            yaml_before = b"config = yaml.load(payload)\n"
            shell_before = b'subprocess.run("echo ok > output", shell=True)\n'
            yaml_source.write_bytes(yaml_before)
            shell_source.write_bytes(shell_before)
            plan = {
                "schema_version": "1.0.0",
                "plan_id": "plan-batch",
                "requests": [
                    {
                        "request_id": "yaml",
                        "rule_id": "TG-PY-YAML-001",
                        "framework": "python-pyyaml",
                        "path": yaml_source.name,
                        "expected_sha256": _digest(yaml_before),
                        "parameters": {},
                    },
                    {
                        "request_id": "shell",
                        "rule_id": "TG-PY-SHELL-001",
                        "framework": "python-subprocess",
                        "path": shell_source.name,
                        "expected_sha256": _digest(shell_before),
                        "parameters": {},
                    },
                ],
            }

            with self.assertRaisesRegex(RemediationError, "shell syntax"):
                apply_remediation_plan(
                    root,
                    plan,
                    backup_root=root / ".trustgate-backups",
                )

            self.assertEqual(yaml_source.read_bytes(), yaml_before)
            self.assertEqual(shell_source.read_bytes(), shell_before)

    def test_verified_rollback_restores_exact_original_bytes(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "config.py"
            before = b"config = yaml.load(payload)\r\n"
            source.write_bytes(before)
            backup_root = root / ".trustgate-backups"
            receipt = apply_remediation_plan(
                root,
                _plan(
                    source,
                    rule_id="TG-PY-YAML-001",
                    framework="python-pyyaml",
                ),
                backup_root=backup_root,
            )

            rollback = rollback_remediation(
                root,
                receipt,
                backup_root=backup_root,
            )

            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(rollback["status"], "rolled_back")
            self.assertEqual(rollback["transaction_id"], receipt["transaction_id"])
            change = receipt["changes"][0]
            self.assertTrue(change["risk_notes"])
            self.assertTrue(change["tests"])
            self.assertIn("backup", change)

    def test_rejects_symlinked_transaction_backup_directory(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "config.py"
            before = b"config = yaml.load(payload)\n"
            source.write_bytes(before)
            backup_root = root / ".trustgate-backups"
            plan = _plan(
                source,
                rule_id="TG-PY-YAML-001",
                framework="python-pyyaml",
            )
            receipt = apply_remediation_plan(
                root,
                plan,
                backup_root=backup_root,
            )
            rollback_remediation(root, receipt, backup_root=backup_root)
            transaction = backup_root / receipt["transaction_id"]
            transaction.rename(root / "preserved-backup")
            outside = root / "outside"
            outside.mkdir()
            transaction.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(RemediationError, "backup transaction"):
                apply_remediation_plan(
                    root,
                    plan,
                    backup_root=backup_root,
                )

            self.assertEqual(list(outside.iterdir()), [])
            self.assertEqual(source.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
