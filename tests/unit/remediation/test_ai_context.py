from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.remediation import AIRemediationError, prepare_ai_context

from .test_guidance import sql_scan_run


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def context_request(
    scan_run: dict[str, object],
    *,
    provider: dict[str, object] | None = None,
    redaction: bool = True,
) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "request_id": "ai-request-1",
        "finding_fingerprint": "v1:sha256:0123456789abcdef",
        "scan_run_digest": _digest(scan_run),
        "remediation_rule_id": "TG-PY-SQL-001",
        "framework": "python-sqlite3",
        "provider": provider
        or {"mode": "local", "command": ["local-model", "--json"]},
        "context": [{"path": "src/app.py", "start_line": 1, "end_line": 4}],
        "redaction": {"enabled": redaction},
    }


class AIContextTests(unittest.TestCase):
    def test_prepares_redacted_local_context_without_contacting_model(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src/app.py"
            source.parent.mkdir(parents=True)
            source.write_text(
                'API_KEY = "sk-live-secret"\n'
                "def search(user_id):\n"
                '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
                "    return cursor.execute(query)\n",
                encoding="utf-8",
            )
            scan_run = sql_scan_run()

            bundle = prepare_ai_context(root, scan_run, context_request(scan_run))

            self.assertEqual(bundle["status"], "awaiting_opt_in")
            self.assertFalse(bundle["disclosure"]["leaves_runner"])
            self.assertEqual(
                bundle["disclosure"]["destination"],
                "local process: local-model",
            )
            self.assertTrue(bundle["disclosure"]["acknowledgement_required"])
            self.assertRegex(
                bundle["disclosure"]["context_digest"],
                r"^sha256:[0-9a-f]{64}$",
            )
            manifest = bundle["context_manifest"][0]
            self.assertEqual(manifest["path"], "src/app.py")
            self.assertEqual(manifest["start_line"], 1)
            self.assertEqual(manifest["end_line"], 4)
            self.assertEqual(manifest["redactions"], 1)
            self.assertNotEqual(
                manifest["original_sha256"], manifest["transmitted_sha256"]
            )
            content = bundle["payload"]["files"][0]["content"]
            self.assertNotIn("sk-live-secret", content)
            self.assertIn('API_KEY = "[REDACTED]"', content)
            self.assertIn("cursor.execute", content)
            self.assertEqual(
                bundle["payload"]["finding"]["fingerprint"],
                "v1:sha256:0123456789abcdef",
            )
            self.assertNotIn("description", bundle["payload"]["finding"])

    def test_remote_disclosure_names_destination_and_context_leaves_runner(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src/app.py"
            source.parent.mkdir(parents=True)
            source.write_text("cursor.execute(query)\n", encoding="utf-8")
            scan_run = sql_scan_run()
            request = context_request(
                scan_run,
                provider={
                    "mode": "remote",
                    "endpoint": "https://models.example.test/v1/remediate",
                    "model": "secure-code-model",
                    "authorization_env": "MODEL_API_TOKEN",
                },
            )
            request["context"][0]["end_line"] = 1

            bundle = prepare_ai_context(root, scan_run, request)

            self.assertTrue(bundle["disclosure"]["leaves_runner"])
            self.assertEqual(
                bundle["disclosure"]["destination"],
                "https://models.example.test/v1/remediate",
            )
            self.assertEqual(bundle["provider"]["model"], "secure-code-model")
            self.assertNotIn("authorization_env", bundle["payload"])

    def test_rejects_stale_binding_path_escape_and_missing_finding_file(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src/app.py"
            source.parent.mkdir(parents=True)
            source.write_text("cursor.execute(query)\n", encoding="utf-8")
            scan_run = sql_scan_run()
            stale = context_request(scan_run)
            stale["scan_run_digest"] = "sha256:" + "0" * 64

            with self.assertRaisesRegex(AIRemediationError, "scan-run content"):
                prepare_ai_context(root, scan_run, stale)

            escaping = context_request(scan_run)
            escaping["context"][0]["path"] = "../outside.py"
            with self.assertRaisesRegex(AIRemediationError, "within repository"):
                prepare_ai_context(root, scan_run, escaping)

            unrelated = context_request(scan_run)
            unrelated["context"][0]["path"] = "src/helper.py"
            (root / "src/helper.py").write_text("value = 1\n", encoding="utf-8")
            unrelated["context"][0]["end_line"] = 1
            with self.assertRaisesRegex(AIRemediationError, "finding file"):
                prepare_ai_context(root, scan_run, unrelated)

    def test_rejects_unbounded_context(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src/app.py"
            source.parent.mkdir(parents=True)
            source.write_text("line\n" * 500, encoding="utf-8")
            scan_run = sql_scan_run()
            request = context_request(scan_run)
            request["context"][0]["end_line"] = 500

            with self.assertRaisesRegex(AIRemediationError, "at most 400 lines"):
                prepare_ai_context(root, scan_run, request)


if __name__ == "__main__":
    unittest.main()
