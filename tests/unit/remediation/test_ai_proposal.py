from __future__ import annotations

import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch as mock_patch

from trustgate.remediation import (
    AIRemediationError,
    prepare_ai_context,
    request_ai_patch,
)

from .test_ai_context import context_request
from .test_guidance import sql_scan_run


_PATCH = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1 +1 @@
-cursor.execute(query)
+cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""


def _bundle(
    root: Path,
    *,
    provider: dict[str, object] | None = None,
    redaction: bool = True,
) -> dict[str, object]:
    source = root / "src/app.py"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("cursor.execute(query)\n", encoding="utf-8")
    scan_run = sql_scan_run()
    request = context_request(scan_run, provider=provider, redaction=redaction)
    request["context"][0]["end_line"] = 1
    return prepare_ai_context(root, scan_run, request)


class AIProposalTests(unittest.TestCase):
    def test_requires_explicit_opt_in_and_exact_context_acknowledgement(self) -> None:
        with TemporaryDirectory() as directory:
            bundle = _bundle(Path(directory))

            with self.assertRaisesRegex(AIRemediationError, "explicit opt-in"):
                request_ai_patch(
                    bundle,
                    opt_in=False,
                    acknowledged_context_digest=bundle["disclosure"]["context_digest"],
                )
            with self.assertRaisesRegex(AIRemediationError, "context digest"):
                request_ai_patch(
                    bundle,
                    opt_in=True,
                    acknowledged_context_digest="sha256:" + "0" * 64,
                )

    def test_invokes_local_model_and_marks_patch_unverified(self) -> None:
        response = json.dumps({"summary": "Parameterize the query", "patch": _PATCH})
        script = (
            "import json,sys; payload=json.load(sys.stdin); "
            "assert payload['finding']['fingerprint']; "
            f"json.dump({response!r}, sys.stdout)"
        )
        # The script above writes a JSON string; use a compact script that writes the
        # response object itself so the transport contract is exercised directly.
        script = (
            "import json,sys; payload=json.load(sys.stdin); "
            "assert payload['finding']['fingerprint']; "
            f"json.dump(json.loads({response!r}), sys.stdout)"
        )
        with TemporaryDirectory() as directory:
            bundle = _bundle(
                Path(directory),
                provider={"mode": "local", "command": [sys.executable, "-c", script]},
            )

            proposal = request_ai_patch(
                bundle,
                opt_in=True,
                acknowledged_context_digest=bundle["disclosure"]["context_digest"],
            )

            self.assertEqual(proposal["status"], "unverified")
            self.assertFalse(proposal["verified"])
            self.assertTrue(proposal["ai_generated"])
            self.assertEqual(proposal["allowed_paths"], ["src/app.py"])
            self.assertEqual(proposal["patch"], _PATCH)
            self.assertIn("not verified", proposal["claim"].lower())
            self.assertRegex(proposal["proposal_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_remote_context_requires_separate_permission_and_redaction(self) -> None:
        provider = {
            "mode": "remote",
            "endpoint": "https://models.example.test/v1/remediate",
            "model": "secure-code-model",
            "authorization_env": "MODEL_API_TOKEN",
        }
        with TemporaryDirectory() as directory:
            bundle = _bundle(Path(directory), provider=provider)
            digest = bundle["disclosure"]["context_digest"]

            with self.assertRaisesRegex(AIRemediationError, "remote context"):
                request_ai_patch(
                    bundle,
                    opt_in=True,
                    acknowledged_context_digest=digest,
                    environment={"MODEL_API_TOKEN": "secret"},
                )

            bundle = _bundle(Path(directory), provider=provider, redaction=False)
            digest = bundle["disclosure"]["context_digest"]
            with self.assertRaisesRegex(AIRemediationError, "redaction"):
                request_ai_patch(
                    bundle,
                    opt_in=True,
                    acknowledged_context_digest=digest,
                    allow_remote_context=True,
                    environment={"MODEL_API_TOKEN": "secret"},
                )

    def test_invokes_separately_authorized_remote_model_without_exposing_token(self) -> None:
        provider = {
            "mode": "remote",
            "endpoint": "https://models.example.test/v1/remediate",
            "model": "secure-code-model",
            "authorization_env": "MODEL_API_TOKEN",
        }
        response = json.dumps(
            {"summary": "Parameterize the query", "patch": _PATCH}
        ).encode()
        captured: dict[str, object] = {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit: int) -> bytes:
                captured["limit"] = limit
                return response

        def open_request(request, *, timeout: int):
            captured["request"] = request
            captured["timeout"] = timeout
            return Response()

        with TemporaryDirectory() as directory:
            bundle = _bundle(Path(directory), provider=provider)
            with mock_patch("trustgate.remediation.ai.urlopen", open_request):
                proposal = request_ai_patch(
                    bundle,
                    opt_in=True,
                    acknowledged_context_digest=bundle["disclosure"]["context_digest"],
                    allow_remote_context=True,
                    environment={"MODEL_API_TOKEN": "remote-secret-token"},
                    timeout_seconds=45,
                )

        request = captured["request"]
        self.assertEqual(
            request.get_header("Authorization"), "Bearer remote-secret-token"
        )
        transmitted = json.loads(request.data.decode("utf-8"))
        self.assertEqual(transmitted["model"], "secure-code-model")
        self.assertEqual(
            transmitted["input"]["finding"]["fingerprint"],
            proposal["finding_fingerprint"],
        )
        self.assertNotIn("remote-secret-token", json.dumps(proposal))
        self.assertEqual(proposal["provider_mode"], "remote")

    def test_rejects_tampered_bundle_and_non_diff_model_output(self) -> None:
        with TemporaryDirectory() as directory:
            bundle = _bundle(Path(directory))
            bundle["allowed_paths"] = ["src/other.py"]
            with self.assertRaisesRegex(AIRemediationError, "integrity"):
                request_ai_patch(
                    bundle,
                    opt_in=True,
                    acknowledged_context_digest=bundle["disclosure"]["context_digest"],
                )

        response = json.dumps({"summary": "Unsafe output", "patch": "replace it"})
        script = f"import sys; sys.stdin.read(); print({response!r})"
        with TemporaryDirectory() as directory:
            bundle = _bundle(
                Path(directory),
                provider={"mode": "local", "command": [sys.executable, "-c", script]},
            )
            with self.assertRaisesRegex(AIRemediationError, "unified diff"):
                request_ai_patch(
                    bundle,
                    opt_in=True,
                    acknowledged_context_digest=bundle["disclosure"]["context_digest"],
                )


if __name__ == "__main__":
    unittest.main()
