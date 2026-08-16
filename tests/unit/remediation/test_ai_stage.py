from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from trustgate.remediation import (
    AIRemediationError,
    prepare_ai_context,
    request_ai_patch,
    stage_ai_patch,
)

from .test_ai_context import context_request
from .test_ai_proposal import _PATCH
from .test_guidance import sql_scan_run


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def initialized_repository(root: Path) -> None:
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "tests@trustgate.local")
    _git(root, "config", "user.name", "Trust Gate Tests")
    source = root / "src/app.py"
    source.parent.mkdir(parents=True)
    source.write_text("cursor.execute(query)\n", encoding="utf-8")
    _git(root, "add", "src/app.py")
    _git(root, "commit", "-q", "-m", "initial")


def proposal_for(root: Path, patch: str = _PATCH) -> dict[str, object]:
    scan_run = sql_scan_run()
    response = json.dumps({"summary": "Parameterize query", "patch": patch})
    script = f"import sys; sys.stdin.read(); print({response!r})"
    request = context_request(
        scan_run,
        provider={"mode": "local", "command": [sys.executable, "-c", script]},
    )
    request["context"][0]["end_line"] = 1
    bundle = prepare_ai_context(root, scan_run, request)
    return request_ai_patch(
        bundle,
        opt_in=True,
        acknowledged_context_digest=bundle["disclosure"]["context_digest"],
    )


class AIStageTests(unittest.TestCase):
    def test_applies_patch_only_in_new_isolated_worktree_branch(self) -> None:
        with TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = parent / "repository"
            repository.mkdir()
            initialized_repository(repository)
            proposal = proposal_for(repository)
            worktree = parent / "ai-worktree"

            stage = stage_ai_patch(
                repository,
                proposal,
                worktree=worktree,
                branch="codex/ai-remediation-test",
            )

            self.assertEqual(stage["status"], "unverified")
            self.assertFalse(stage["verified"])
            self.assertEqual(stage["changed_files"], ["src/app.py"])
            self.assertEqual(stage["branch"], "codex/ai-remediation-test")
            self.assertEqual(_git(repository, "branch", "--show-current"), "main")
            self.assertEqual(
                (repository / "src/app.py").read_text(encoding="utf-8"),
                "cursor.execute(query)\n",
            )
            self.assertIn("cursor.execute(\"SELECT", (worktree / "src/app.py").read_text())
            self.assertIn("not verified", stage["claim"].lower())

    def test_rejects_dirty_repository_and_patch_outside_allowed_paths(self) -> None:
        with TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = parent / "repository"
            repository.mkdir()
            initialized_repository(repository)
            proposal = proposal_for(repository)
            (repository / "src/app.py").write_text("dirty\n", encoding="utf-8")

            with self.assertRaisesRegex(AIRemediationError, "clean"):
                stage_ai_patch(
                    repository,
                    proposal,
                    worktree=parent / "dirty-worktree",
                    branch="codex/dirty",
                )

        malicious = _PATCH.replace("src/app.py", "src/other.py")
        with TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = parent / "repository"
            repository.mkdir()
            initialized_repository(repository)
            proposal = proposal_for(repository, malicious)

            with self.assertRaisesRegex(AIRemediationError, "allowed context paths"):
                stage_ai_patch(
                    repository,
                    proposal,
                    worktree=parent / "unsafe-worktree",
                    branch="codex/unsafe",
                )
            self.assertFalse((parent / "unsafe-worktree").exists())


if __name__ == "__main__":
    unittest.main()
