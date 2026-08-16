from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from tests.unit.schemas.test_documents import scanner_result
from trustgate.remediation import (
    publish_ai_remediation,
    stage_ai_patch,
    verify_ai_remediation,
)
from trustgate.scanners.models import ScannerState
from trustgate.schema import build_scan_run

from .test_ai_stage import initialized_repository, proposal_for
from .test_guidance import sql_scan_run


def clean_scan_run() -> dict[str, object]:
    return build_scan_run(
        target=".",
        findings=[],
        scanner_results=[scanner_result(ScannerState.CLEAN)],
        repository="example/service",
        ref="refs/heads/main",
        commit="a" * 40,
        trigger="push",
    )


def new_high_risk_scan_run() -> dict[str, object]:
    finding = deepcopy(sql_scan_run()["findings"][0])
    finding["finding_id"] = "finding-new-high"
    finding["fingerprint"] = "v1:sha256:fedcba9876543210"
    finding["title"] = "New high-risk vulnerability"
    return build_scan_run(
        target=".",
        findings=[finding],
        scanner_results=[scanner_result(ScannerState.FINDINGS)],
        repository="example/service",
        ref="refs/heads/main",
        commit="a" * 40,
        trigger="push",
    )


def verification_config(post_scan: dict[str, object], *, fail_unit: bool = False) -> dict[str, object]:
    success = [sys.executable, "-c", "print('ok')"]
    unit = [sys.executable, "-c", "raise SystemExit(1)"] if fail_unit else success
    encoded = base64.b64encode(json.dumps(post_scan).encode("utf-8")).decode("ascii")
    scanner = [
        sys.executable,
        "-c",
        (
            "import base64,pathlib; "
            f"pathlib.Path('reports/post.json').write_bytes(base64.b64decode({encoded!r}))"
        ),
    ]
    return {
        "schema_version": "1.0.0",
        "timeout_seconds": 30,
        "formatting": [success],
        "type_checking": [success],
        "unit_tests": [unit],
        "integration_tests": [success],
        "security_scanners": [scanner],
        "post_scan_run": "reports/post.json",
    }


class AIVerificationTests(unittest.TestCase):
    def _staged(self, parent: Path) -> tuple[dict[str, object], dict[str, object]]:
        repository = parent / "repository"
        repository.mkdir()
        initialized_repository(repository)
        proposal = proposal_for(repository)
        stage = stage_ai_patch(
            repository,
            proposal,
            worktree=parent / "ai-worktree",
            branch="codex/ai-remediation-test",
        )
        return proposal, stage

    def test_verifies_all_check_classes_original_absent_and_no_new_high_risk(self) -> None:
        with TemporaryDirectory() as directory:
            parent = Path(directory)
            proposal, stage = self._staged(parent)

            verification = verify_ai_remediation(
                stage,
                proposal,
                sql_scan_run(),
                verification_config(clean_scan_run()),
            )

            self.assertEqual(verification["status"], "verified")
            self.assertTrue(verification["verified"])
            self.assertTrue(verification["original_finding_absent"])
            self.assertEqual(verification["new_high_risk_findings"], [])
            self.assertEqual(
                set(verification["checks"]),
                {
                    "formatting",
                    "type_checking",
                    "unit_tests",
                    "integration_tests",
                    "security_scanners",
                },
            )
            self.assertTrue(
                all(result["passed"] for results in verification["checks"].values() for result in results)
            )
            self.assertIn("verified by", verification["claim"].lower())

    def test_failed_verification_blocks_completion_and_publication(self) -> None:
        with TemporaryDirectory() as directory:
            parent = Path(directory)
            proposal, stage = self._staged(parent)

            verification = verify_ai_remediation(
                stage,
                proposal,
                sql_scan_run(),
                verification_config(sql_scan_run(), fail_unit=True),
            )

            self.assertEqual(verification["status"], "verification_failed")
            self.assertFalse(verification["verified"])
            self.assertFalse(verification["original_finding_absent"])
            self.assertTrue(verification["blockers"])
            self.assertIn("not fixed", verification["claim"].lower())
            with self.assertRaisesRegex(ValueError, "verified"):
                publish_ai_remediation(
                    stage,
                    verification,
                    title="Fix SQL injection",
                    body="Verified remediation",
                )

    def test_new_high_risk_finding_blocks_verification(self) -> None:
        with TemporaryDirectory() as directory:
            parent = Path(directory)
            proposal, stage = self._staged(parent)

            verification = verify_ai_remediation(
                stage,
                proposal,
                sql_scan_run(),
                verification_config(new_high_risk_scan_run()),
            )

            self.assertEqual(verification["status"], "verification_failed")
            self.assertTrue(verification["original_finding_absent"])
            self.assertEqual(
                verification["new_high_risk_findings"][0]["fingerprint"],
                "v1:sha256:fedcba9876543210",
            )
            self.assertIn("new high-risk", " ".join(verification["blockers"]))

    def test_verified_patch_is_pushed_and_opened_only_as_draft_pr(self) -> None:
        with TemporaryDirectory() as directory:
            parent = Path(directory)
            bare = parent / "remote.git"
            bare.mkdir()
            subprocess.run(
                ["git", "init", "--bare", "-q", str(bare)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            proposal, stage = self._staged(parent)
            subprocess.run(
                ["git", "remote", "add", "origin", str(bare)],
                cwd=stage["worktree"],
                check=True,
            )
            verification = verify_ai_remediation(
                stage,
                proposal,
                sql_scan_run(),
                verification_config(clean_scan_run()),
            )
            log = parent / "gh-arguments.json"
            fake_gh = parent / "fake-gh"
            fake_gh.write_text(
                "#!/usr/bin/env python3\n"
                "import json,sys\n"
                f"open({str(log)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
                "print('https://github.example.test/example/service/pull/42')\n",
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)

            publication = publish_ai_remediation(
                stage,
                verification,
                title="Parameterize SQL query",
                body="Verified by Trust Gate.\n\nAI-generated draft.",
                gh=str(fake_gh),
            )

            self.assertEqual(publication["status"], "draft_pr_created")
            self.assertTrue(publication["verified"])
            self.assertTrue(publication["draft"])
            self.assertEqual(
                publication["pull_request_url"],
                "https://github.example.test/example/service/pull/42",
            )
            arguments = json.loads(log.read_text(encoding="utf-8"))
            self.assertIn("--draft", arguments)
            remote_sha = subprocess.run(
                [
                    "git",
                    "--git-dir",
                    str(bare),
                    "rev-parse",
                    "refs/heads/codex/ai-remediation-test",
                ],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            self.assertEqual(remote_sha, publication["commit"])


if __name__ == "__main__":
    unittest.main()
