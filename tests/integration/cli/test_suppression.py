from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.unit.schemas.test_schema_contracts import valid_finding


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
POLICY_DIGEST = "sha256:" + "a" * 64


class SuppressionCliTests(unittest.TestCase):
    def run_cli(self, workspace: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "trustgate", "suppression", *arguments],
            cwd=workspace,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_create_lint_apply_and_expiry_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            finding_path = workspace / "finding.json"
            finding_path.write_text(json.dumps(valid_finding()), encoding="utf-8")
            scope = workspace / "scope.json"
            scope.write_text(
                json.dumps(
                    {
                        "branches": ["main"],
                        "paths": ["src/**"],
                        "environments": ["production"],
                    }
                ),
                encoding="utf-8",
            )
            approval = workspace / "approval.json"
            approval.write_text(
                json.dumps(
                    {
                        "actor": "user:security@example.test",
                        "timestamp": "2026-08-03T11:59:00Z",
                        "reason": "Approved for seven days.",
                    }
                ),
                encoding="utf-8",
            )
            evidence = workspace / "evidence.json"
            evidence.write_text(
                json.dumps(
                    [
                        {
                            "kind": "ticket",
                            "reference": "SEC-47",
                            "summary": "Compensating control reviewed.",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            suppression = workspace / "suppression.json"
            suppressed = workspace / "suppressed.json"
            reopened = workspace / "reopened.json"

            created = self.run_cli(
                workspace,
                "create",
                "--input",
                str(finding_path),
                "--output",
                str(suppression),
                "--repository",
                "example/service",
                "--reason",
                "Temporary compensating control.",
                "--author",
                "user:developer@example.test",
                "--created-at",
                "2026-08-03T12:00:00Z",
                "--expires-at",
                "2026-08-10T12:00:00Z",
                "--scope",
                str(scope),
                "--approval",
                str(approval),
                "--evidence",
                str(evidence),
                "--policy-digest",
                POLICY_DIGEST,
            )
            linted = self.run_cli(
                workspace,
                "lint",
                "--input",
                str(suppression),
                "--evaluated-at",
                "2026-08-03T12:00:00Z",
            )
            applied = self.run_cli(
                workspace,
                "apply",
                "--finding",
                str(finding_path),
                "--suppression",
                str(suppression),
                "--output",
                str(suppressed),
                "--repository",
                "example/service",
                "--ref",
                "main",
                "--environment",
                "production",
                "--changed-at",
                "2026-08-03T12:00:00Z",
            )
            revalidated = self.run_cli(
                workspace,
                "revalidate",
                "--finding",
                str(suppressed),
                "--suppression",
                str(suppression),
                "--output",
                str(reopened),
                "--repository",
                "example/service",
                "--ref",
                "main",
                "--environment",
                "production",
                "--policy-digest",
                POLICY_DIGEST,
                "--evaluated-at",
                "2026-08-10T12:00:00Z",
            )

            self.assertEqual(created.returncode, 0, created.stderr)
            self.assertEqual(linted.returncode, 0, linted.stderr)
            self.assertIn("SUPPRESSION_EXPIRING", linted.stdout)
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertEqual(
                json.loads(suppressed.read_text(encoding="utf-8"))["status"],
                "suppressed",
            )
            self.assertEqual(revalidated.returncode, 1, revalidated.stderr)
            self.assertIn("reopened=true", revalidated.stdout)
            self.assertEqual(
                json.loads(reopened.read_text(encoding="utf-8"))["status"],
                "open",
            )


if __name__ == "__main__":
    unittest.main()
