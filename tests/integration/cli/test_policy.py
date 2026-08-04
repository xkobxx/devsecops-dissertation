from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.unit.decisions.test_persistence import scan_run


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


BASE_POLICY = """\
schema_version: 1.0.0
version: 1
policy_id: organisation-base
policy_version: 1.0.0
default_action: investigate
policies:
  - name: monitor-low
    action: monitor
    when:
      severity: low
"""


SERVICE_POLICY = """\
schema_version: 1.0.0
version: 1
policy_id: service-policy
policy_version: 2.0.0
extends:
  - path: base.policy.yml
    policy_id: organisation-base
    policy_version: 1.0.0
policies:
  - name: block-production-high
    action: block
    when:
      all:
        - severity: high
        - environment: production
"""


class PolicyCliTests(unittest.TestCase):
    def run_cli(self, workspace: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "trustgate", "policy", *arguments],
            cwd=workspace,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_policy_commands_validate_simulate_explain_and_test_saved_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "base.policy.yml").write_text(BASE_POLICY, encoding="utf-8")
            policy = workspace / "service.policy.yml"
            policy.write_text(SERVICE_POLICY, encoding="utf-8")
            findings = workspace / "scan.json"
            findings.write_text(json.dumps(scan_run()), encoding="utf-8")
            context = workspace / "context.json"
            context.write_text(
                json.dumps({"shared": {"environment": "production"}}),
                encoding="utf-8",
            )
            expectations = workspace / "expectations.json"
            expectations.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "tests": [
                            {
                                "name": "production high blocks",
                                "finding_id": "finding-001",
                                "expected_outcome": "BLOCK_IMMEDIATELY",
                                "expected_policy": "block-production-high",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            validated = self.run_cli(
                workspace,
                "validate",
                "--policy",
                str(policy),
                "--repository",
                "example/trustgate",
            )
            simulated = self.run_cli(
                workspace,
                "simulate",
                "--policy",
                str(policy),
                "--input",
                str(findings),
                "--runtime-context",
                str(context),
            )
            explained = self.run_cli(
                workspace,
                "explain",
                "--policy",
                str(policy),
                "--input",
                str(findings),
                "--runtime-context",
                str(context),
                "--finding-id",
                "finding-001",
            )
            tested = self.run_cli(
                workspace,
                "test",
                "--policy",
                str(policy),
                "--input",
                str(findings),
                "--runtime-context",
                str(context),
                "--expectations",
                str(expectations),
            )

            self.assertEqual(validated.returncode, 0, validated.stderr)
            self.assertIn("service-policy@2.0.0 is valid", validated.stdout)
            self.assertEqual(simulated.returncode, 0, simulated.stderr)
            self.assertEqual(
                json.loads(simulated.stdout)["evaluations"][0]["outcome"],
                "BLOCK_IMMEDIATELY",
            )
            self.assertEqual(explained.returncode, 0, explained.stderr)
            self.assertIn("block-production-high", explained.stdout)
            self.assertIn("finding.normalised_severity", explained.stdout)
            self.assertEqual(tested.returncode, 0, tested.stderr)
            self.assertIn("1 passed, 0 failed", tested.stdout)

    def test_invalid_policy_fails_clearly_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            policy = workspace / "invalid.policy.yml"
            policy.write_text(
                SERVICE_POLICY.replace("severity: high", "made_up_risk: true"),
                encoding="utf-8",
            )

            completed = self.run_cli(
                workspace,
                "validate",
                "--policy",
                str(policy),
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("Policy error:", completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
