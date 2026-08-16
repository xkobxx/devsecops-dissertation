from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

from trustgate.cli import main as cli_main

from .test_guidance import guidance_request, sql_scan_run
from .test_ai_context import context_request
from .test_ai_proposal import _PATCH


class RemediationCliTests(unittest.TestCase):
    def test_cli_previews_context_and_requires_explicit_ai_opt_in(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src/app.py"
            source.parent.mkdir(parents=True)
            source.write_text("cursor.execute(query)\n", encoding="utf-8")
            scan_run = sql_scan_run()
            response = json.dumps({"summary": "Parameterize", "patch": _PATCH})
            script = f"import sys; sys.stdin.read(); print({response!r})"
            request = context_request(
                scan_run,
                provider={"mode": "local", "command": [sys.executable, "-c", script]},
            )
            request["context"][0]["end_line"] = 1
            scan = root / "scan.json"
            request_path = root / "request.json"
            context = root / "context.json"
            proposal = root / "proposal.json"
            scan.write_text(json.dumps(scan_run), encoding="utf-8")
            request_path.write_text(json.dumps(request), encoding="utf-8")

            self.assertEqual(
                cli_main(
                    [
                        "remediate",
                        "ai-context",
                        "--root",
                        str(root),
                        "--input",
                        str(scan),
                        "--request",
                        str(request_path),
                        "--output",
                        str(context),
                    ]
                ),
                0,
            )
            bundle = json.loads(context.read_text(encoding="utf-8"))
            propose_args = [
                "remediate",
                "ai-propose",
                "--context",
                str(context),
                "--acknowledge-context-digest",
                bundle["disclosure"]["context_digest"],
                "--output",
                str(proposal),
            ]
            self.assertEqual(cli_main(propose_args), 2)
            self.assertFalse(proposal.exists())
            propose_args.append("--opt-in-ai-remediation")
            self.assertEqual(cli_main(propose_args), 0)
            self.assertEqual(
                json.loads(proposal.read_text(encoding="utf-8"))["status"],
                "unverified",
            )

    def test_cli_generates_versioned_guidance_report(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            scan_path = root / "scan-run.json"
            request_path = root / "guidance-request.json"
            output = root / "guidance.json"
            scan_run = sql_scan_run()
            scan_path.write_text(
                json.dumps(scan_run, indent=2) + "\n",
                encoding="utf-8",
            )
            request_path.write_text(
                json.dumps(guidance_request(scan_run), indent=2) + "\n",
                encoding="utf-8",
            )

            result = cli_main(
                [
                    "remediate",
                    "guide",
                    "--input",
                    str(scan_path),
                    "--guidance",
                    str(request_path),
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(result, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["schema_version"], "1.0.0")
            self.assertEqual(report["entries"][0]["status"], "guidance_only")

    def test_cli_lists_applies_and_rolls_back_deterministic_fix(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "config.py"
            before = b"config = yaml.load(payload)\n"
            source.write_bytes(before)
            plan = root / "plan.json"
            receipt = root / "receipt.json"
            rollback = root / "rollback.json"
            rules = root / "rules.json"
            plan.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0.0",
                        "plan_id": "plan-cli",
                        "requests": [
                            {
                                "request_id": "yaml",
                                "rule_id": "TG-PY-YAML-001",
                                "framework": "python-pyyaml",
                                "path": "config.py",
                                "expected_sha256": "sha256:"
                                + hashlib.sha256(before).hexdigest(),
                                "parameters": {},
                            }
                        ],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            self.assertEqual(
                cli_main(["remediate", "rules", "--output", str(rules)]),
                0,
            )
            self.assertEqual(
                cli_main(
                    [
                        "remediate",
                        "apply",
                        "--root",
                        str(root),
                        "--plan",
                        str(plan),
                        "--backup-root",
                        str(root / ".trustgate-backups"),
                        "--receipt",
                        str(receipt),
                    ]
                ),
                0,
            )
            self.assertEqual(
                source.read_text(encoding="utf-8"),
                "config = yaml.safe_load(payload)\n",
            )
            self.assertEqual(
                cli_main(
                    [
                        "remediate",
                        "rollback",
                        "--root",
                        str(root),
                        "--receipt",
                        str(receipt),
                        "--backup-root",
                        str(root / ".trustgate-backups"),
                        "--output",
                        str(rollback),
                    ]
                ),
                0,
            )

            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(len(json.loads(rules.read_text(encoding="utf-8"))), 8)
            self.assertEqual(
                json.loads(receipt.read_text(encoding="utf-8"))["status"],
                "applied",
            )
            self.assertEqual(
                json.loads(rollback.read_text(encoding="utf-8"))["status"],
                "rolled_back",
            )


if __name__ == "__main__":
    unittest.main()
