from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from trustgate.schema import build_scan_run, validate_instance
from trustgate.threat_intelligence.cache import ThreatCache
from trustgate.threat_intelligence.models import ThreatRecord

from tests.unit.schemas.test_documents import scanner_result
from tests.unit.schemas.test_schema_contracts import valid_finding
from trustgate.scanners.models import ScannerState


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)


class ThreatIntelligenceCliTests(unittest.TestCase):
    def test_enrich_command_runs_fully_offline_and_marks_stale_gate_context(self):
        finding = valid_finding()
        finding["cve"] = ["CVE-2026-1234"]
        scan_run = build_scan_run(
            target=".",
            findings=[finding],
            scanner_results=[scanner_result(ScannerState.FINDINGS)],
        )
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            input_path = workspace / "scan-run.json"
            output_path = workspace / "enriched.json"
            cache_dir = workspace / "cache"
            input_path.write_text(json.dumps(scan_run), encoding="utf-8")
            ThreatCache(cache_dir).put(
                "epss",
                "CVE-2026-1234",
                [
                    ThreatRecord(
                        source="epss",
                        advisory_ids=("CVE-2026-1234",),
                        epss_probability=0.42,
                        epss_percentile=0.91,
                    ).to_dict()
                ],
                fetched_at=NOW - timedelta(days=2),
                ttl=timedelta(hours=24),
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "enrich",
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                    "--cache-dir",
                    str(cache_dir),
                    "--network-mode",
                    "disabled",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            enriched = json.loads(output_path.read_text(encoding="utf-8"))
            validate_instance("scan-run", enriched)
            threat = enriched["findings"][0]["threat_intelligence"]
            self.assertEqual(threat["epss_probability"], 0.42)
            self.assertTrue(threat["stale"])
            self.assertEqual(enriched["summary"]["threat_data"]["status"], "stale")
            self.assertIn("offline", completed.stdout.lower())

    def test_aggregate_carries_offline_staleness_into_policy_result(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            reports = workspace / "reports"
            reports.mkdir()
            (reports / "pip_audit_report.json").write_text(
                json.dumps(
                    {
                        "dependencies": [
                            {
                                "name": "demo",
                                "version": "1.0.0",
                                "vulns": [
                                    {
                                        "id": "CVE-2026-1234",
                                        "severity": "HIGH",
                                        "description": "Vulnerable package.",
                                        "aliases": [],
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            cache_dir = workspace / "cache"
            ThreatCache(cache_dir).put(
                "epss",
                "CVE-2026-1234",
                [
                    ThreatRecord(
                        source="epss",
                        advisory_ids=("CVE-2026-1234",),
                        epss_probability=0.42,
                        epss_percentile=0.91,
                    ).to_dict()
                ],
                fetched_at=NOW - timedelta(days=2),
                ttl=timedelta(hours=24),
            )
            output_path = reports / "findings.json"
            policy_path = reports / "policy-result.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustgate",
                    "aggregate",
                    "--reports-dir",
                    str(reports),
                    "--output",
                    str(output_path),
                    "--policy-output",
                    str(policy_path),
                    "--required-scanner",
                    "pip-audit",
                    "--fail-on",
                    "none",
                    "--enrich-threats",
                    "--network-mode",
                    "disabled",
                    "--threat-cache-dir",
                    str(cache_dir),
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            scan_run = json.loads(output_path.read_text(encoding="utf-8"))
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            self.assertEqual(scan_run["summary"]["threat_data"]["status"], "stale")
            self.assertTrue(policy["metadata"]["threat_data_stale"])
            self.assertIn("stale threat data", policy["reason"].lower())


if __name__ == "__main__":
    unittest.main()
