"""Tests for canonical scan-run and policy-result document builders."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from trustgate.correlation import CorrelationConfig, ScannerContradiction
from trustgate.scanners.models import ParserStatus, ScannerResult, ScannerState
from trustgate.schema import validate_instance
from trustgate.schema.documents import build_policy_result, build_scan_run

from .test_schema_contracts import valid_finding


STARTED = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)


def scanner_result(
    state: ScannerState,
    *,
    required: bool = True,
    error: str | None = None,
) -> ScannerResult:
    return ScannerResult(
        scanner="semgrep",
        state=state,
        started_at=STARTED,
        ended_at=STARTED + timedelta(seconds=2),
        exit_code=0 if state in {ScannerState.CLEAN, ScannerState.FINDINGS} else 2,
        timed_out=False,
        report_path="reports/semgrep.json",
        report_produced=True,
        parser_status=(
            ParserStatus.SUCCESS
            if state in {ScannerState.CLEAN, ScannerState.FINDINGS}
            else ParserStatus.FAILED
        ),
        version="1.125.0",
        stdout_path=None,
        stderr_path=None,
        finding_count=1 if state is ScannerState.FINDINGS else 0,
        error=error,
        required=required,
    )


class CanonicalDocumentTests(unittest.TestCase):
    def test_builds_a_valid_scan_run_with_canonical_scanner_health(self) -> None:
        scan_run = build_scan_run(
            target=".",
            findings=[valid_finding()],
            scanner_results=[scanner_result(ScannerState.FINDINGS)],
            repository="example/repository",
            ref="refs/heads/main",
            commit="0" * 40,
            trigger="push",
        )

        validate_instance("scan-run", scan_run)
        self.assertEqual(scan_run["summary"]["total_findings"], 1)
        self.assertEqual(scan_run["scanners"][0]["scanner_version"], "1.125.0")
        self.assertTrue(scan_run["scanners"][0]["healthy"])
        self.assertNotIn("version", scan_run["scanners"][0])

    def test_scan_run_consolidates_duplicate_and_cross_scanner_findings(self) -> None:
        semgrep = valid_finding()
        semgrep_repeat = valid_finding()
        semgrep_repeat["start_line"] = 44
        semgrep_repeat["end_line"] = 44
        semgrep_repeat["raw_report_reference"] = {
            "path": "reports/semgrep-repeat.json",
            "sha256": "1" * 64,
            "scanner_finding_id": "repeat",
        }
        bandit = valid_finding()
        bandit.update(
            {
                "scanner": "bandit",
                "rule_id": "B608",
                "finding_id": "finding-bandit",
                "fingerprint": "v2:sha256:" + "b" * 64,
                "start_line": 43,
                "end_line": 43,
                "raw_report_reference": {
                    "path": "reports/bandit.json",
                    "sha256": "b" * 64,
                    "scanner_finding_id": "B608:43",
                },
            }
        )

        scan_run = build_scan_run(
            target=".",
            findings=[semgrep, semgrep_repeat, bandit],
            scanner_results=[scanner_result(ScannerState.FINDINGS)],
        )

        self.assertEqual(scan_run["summary"]["total_findings"], 1)
        self.assertEqual(len(scan_run["findings"]), 1)
        issue = scan_run["findings"][0]
        self.assertEqual(issue["occurrence_count"], 3)
        self.assertEqual(issue["supporting_scanners"], ["bandit", "semgrep"])
        self.assertEqual(len(issue["raw_evidence_references"]), 3)

    def test_scan_run_accepts_ancestry_and_contradiction_evidence(self) -> None:
        semgrep = valid_finding()
        bandit = valid_finding()
        bandit.update(
            {
                "scanner": "bandit",
                "rule_id": "B608",
                "finding_id": "finding-bandit",
                "fingerprint": "v2:sha256:" + "b" * 64,
                "raw_report_reference": {
                    "path": "reports/bandit.json",
                    "sha256": "b" * 64,
                    "scanner_finding_id": "B608",
                },
            }
        )

        scan_run = build_scan_run(
            target=".",
            findings=[semgrep, bandit],
            scanner_results=[scanner_result(ScannerState.FINDINGS)],
            correlation_config=CorrelationConfig(
                rule_ancestry={
                    "semgrep:python.lang.security.audit.sqli": "shared/sql",
                    "bandit:B608": "shared/sql",
                }
            ),
            contradictions=[
                ScannerContradiction(
                    scanner="review-tool",
                    finding_identity=str(bandit["fingerprint"]),
                    reason="Sanitizer observed.",
                )
            ],
        )

        issue = scan_run["findings"][0]
        self.assertEqual(
            issue["corroboration"]["independent_scanner_count"],
            1,
        )
        self.assertEqual(issue["contradicting_scanners"], ["review-tool"])

    def test_required_scanner_failure_produces_failed_scan_and_policy(self) -> None:
        scan_run = build_scan_run(
            target=".",
            findings=[],
            scanner_results=[
                scanner_result(
                    ScannerState.FAILED_SCANNER,
                    error="Scanner crashed.",
                )
            ],
        )
        policy_result = build_policy_result(
            scan_run,
            fail_on="high",
            scanner_failure_policy="fail",
        )

        validate_instance("scan-run", scan_run)
        validate_instance("policy-result", policy_result)
        self.assertEqual(scan_run["status"], "failed")
        self.assertEqual(policy_result["outcome"], "fail")
        self.assertEqual(policy_result["metadata"]["exit_code"], 2)
        self.assertIn("scanner", policy_result["reason"].lower())

    def test_severity_threshold_produces_explainable_failed_policy(self) -> None:
        scan_run = build_scan_run(
            target=".",
            findings=[valid_finding()],
            scanner_results=[scanner_result(ScannerState.FINDINGS)],
        )
        policy_result = build_policy_result(
            scan_run,
            fail_on="high",
            scanner_failure_policy="fail",
        )

        validate_instance("policy-result", policy_result)
        self.assertEqual(policy_result["outcome"], "fail")
        self.assertEqual(policy_result["matched_finding_ids"], ["finding-001"])
        self.assertEqual(policy_result["metadata"]["exit_code"], 1)

    def test_warn_policy_does_not_hide_scanner_health(self) -> None:
        scan_run = build_scan_run(
            target=".",
            findings=[],
            scanner_results=[
                scanner_result(
                    ScannerState.FAILED_SCANNER,
                    error="Scanner crashed.",
                )
            ],
        )
        policy_result = build_policy_result(
            scan_run,
            fail_on="none",
            scanner_failure_policy="warn",
        )

        validate_instance("policy-result", policy_result)
        self.assertEqual(policy_result["outcome"], "warn")
        self.assertEqual(policy_result["metadata"]["exit_code"], 0)

    def test_policy_can_choose_original_or_normalised_severity(self) -> None:
        finding = valid_finding()
        finding["original_severity"] = "LOW"
        finding["normalised_severity"] = "high"
        scan_run = build_scan_run(
            target=".",
            findings=[finding],
            scanner_results=[scanner_result(ScannerState.FINDINGS)],
        )

        normalised_policy = build_policy_result(
            scan_run,
            fail_on="high",
            scanner_failure_policy="fail",
            severity_basis="normalised",
        )
        original_policy = build_policy_result(
            scan_run,
            fail_on="high",
            scanner_failure_policy="fail",
            severity_basis="original",
        )

        self.assertEqual(normalised_policy["outcome"], "fail")
        self.assertEqual(original_policy["outcome"], "pass")
        self.assertEqual(
            normalised_policy["metadata"]["severity_basis"],
            "normalised",
        )
        self.assertEqual(
            original_policy["metadata"]["severity_basis"],
            "original",
        )
        self.assertIn("original-severity", original_policy["reason"])

    def test_gate_result_explicitly_identifies_stale_threat_data(self) -> None:
        finding = valid_finding()
        finding["threat_intelligence"] = {
            "advisory_ids": ["CVE-2026-1234"],
            "cvss_score": None,
            "cvss_vector": None,
            "epss_probability": 0.4,
            "epss_percentile": 0.9,
            "kev_status": False,
            "known_exploitation_date": None,
            "ransomware_association": None,
            "fixed_versions": [],
            "published_date": None,
            "modified_date": None,
            "data_source_timestamp": "2026-01-01T00:00:00Z",
            "network_mode": "disabled",
            "stale": True,
            "risk_context_complete": False,
            "limitations": ["No threat feed provides complete risk context."],
            "sources": [
                {
                    "source": "epss",
                    "status": "stale-cache",
                    "fetched_at": "2026-01-01T00:00:00Z",
                    "expires_at": "2026-01-02T00:00:00Z",
                    "stale": True,
                    "identifiers_sent": [],
                }
            ],
            "failures": [],
        }
        scan_run = build_scan_run(
            target=".",
            findings=[finding],
            scanner_results=[scanner_result(ScannerState.FINDINGS)],
        )
        policy_result = build_policy_result(
            scan_run,
            fail_on="high",
            scanner_failure_policy="fail",
        )

        self.assertEqual(scan_run["summary"]["threat_data"]["status"], "stale")
        self.assertEqual(
            scan_run["summary"]["threat_data"]["stale_findings"], 1
        )
        self.assertTrue(policy_result["metadata"]["threat_data_stale"])
        self.assertEqual(policy_result["metadata"]["threat_data_status"], "stale")
        self.assertIn("stale threat data", policy_result["reason"].lower())


if __name__ == "__main__":
    unittest.main()
