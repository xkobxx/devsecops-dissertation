"""Tests for canonical scan-run and policy-result document builders."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

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


if __name__ == "__main__":
    unittest.main()
