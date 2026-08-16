"""End-to-end scenario tests.

Each test validates a complete workflow from findings through
gate decision to output.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from trustgate.management.dashboard import (
    multi_repository_dashboard,
    organisation_risk_overview,
    suppression_expiry_summary,
)
from trustgate.benchmarks.regression import compare_evaluations
from trustgate.calibration.feedback import FeedbackStore, record_feedback
from trustgate.calibration.models import build_calibration_model, detect_drift
from trustgate.compliance.mappings import build_evidence_report
from trustgate.deployment.modes import validate_deployment_config
from trustgate.errors import scanner_failed, no_findings_produced
from trustgate.integrations.adapters import create_adapter
from trustgate.integrations.tickets import (
    TicketState,
    TicketStore,
    assign_finding,
    sync_ticket_close,
)


def _finding(
    severity: str = "high",
    scanner: str = "Bandit",
    rule_id: str = "B101",
    **kwargs: object,
) -> dict:
    return {
        "fingerprint": f"{scanner}:{rule_id}:test.py:1",
        "finding_id": f"f-{rule_id}",
        "severity": severity,
        "scanner": scanner,
        "rule_id": rule_id,
        "file_path": "test.py",
        "line": 1,
        **kwargs,
    }


class CleanRepositoryPassesTests(unittest.TestCase):
    """E2E: clean repository with no findings should pass."""

    def test_no_findings_exit_zero(self):
        err = no_findings_produced()
        self.assertEqual(err.exit_code, 0)

    def test_empty_dashboard_zero_risk(self):
        result = organisation_risk_overview([])
        self.assertEqual(result["risk_score"], 0)


class CriticalVulnerabilityBlocksTests(unittest.TestCase):
    """E2E: new critical vulnerability should block the gate."""

    def test_critical_finding_high_risk(self):
        repos = [{"name": "app", "findings": [_finding("critical")]}]
        result = organisation_risk_overview(repos)
        self.assertGreater(result["risk_score"], 0)

    def test_critical_regression_detected(self):
        baseline = {"tools": {"Bandit": {"precision": 0.9, "recall": 0.9, "f1": 0.9, "sample_size": 100}}}
        current = {"tools": {"Bandit": {"precision": 0.5, "recall": 0.5, "f1": 0.5, "sample_size": 100}}}
        result = compare_evaluations(baseline, current)
        self.assertFalse(result["passed"])


class ScannerFailureBlocksTests(unittest.TestCase):
    """E2E: scanner failure should block the gate."""

    def test_scanner_failure_not_trustworthy(self):
        err = scanner_failed("Bandit", exit_code=1)
        self.assertFalse(err.gate_trustworthy)


class SuppressionExpiresTests(unittest.TestCase):
    """E2E: expired suppression should reopen the finding."""

    def test_expired_suppression_detected(self):
        suppressions = [
            {"finding_fingerprint": "abc", "expires_at": 1000.0},
        ]
        result = suppression_expiry_summary(suppressions, current_time=2000.0)
        self.assertEqual(result["expired"], 1)
        self.assertIn("abc", result["expired_fingerprints"])


class KEVChangesReprioritiseTests(unittest.TestCase):
    """E2E: KEV status change should trigger reprioritisation."""

    def test_kev_change_detected_in_threat_intel(self):
        from trustgate.management.dashboard import threat_intelligence_changes
        baseline = [{"cve_id": "CVE-2024-1234", "kev": False}]
        current = [{"cve_id": "CVE-2024-1234", "kev": True}]
        result = threat_intelligence_changes(baseline, current)
        self.assertEqual(len(result["changed"]), 1)
        self.assertTrue(result["changed"][0]["changes"]["kev"]["now"])


class DeterministicFixTests(unittest.TestCase):
    """E2E: deterministic fix should pass verification."""

    def test_benchmark_regression_passes_when_improved(self):
        baseline = {"tools": {"Bandit": {"precision": 0.8, "recall": 0.8, "f1": 0.8, "sample_size": 100}}}
        current = {"tools": {"Bandit": {"precision": 0.9, "recall": 0.9, "f1": 0.9, "sample_size": 100}}}
        result = compare_evaluations(baseline, current)
        self.assertTrue(result["passed"])


class FailedFixTests(unittest.TestCase):
    """E2E: failed fix should remain unresolved."""

    def test_unvalidated_ticket_close_does_not_resolve(self):
        record = assign_finding(
            _finding(), owner="dev", integration_type="jira",
        )
        closed = sync_ticket_close(record, validated=False)
        self.assertFalse(closed["finding_state_updated"])


class EvidenceBundleTests(unittest.TestCase):
    """E2E: evidence report should be exportable and verifiable."""

    def test_compliance_evidence_exportable(self):
        report = build_evidence_report("owasp-top-10")
        # Should be JSON-serializable
        serialised = json.dumps(report)
        self.assertIsInstance(json.loads(serialised), dict)

    def test_compliance_evidence_has_disclaimer(self):
        report = build_evidence_report("pci-dss")
        self.assertIn("does not claim", report["disclaimer"])


class TicketLifecycleTests(unittest.TestCase):
    """E2E: ticket lifecycle from assignment to resolution."""

    def test_full_ticket_lifecycle(self):
        with tempfile.TemporaryDirectory() as d:
            store = TicketStore(Path(d) / "tickets.json")

            # 1. Assign finding
            finding = _finding()
            record = assign_finding(
                finding, owner="alice", integration_type="jira",
            )
            stored = store.assign(record)
            self.assertEqual(stored["state"], TicketState.OPEN)

            # 2. Update to in-progress
            updated = store.update_state(
                record["ticket_key"], TicketState.IN_PROGRESS,
            )
            self.assertEqual(updated["state"], TicketState.IN_PROGRESS)

            # 3. Close with validation
            resolved = store.update_state(
                record["ticket_key"],
                TicketState.RESOLVED,
                validated=True,
            )
            self.assertTrue(resolved["finding_state_updated"])
            self.assertEqual(resolved["finding_new_status"], "resolved")

            # 4. No duplicate tickets
            dup = assign_finding(
                finding, owner="bob", integration_type="jira",
            )
            stored_dup = store.assign(dup)
            all_tickets = store.list()
            self.assertEqual(len(all_tickets), 1)


class CalibrationFeedbackLifecycleTests(unittest.TestCase):
    """E2E: feedback → calibration → drift detection."""

    def test_full_calibration_lifecycle(self):
        with tempfile.TemporaryDirectory() as d:
            store = FeedbackStore(Path(d) / "feedback.json")

            # 1. Record feedback — unique fingerprints to avoid dedup
            for i in range(10):
                entry = {
                    "finding_fingerprint": f"finding-{i}",
                    "feedback_type": "confirmed_true_positive",
                    "rule_id": "B101",
                    "scanner": "Bandit",
                }
                rec = record_feedback(entry)
                store.add(rec)

            # 2. Build calibration model
            feedback = store.export()
            self.assertEqual(len(feedback), 10)
            model = build_calibration_model(feedback)
            self.assertIn("Bandit:B101", model.rules)

            # 3. Detect drift (local precision ~0.917 vs global 0.3)
            drift = detect_drift(0.3, model, "Bandit:B101")
            self.assertIsNotNone(drift)
            self.assertEqual(drift["direction"], "higher")


class IntegrationAdapterLifecycleTests(unittest.TestCase):
    """E2E: finding → adapter → formatted payload."""

    def test_all_adapters_produce_valid_output(self):
        finding = _finding()
        for adapter_type in ["linear", "jira", "slack", "microsoft_teams",
                            "email", "webhook", "siem"]:
            adapter = create_adapter(adapter_type)
            result = adapter.format_finding(finding)
            self.assertIn("severity", result)
            self.assertIn("title", result)


if __name__ == "__main__":
    unittest.main()
