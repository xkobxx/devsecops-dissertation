from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import unittest

from trustgate.baselines import (
    BaselineCompatibilityError,
    BaselineGateError,
    BaselineIntegrityError,
    GateMode,
    create_baseline,
    evaluate_gate,
)
from trustgate.policy.models import PolicyDocument
from trustgate.schema import validate_instance

from tests.unit.baselines.test_comparison import changed_runs, finding
from tests.unit.baselines.test_creation import GENERATED_AT
from tests.unit.policy.test_schema import policy_document


EVALUATED_AT = datetime(2026, 8, 4, 14, 0, tzinfo=timezone.utc)


def baseline_and_current() -> tuple[dict[str, object], dict[str, object]]:
    baseline_scan, current = changed_runs()
    baseline = create_baseline(
        baseline_scan,
        default_branch="main",
        generated_at=GENERATED_AT,
    )
    return baseline, current


def retain(current: dict[str, object], *names: str) -> dict[str, object]:
    retained = deepcopy(current)
    fingerprints = {finding(name)["fingerprint"] for name in names}
    retained["findings"] = [
        item for item in retained["findings"] if item["fingerprint"] in fingerprints
    ]
    retained["summary"]["total_findings"] = len(retained["findings"])
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }
    for item in retained["findings"]:
        counts[item["normalised_severity"]] += 1
    retained["summary"]["severity_counts"] = counts
    retained["scanners"][0]["finding_count"] = len(retained["findings"])
    return retained


class DifferentialGateModeTests(unittest.TestCase):
    def test_new_is_default_and_ignores_historical_high_findings(self) -> None:
        baseline, current = baseline_and_current()
        historical_only = retain(current, "stable")

        gate = evaluate_gate(
            baseline,
            historical_only,
            evaluated_at=EVALUATED_AT,
        )

        validate_instance("baseline-gate", gate)
        self.assertEqual(gate["gate_mode"], "new")
        self.assertTrue(gate["passed"])
        self.assertEqual(gate["blocked_findings"], [])
        self.assertEqual(gate["baseline_age_seconds"], 172800.0)

    def test_new_high_risk_finding_blocks_default_gate(self) -> None:
        baseline, current = baseline_and_current()

        gate = evaluate_gate(baseline, current, evaluated_at=EVALUATED_AT)

        self.assertFalse(gate["passed"])
        self.assertEqual(gate["candidate_fingerprints"], [finding("introduced")["fingerprint"]])
        self.assertEqual(
            [item["fingerprint"] for item in gate["blocked_findings"]],
            [finding("introduced")["fingerprint"]],
        )
        self.assertEqual(gate["blocked_findings"][0]["reasons"], ["new"])

    def test_all_mode_explicitly_enforces_historical_risk(self) -> None:
        baseline, current = baseline_and_current()
        historical_only = retain(current, "stable")

        gate = evaluate_gate(
            baseline,
            historical_only,
            mode=GateMode.ALL,
            evaluated_at=EVALUATED_AT,
        )

        self.assertFalse(gate["passed"])
        self.assertEqual(
            [item["fingerprint"] for item in gate["blocked_findings"]],
            [finding("stable")["fingerprint"]],
        )
        self.assertEqual(gate["blocked_findings"][0]["reasons"], ["legacy"])

    def test_worsened_mode_blocks_new_and_materially_changed_risk(self) -> None:
        baseline, current = baseline_and_current()
        changed = retain(current, "worsened", "introduced")

        gate = evaluate_gate(
            baseline,
            changed,
            mode=GateMode.WORSENED,
            evaluated_at=EVALUATED_AT,
        )

        self.assertFalse(gate["passed"])
        self.assertEqual(
            {item["fingerprint"] for item in gate["blocked_findings"]},
            {
                finding("worsened")["fingerprint"],
                finding("introduced")["fingerprint"],
            },
        )
        reasons = {
            item["fingerprint"]: item["reasons"]
            for item in gate["blocked_findings"]
        }
        self.assertEqual(reasons[finding("worsened")["fingerprint"]], ["worsened"])

    def test_threshold_is_applied_to_selected_candidates(self) -> None:
        baseline, current = baseline_and_current()
        new_medium = finding("introduced", severity="medium")
        current = retain(current, "introduced")
        current["findings"] = [new_medium]
        current["summary"]["severity_counts"] = {
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 0,
            "info": 0,
            "unknown": 0,
        }

        high_gate = evaluate_gate(
            baseline,
            current,
            fail_on="high",
            evaluated_at=EVALUATED_AT,
        )
        medium_gate = evaluate_gate(
            baseline,
            current,
            fail_on="medium",
            evaluated_at=EVALUATED_AT,
        )

        self.assertTrue(high_gate["passed"])
        self.assertFalse(medium_gate["passed"])


class PolicyAndCompatibilityGateTests(unittest.TestCase):
    def test_policy_mode_applies_public_policy_to_changed_risk(self) -> None:
        baseline, current = baseline_and_current()
        current = retain(current, "introduced")
        policy = PolicyDocument.from_dict(policy_document({"severity": "critical"}))

        gate = evaluate_gate(
            baseline,
            current,
            mode=GateMode.POLICY,
            policy=policy,
            evaluated_at=EVALUATED_AT,
        )

        self.assertFalse(gate["passed"])
        self.assertEqual(gate["policy_id"], "product-policy")
        self.assertEqual(gate["policy_version"], "2026.08.1")
        self.assertEqual(gate["blocked_findings"][0]["policy_outcome"], "BLOCK_IMMEDIATELY")
        self.assertEqual(gate["blocked_findings"][0]["matched_policy"], "roadmap-rule")
        self.assertIn("policy", gate["blocked_findings"][0]["reasons"])

    def test_policy_mode_requires_a_policy_document(self) -> None:
        baseline, current = baseline_and_current()

        with self.assertRaisesRegex(BaselineGateError, "requires.*policy"):
            evaluate_gate(
                baseline,
                current,
                mode=GateMode.POLICY,
                evaluated_at=EVALUATED_AT,
            )

    def test_explicit_legacy_enforcement_expands_new_mode(self) -> None:
        baseline, current = baseline_and_current()
        historical_only = retain(current, "stable")

        gate = evaluate_gate(
            baseline,
            historical_only,
            enforce_legacy_risk=True,
            evaluated_at=EVALUATED_AT,
        )

        self.assertFalse(gate["passed"])
        self.assertTrue(gate["enforce_legacy_risk"])
        self.assertEqual(gate["blocked_findings"][0]["reasons"], ["legacy"])

    def test_policy_mode_leaves_unchanged_legacy_risk_out_until_explicitly_enabled(self) -> None:
        baseline, current = baseline_and_current()
        historical_only = retain(current, "stable")
        policy = PolicyDocument.from_dict(policy_document({"severity": "high"}))

        adoption_gate = evaluate_gate(
            baseline,
            historical_only,
            mode=GateMode.POLICY,
            policy=policy,
            evaluated_at=EVALUATED_AT,
        )
        legacy_gate = evaluate_gate(
            baseline,
            historical_only,
            mode=GateMode.POLICY,
            policy=policy,
            enforce_legacy_risk=True,
            evaluated_at=EVALUATED_AT,
        )

        self.assertTrue(adoption_gate["passed"])
        self.assertFalse(legacy_gate["passed"])

    def test_scanner_coverage_regression_always_fails_closed(self) -> None:
        baseline, current = baseline_and_current()
        current = retain(current, "stable")
        current["scanners"] = []
        current["summary"]["required_scanners"] = 0
        current["summary"]["healthy_scanners"] = 0
        current["summary"]["scanner_state_counts"] = {
            "CLEAN": 0,
            "FINDINGS": 0,
            "FAILED_SCANNER": 0,
            "PARTIAL": 0,
            "SKIPPED": 0,
        }

        gate = evaluate_gate(baseline, current, evaluated_at=EVALUATED_AT)

        self.assertFalse(gate["passed"])
        self.assertEqual(gate["blocked_findings"], [])
        self.assertEqual(len(gate["scanner_coverage_regressions"]), 1)

    def test_invalid_or_incompatible_baseline_fails_before_gating(self) -> None:
        baseline, current = baseline_and_current()
        tampered = deepcopy(baseline)
        tampered["commit"] = "c" * 40
        wrong_repository = deepcopy(current)
        wrong_repository["repository"] = "example/other"

        with self.assertRaises(BaselineIntegrityError):
            evaluate_gate(tampered, current, evaluated_at=EVALUATED_AT)
        with self.assertRaises(BaselineCompatibilityError):
            evaluate_gate(baseline, wrong_repository, evaluated_at=EVALUATED_AT)


if __name__ == "__main__":
    unittest.main()
