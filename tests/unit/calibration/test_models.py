"""Tests for local calibration models."""

from __future__ import annotations

import unittest

from trustgate.calibration.models import (
    CALIBRATION_MODEL_VERSION,
    MIN_LOCAL_SAMPLES,
    CalibrationModel,
    build_calibration_model,
    detect_drift,
    merge_global_and_local,
)


def _feedback(
    rule_id: str = "B101",
    scanner: str = "Bandit",
    feedback_type: str = "confirmed_true_positive",
    **kwargs: object,
) -> dict:
    return {
        "rule_id": rule_id,
        "scanner": scanner,
        "feedback_type": feedback_type,
        **kwargs,
    }


class BuildCalibrationModelTests(unittest.TestCase):

    def test_empty_feedback_produces_empty_model(self):
        model = build_calibration_model([])
        self.assertEqual(len(model.rules), 0)

    def test_true_positives_counted(self):
        feedback = [_feedback() for _ in range(3)]
        model = build_calibration_model(feedback)
        cal = model.rules["Bandit:B101"]
        self.assertEqual(cal.true_positives, 3)
        self.assertEqual(cal.false_positives, 0)
        self.assertEqual(cal.sample_size, 3)

    def test_false_positives_counted(self):
        feedback = [
            _feedback(feedback_type="confirmed_false_positive")
            for _ in range(2)
        ]
        model = build_calibration_model(feedback)
        cal = model.rules["Bandit:B101"]
        self.assertEqual(cal.false_positives, 2)

    def test_mixed_feedback(self):
        feedback = [
            _feedback(feedback_type="confirmed_true_positive"),
            _feedback(feedback_type="confirmed_true_positive"),
            _feedback(feedback_type="confirmed_false_positive"),
        ]
        model = build_calibration_model(feedback)
        cal = model.rules["Bandit:B101"]
        self.assertEqual(cal.true_positives, 2)
        self.assertEqual(cal.false_positives, 1)
        self.assertEqual(cal.sample_size, 3)

    def test_other_feedback_types_ignored_for_precision(self):
        feedback = [
            _feedback(feedback_type="fixed"),
            _feedback(feedback_type="accepted_risk"),
        ]
        model = build_calibration_model(feedback)
        self.assertEqual(len(model.rules), 0)

    def test_multiple_rules_separated(self):
        feedback = [
            _feedback(rule_id="B101"),
            _feedback(rule_id="B102"),
        ]
        model = build_calibration_model(feedback)
        self.assertIn("Bandit:B101", model.rules)
        self.assertIn("Bandit:B102", model.rules)

    def test_scope_recorded(self):
        model = build_calibration_model(
            [], scope="organisation", scope_id="acme-corp"
        )
        self.assertEqual(model.scope, "organisation")
        self.assertEqual(model.scope_id, "acme-corp")

    def test_local_precision_with_prior(self):
        """Beta(1,1) prior: 3 TP, 0 FP → (1+3)/(1+3+1+0) = 0.8"""
        feedback = [_feedback() for _ in range(3)]
        model = build_calibration_model(feedback)
        cal = model.rules["Bandit:B101"]
        self.assertAlmostEqual(cal.local_precision, 0.8, places=4)

    def test_insufficient_evidence_flag(self):
        feedback = [_feedback() for _ in range(2)]
        model = build_calibration_model(feedback)
        cal = model.rules["Bandit:B101"]
        self.assertFalse(cal.has_sufficient_evidence)

    def test_sufficient_evidence_flag(self):
        feedback = [_feedback() for _ in range(MIN_LOCAL_SAMPLES)]
        model = build_calibration_model(feedback)
        cal = model.rules["Bandit:B101"]
        self.assertTrue(cal.has_sufficient_evidence)

    def test_to_dict(self):
        feedback = [_feedback() for _ in range(5)]
        model = build_calibration_model(feedback, scope_id="my-repo")
        d = model.to_dict()
        self.assertEqual(d["model_version"], CALIBRATION_MODEL_VERSION)
        self.assertIn("Bandit:B101", d["rules"])


class MergeGlobalAndLocalTests(unittest.TestCase):

    def test_no_local_data_returns_global(self):
        model = CalibrationModel()
        result = merge_global_and_local(0.8, model, "Bandit:B101")
        self.assertEqual(result["merged_estimate"], 0.8)
        self.assertEqual(result["source"], "global_only")
        self.assertFalse(result["shrinkage_applied"])

    def test_insufficient_local_returns_global(self):
        feedback = [_feedback() for _ in range(2)]
        model = build_calibration_model(feedback)
        result = merge_global_and_local(0.8, model, "Bandit:B101")
        self.assertEqual(result["merged_estimate"], 0.8)
        self.assertEqual(result["source"], "global_only")

    def test_sufficient_local_merges(self):
        feedback = [_feedback() for _ in range(10)]
        model = build_calibration_model(feedback)
        result = merge_global_and_local(0.5, model, "Bandit:B101")
        self.assertEqual(result["source"], "merged")
        self.assertTrue(result["shrinkage_applied"])
        # Local precision is ~0.917, global is 0.5
        # Merged should be between them, closer to local
        self.assertGreater(result["merged_estimate"], 0.5)
        self.assertLess(result["merged_estimate"], 1.0)

    def test_shrinkage_pulls_toward_global(self):
        feedback = [_feedback() for _ in range(MIN_LOCAL_SAMPLES)]
        model = build_calibration_model(feedback)
        # With shrinkage, merged should be between local and global
        result = merge_global_and_local(0.3, model, "Bandit:B101")
        local = result["local_estimate"]
        self.assertGreater(result["merged_estimate"], 0.3)
        self.assertLessEqual(result["merged_estimate"], local)

    def test_more_evidence_reduces_shrinkage(self):
        few = [_feedback() for _ in range(MIN_LOCAL_SAMPLES)]
        many = [_feedback() for _ in range(50)]
        model_few = build_calibration_model(few)
        model_many = build_calibration_model(many)

        r_few = merge_global_and_local(0.3, model_few, "Bandit:B101")
        r_many = merge_global_and_local(0.3, model_many, "Bandit:B101")

        # More evidence → less shrinkage → closer to local
        self.assertGreater(
            r_many["merged_estimate"], r_few["merged_estimate"]
        )

    def test_small_local_samples_cannot_create_extreme_confidence(self):
        """Even with all-TP local feedback, shrinkage prevents extreme values."""
        feedback = [_feedback() for _ in range(MIN_LOCAL_SAMPLES)]
        model = build_calibration_model(feedback)
        result = merge_global_and_local(0.5, model, "Bandit:B101")
        # Should not be 1.0
        self.assertLess(result["merged_estimate"], 0.95)

    def test_global_and_local_shown_together(self):
        feedback = [_feedback() for _ in range(10)]
        model = build_calibration_model(feedback)
        result = merge_global_and_local(0.7, model, "Bandit:B101")
        self.assertIn("global_estimate", result)
        self.assertIn("local_estimate", result)
        self.assertIn("merged_estimate", result)

    def test_model_version_included(self):
        model = CalibrationModel()
        result = merge_global_and_local(0.8, model, "Bandit:B101")
        self.assertEqual(result["model_version"], CALIBRATION_MODEL_VERSION)


class DriftDetectionTests(unittest.TestCase):

    def test_no_drift_returns_none(self):
        feedback = [_feedback() for _ in range(10)]
        model = build_calibration_model(feedback)
        # Local precision ~0.917, global 0.8 → diff ~0.117 < 0.2
        result = detect_drift(0.8, model, "Bandit:B101")
        self.assertIsNone(result)

    def test_drift_detected(self):
        # 10 TP → local ~0.917, global 0.3 → diff ~0.617
        feedback = [_feedback() for _ in range(10)]
        model = build_calibration_model(feedback)
        result = detect_drift(0.3, model, "Bandit:B101")
        self.assertIsNotNone(result)
        self.assertGreater(result["drift"], 0.2)
        self.assertEqual(result["direction"], "higher")

    def test_drift_lower_direction(self):
        feedback = [
            _feedback(feedback_type="confirmed_false_positive")
            for _ in range(10)
        ]
        model = build_calibration_model(feedback)
        result = detect_drift(0.9, model, "Bandit:B101")
        self.assertIsNotNone(result)
        self.assertEqual(result["direction"], "lower")

    def test_insufficient_evidence_no_drift(self):
        feedback = [_feedback() for _ in range(2)]
        model = build_calibration_model(feedback)
        result = detect_drift(0.1, model, "Bandit:B101")
        self.assertIsNone(result)

    def test_custom_threshold(self):
        feedback = [_feedback() for _ in range(10)]
        model = build_calibration_model(feedback)
        # With stricter threshold
        result = detect_drift(
            0.8, model, "Bandit:B101", drift_threshold=0.1
        )
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
