"""Tests for statistically conservative confidence calculations."""

from __future__ import annotations

import unittest

from trustgate.benchmarks.statistics import (
    classification_metrics,
    maturity_level,
    posterior_precision,
)


class ConfidenceStatisticsTests(unittest.TestCase):
    def test_uniform_prior_without_samples_has_wide_interval(self) -> None:
        score = posterior_precision(0, 0)

        self.assertEqual(score["displayed_estimate"], 0.5)
        self.assertAlmostEqual(score["interval"]["lower"], 0.025, places=3)
        self.assertAlmostEqual(score["interval"]["upper"], 0.975, places=3)
        self.assertEqual(score["maturity"], "Experimental")

    def test_one_success_is_not_high_confidence(self) -> None:
        score = posterior_precision(1, 0)

        self.assertAlmostEqual(score["displayed_estimate"], 2 / 3, places=6)
        self.assertLess(score["gating_estimate"], 0.2)
        self.assertEqual(score["sample_size"], 1)
        self.assertEqual(score["decision_tier"], "Experimental")

    def test_gate_uses_lower_credible_bound_after_maturity(self) -> None:
        score = posterior_precision(95, 5)

        self.assertGreater(score["displayed_estimate"], score["gating_estimate"])
        self.assertGreater(score["gating_estimate"], 0.7)
        self.assertEqual(score["decision_tier"], "High")
        self.assertEqual(score["maturity"], "Mature")

    def test_maturity_bands_match_the_roadmap(self) -> None:
        cases = {
            0: "Experimental",
            4: "Experimental",
            5: "Directional",
            29: "Directional",
            30: "Moderate",
            99: "Moderate",
            100: "Mature",
        }

        for sample_size, expected in cases.items():
            with self.subTest(sample_size=sample_size):
                self.assertEqual(maturity_level(sample_size), expected)
        self.assertEqual(
            maturity_level(100, independently_reproduced=True),
            "Verified",
        )

    def test_precision_recall_f1_brier_and_calibration_error(self) -> None:
        metrics = classification_metrics(
            true_positives=2,
            false_positives=1,
            false_negatives=1,
            labels=[1, 1, 0],
            probabilities=[0.8, 0.8, 0.8],
            calibration_bins=5,
        )

        self.assertAlmostEqual(metrics["precision"], 2 / 3, places=6)
        self.assertAlmostEqual(metrics["recall"], 2 / 3, places=6)
        self.assertAlmostEqual(metrics["f1"], 2 / 3, places=6)
        self.assertAlmostEqual(metrics["brier_score"], 0.24, places=6)
        self.assertAlmostEqual(metrics["calibration_error"], 0.133333, places=6)
        self.assertEqual(metrics["calibration_quality"], "moderate")

    def test_zero_denominators_and_missing_calibration_are_explicit(self) -> None:
        metrics = classification_metrics(
            true_positives=0,
            false_positives=0,
            false_negatives=0,
        )

        self.assertEqual(metrics["precision"], 0.0)
        self.assertEqual(metrics["recall"], 0.0)
        self.assertEqual(metrics["f1"], 0.0)
        self.assertIsNone(metrics["brier_score"])
        self.assertEqual(metrics["calibration_quality"], "unavailable")


if __name__ == "__main__":
    unittest.main()
