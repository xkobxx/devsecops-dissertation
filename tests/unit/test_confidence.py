"""Tests for separate, non-circular confidence concepts."""

from __future__ import annotations

import unittest

from trustgate.benchmarks.statistics import posterior_precision
from trustgate.confidence import (
    CONFIDENCE_DEFINITIONS,
    CONFIDENCE_EVIDENCE,
    CONFIDENCE_FIELDS,
    build_confidence_components,
    validate_dependency_graph,
)


class ConfidenceConceptTests(unittest.TestCase):
    def test_each_confidence_type_is_defined_with_evidence(self) -> None:
        self.assertEqual(set(CONFIDENCE_DEFINITIONS), set(CONFIDENCE_FIELDS))
        self.assertEqual(set(CONFIDENCE_EVIDENCE), set(CONFIDENCE_FIELDS))
        for field in CONFIDENCE_FIELDS:
            self.assertTrue(CONFIDENCE_DEFINITIONS[field])
            self.assertTrue(CONFIDENCE_EVIDENCE[field])

    def test_component_builder_returns_every_separate_field(self) -> None:
        components = build_confidence_components(
            {
                "reachability": "reachable",
                "evidence": [
                    {"kind": "corroboration"},
                    {"kind": "exploit_validation"},
                ],
                "remediation": {
                    "references": ["https://example.com/fix"],
                },
            },
            posterior_precision(25, 5),
        )

        self.assertEqual(set(components), set(CONFIDENCE_FIELDS))
        self.assertIsNotNone(
            components["scanner_rule_reliability"]["estimate"]
        )
        self.assertIsNotNone(
            components["finding_validity_confidence"]["estimate"]
        )
        self.assertIsNotNone(
            components["reachability_confidence"]["estimate"]
        )
        self.assertIsNotNone(
            components["exploitability_confidence"]["estimate"]
        )
        self.assertIsNotNone(
            components["remediation_confidence"]["estimate"]
        )

    def test_scanner_reliability_is_not_exploitability(self) -> None:
        reliability = posterior_precision(95, 5)
        components = build_confidence_components(
            {
                "reachability": "unknown",
                "evidence": [],
                "remediation": None,
            },
            reliability,
        )

        self.assertGreater(
            components["scanner_rule_reliability"]["estimate"],
            0.9,
        )
        self.assertIsNone(
            components["exploitability_confidence"]["estimate"]
        )
        self.assertIn(
            "not exploitability evidence",
            components["exploitability_confidence"]["explanation"],
        )

    def test_overall_uses_conservative_leaf_minimum_without_double_counting(self) -> None:
        components = build_confidence_components(
            {
                "reachability": "reachable",
                "evidence": [{"kind": "exploit_validation"}],
                "remediation": {
                    "references": ["https://example.com/fix"],
                },
            },
            posterior_precision(95, 5),
        )
        overall = components["overall_decision_confidence"]
        leaf_bounds = [
            components[field]["conservative_bound"]
            for field in (
                "finding_validity_confidence",
                "reachability_confidence",
                "exploitability_confidence",
                "remediation_confidence",
            )
        ]

        self.assertEqual(overall["conservative_bound"], min(leaf_bounds))
        self.assertEqual(overall["decision_tier"], "Likely")
        self.assertNotIn(
            "scanner_rule_reliability",
            overall["evidence"],
        )

    def test_cycle_detection_prevents_circular_calculations(self) -> None:
        with self.assertRaisesRegex(ValueError, "circular"):
            validate_dependency_graph(
                {
                    "a": ("b",),
                    "b": ("a",),
                }
            )


if __name__ == "__main__":
    unittest.main()
