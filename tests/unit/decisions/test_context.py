from __future__ import annotations

import unittest

from trustgate.decisions.context import (
    DECISION_COMPONENTS,
    build_decision_context,
)


def finding() -> dict[str, object]:
    return {
        "finding_id": "finding-sqli",
        "original_severity": "ERROR",
        "normalised_severity": "high",
        "reachability": "reachable",
        "status": "acknowledged",
        "introduced_commit": "abcdef1234567",
        "finding_validity_confidence": {
            "estimate": 0.96,
            "conservative_bound": 0.91,
        },
        "threat_intelligence": {
            "epss_probability": 0.88,
            "kev_status": True,
            "fixed_versions": ["2.0.1"],
        },
        "environment": {
            "runtime_environment": "production",
            "internet_exposed": True,
            "authentication_required": False,
            "data_sensitivity": "restricted",
            "asset_criticality": "critical",
            "existing_controls": ["waf", "parameter-validation"],
            "public_exploit_available": True,
            "change_status": "new",
        },
        "remediation": {"summary": "Use parameterised queries."},
    }


class DecisionContextTests(unittest.TestCase):
    def test_context_contains_all_sixteen_named_components(self) -> None:
        context = build_decision_context(finding())

        self.assertEqual(
            set(context.to_dict()["components"]),
            set(DECISION_COMPONENTS),
        )
        self.assertEqual(len(DECISION_COMPONENTS), 16)
        self.assertEqual(context.value("finding_validity_confidence"), 0.91)
        self.assertEqual(context.value("original_severity"), "ERROR")
        self.assertEqual(context.value("normalised_severity"), "high")
        self.assertEqual(context.value("reachability"), "reachable")
        self.assertEqual(context.value("epss"), 0.88)
        self.assertIs(context.value("cisa_kev"), True)
        self.assertIs(context.value("public_exploit_availability"), True)
        self.assertIs(context.value("internet_exposure"), True)
        self.assertIs(context.value("authentication_requirements"), False)
        self.assertEqual(context.value("data_sensitivity"), "restricted")
        self.assertEqual(context.value("asset_criticality"), "critical")
        self.assertEqual(context.value("runtime_environment"), "production")
        self.assertEqual(
            context.value("existing_controls"),
            ["parameter-validation", "waf"],
        )
        self.assertIs(context.value("fix_availability"), True)
        self.assertEqual(context.value("new_existing_status"), "new")
        self.assertEqual(context.value("human_triage_state"), "acknowledged")

    def test_missing_values_remain_explicit_unresolved_uncertainty(self) -> None:
        context = build_decision_context(
            {
                "finding_id": "finding-incomplete",
                "normalised_severity": "unknown",
                "reachability": "unknown",
                "status": "open",
            }
        )

        missing = context.unresolved_uncertainty()
        self.assertIn("epss", missing)
        self.assertIn("cisa_kev", missing)
        self.assertIn("internet_exposure", missing)
        component = context.to_dict()["components"]["epss"]
        self.assertIsNone(component["value"])
        self.assertEqual(component["evidence"], [])
        self.assertIn("not available", component["uncertainty"])

    def test_explicit_runtime_context_overrides_finding_environment(self) -> None:
        context = build_decision_context(
            finding(),
            runtime_context={
                "runtime_environment": "staging",
                "internet_exposure": False,
                "existing_controls": [],
            },
        )

        self.assertEqual(context.value("runtime_environment"), "staging")
        self.assertIs(context.value("internet_exposure"), False)
        self.assertEqual(context.value("existing_controls"), [])
        self.assertIn(
            "runtime_context.internet_exposure",
            context.component("internet_exposure").evidence,
        )


if __name__ == "__main__":
    unittest.main()
