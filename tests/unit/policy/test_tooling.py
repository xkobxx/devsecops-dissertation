from __future__ import annotations

import unittest

from trustgate.policy.models import PolicyDocument
from trustgate.policy.tooling import (
    PolicyTestError,
    explain_policy_result,
    run_policy_tests,
    simulate_scan_run,
)

from tests.unit.decisions.test_persistence import scan_run
from tests.unit.policy.test_schema import policy_document


def runtime_context() -> dict[str, object]:
    return {
        "environment": "production",
        "introduced_in_pull_request": True,
    }


class PolicyToolingTests(unittest.TestCase):
    def test_simulation_evaluates_saved_findings_without_mutating_them(self) -> None:
        source = scan_run()
        document = PolicyDocument.from_dict(
            policy_document(
                {
                    "all": [
                        {"severity": "high"},
                        {"environment": "production"},
                    ]
                }
            )
        )

        simulation = simulate_scan_run(
            document,
            source,
            runtime_context=runtime_context(),
        )

        self.assertNotIn("policy_evaluation", source["findings"][0])
        self.assertEqual(simulation["total_findings"], 1)
        self.assertEqual(
            simulation["evaluations"][0]["outcome"],
            "BLOCK_IMMEDIATELY",
        )
        self.assertRegex(
            simulation["simulation_digest"],
            r"^sha256:[0-9a-f]{64}$",
        )
        repeated = simulate_scan_run(
            document,
            source,
            runtime_context=runtime_context(),
        )
        self.assertEqual(
            repeated["simulation_digest"],
            simulation["simulation_digest"],
        )

    def test_explanation_shows_policy_conditions_actual_values_and_provenance(self) -> None:
        document = PolicyDocument.from_dict(
            policy_document({"severity": "high"})
        )
        simulation = simulate_scan_run(document, scan_run())

        explanation = explain_policy_result(simulation["evaluations"][0])

        self.assertIn("roadmap-rule", explanation)
        self.assertIn("severity", explanation)
        self.assertIn("high", explanation)
        self.assertIn("finding.normalised_severity", explanation)
        self.assertIn("2026.08.1", explanation)

    def test_policy_unit_tests_compare_saved_findings_to_expectations(self) -> None:
        document = PolicyDocument.from_dict(
            policy_document({"severity": "high"})
        )
        expectations = {
            "version": 1,
            "tests": [
                {
                    "name": "high finding blocks",
                    "finding_id": "finding-001",
                    "expected_outcome": "BLOCK_IMMEDIATELY",
                    "expected_policy": "roadmap-rule",
                }
            ],
        }

        result = run_policy_tests(document, scan_run(), expectations)

        self.assertEqual(result["passed"], 1)
        self.assertEqual(result["failed"], 0)
        self.assertTrue(result["tests"][0]["passed"])

    def test_invalid_test_definitions_fail_instead_of_silently_passing(self) -> None:
        document = PolicyDocument.from_dict(
            policy_document({"severity": "high"})
        )

        with self.assertRaisesRegex(PolicyTestError, "expected_outcome"):
            run_policy_tests(
                document,
                scan_run(),
                {
                    "version": 1,
                    "tests": [
                        {
                            "name": "incomplete",
                            "finding_id": "finding-001",
                        }
                    ],
                },
            )


if __name__ == "__main__":
    unittest.main()
