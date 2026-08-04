from __future__ import annotations

import unittest

from trustgate.policy.context import build_policy_context
from trustgate.policy.evaluator import evaluate_policy
from trustgate.policy.models import PolicyDocument

from tests.unit.policy.test_context import finding, scan_run
from tests.unit.policy.test_schema import policy_document


class PolicyEvaluatorTests(unittest.TestCase):
    def test_nested_policy_selects_first_match_and_maps_action(self) -> None:
        document = policy_document(
            {
                "any": [
                    {
                        "all": [
                            {"environment": "production"},
                            {"kev": True},
                        ]
                    },
                    {
                        "all": [
                            {"severity": "critical"},
                            {"reachability": "confirmed"},
                            {"cwe": ["CWE-89"]},
                        ]
                    },
                ]
            }
        )
        document["policies"].append(
            {
                "name": "later-rule",
                "action": "monitor",
                "when": {"severity": "critical"},
            }
        )
        context = build_policy_context(
            scan_run(),
            finding(),
            runtime_context={"introduced_in_pull_request": True},
        )

        result = evaluate_policy(PolicyDocument.from_dict(document), context)
        output = result.to_dict()

        self.assertEqual(output["matched_policy"], "roadmap-rule")
        self.assertEqual(output["action"], "block")
        self.assertEqual(output["outcome"], "BLOCK_IMMEDIATELY")
        self.assertEqual(output["policy_version"], "2026.08.1")
        self.assertEqual(len(output["trace"]), 2)
        self.assertTrue(output["trace"][0]["matched"])
        self.assertTrue(output["trace"][1]["matched"])

    def test_policy_evaluation_is_deterministic(self) -> None:
        document = PolicyDocument.from_dict(
            policy_document({"confidence_lower_bound": ">=0.80"})
        )
        context = build_policy_context(scan_run(), finding())

        first = evaluate_policy(document, context).to_dict()
        second = evaluate_policy(document, context).to_dict()

        self.assertEqual(first, second)
        self.assertRegex(first["evaluation_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_no_match_uses_explicit_default_action(self) -> None:
        document = policy_document({"severity": "low"})
        document["default_action"] = "insufficient_evidence"

        result = evaluate_policy(
            PolicyDocument.from_dict(document),
            build_policy_context(scan_run(), finding()),
        )

        self.assertIsNone(result.matched_policy)
        self.assertEqual(result.action.value, "insufficient_evidence")
        self.assertEqual(result.outcome, "INSUFFICIENT_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
