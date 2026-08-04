from __future__ import annotations

import copy
import unittest

from trustgate.decisions.context import build_decision_context
from trustgate.decisions.engine import evaluate, reproduce_decision
from trustgate.decisions.models import DecisionOutcome
from trustgate.decisions.policy import default_policy

from tests.unit.decisions.test_context import finding


class DecisionEngineTests(unittest.TestCase):
    def test_high_risk_example_is_blocked_with_complete_explanation(self) -> None:
        context = build_decision_context(finding())

        decision = evaluate(context, default_policy())
        document = decision.to_dict()

        self.assertEqual(decision.outcome, DecisionOutcome.BLOCK_IMMEDIATELY)
        self.assertEqual(document["policy"]["matched_rule_id"], "block-exploitable-production-risk")
        self.assertEqual(document["policy"]["version"], "1.0.0")
        self.assertIn("Confirmed reachable high-severity issue", document["explanation"])
        self.assertIn("CISA KEV", " ".join(document["explanation"]))
        self.assertIn(document["evidence_strength"]["level"], {"moderate", "strong"})
        self.assertIn("evaluation_trace", document)
        self.assertEqual(
            document["policy"]["snapshot"]["policy_id"],
            "trustgate-contextual-default",
        )

    def test_decision_is_deterministic_and_reproducible_from_document(self) -> None:
        context = build_decision_context(finding())
        policy = default_policy()

        first = evaluate(context, policy).to_dict()
        second = evaluate(context, policy).to_dict()
        reproduced = reproduce_decision(copy.deepcopy(first)).to_dict()

        self.assertEqual(first, second)
        self.assertEqual(reproduced, first)
        self.assertEqual(first["decision_id"], first["reproduction_digest"])

    def test_unresolved_uncertainty_is_preserved_not_scored_away(self) -> None:
        context = build_decision_context(
            {
                "finding_id": "finding-unknown",
                "normalised_severity": "unknown",
                "reachability": "unknown",
                "status": "open",
            }
        )

        decision = evaluate(context, default_policy()).to_dict()

        self.assertEqual(decision["outcome"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(decision["evidence_strength"]["level"], "insufficient")
        self.assertIn("epss", decision["unresolved_uncertainty"])
        self.assertGreater(len(decision["unresolved_uncertainty"]), 5)

    def test_reproduction_detects_tampered_context_or_policy(self) -> None:
        document = evaluate(
            build_decision_context(finding()),
            default_policy(),
        ).to_dict()
        document["context"]["components"]["cisa_kev"]["value"] = False

        with self.assertRaisesRegex(ValueError, "reproduction digest"):
            reproduce_decision(document)


if __name__ == "__main__":
    unittest.main()
