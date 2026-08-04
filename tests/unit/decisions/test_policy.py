from __future__ import annotations

import unittest

from trustgate.decisions.models import (
    Condition,
    DecisionOutcome,
    DecisionPolicy,
    DecisionRule,
)
from trustgate.decisions.policy import default_policy


class DecisionPolicyTests(unittest.TestCase):
    def test_contract_exposes_all_nine_roadmap_outcomes(self) -> None:
        self.assertEqual(
            {outcome.value for outcome in DecisionOutcome},
            {
                "BLOCK_IMMEDIATELY",
                "FIX_BEFORE_RELEASE",
                "FIX_WITHIN_SLA",
                "INVESTIGATE",
                "MONITOR",
                "TEMPORARILY_SUPPRESSED",
                "ACCEPTED_RISK",
                "LIKELY_NOISE",
                "INSUFFICIENT_EVIDENCE",
            },
        )

    def test_default_policy_documents_a_rule_for_every_outcome(self) -> None:
        policy = default_policy()

        covered = {rule.outcome for rule in policy.rules}
        covered.add(policy.default_outcome)
        self.assertEqual(covered, set(DecisionOutcome))
        self.assertTrue(policy.policy_id)
        self.assertTrue(policy.version)
        self.assertTrue(all(rule.explanation for rule in policy.rules))

    def test_policy_snapshot_is_declarative_and_versioned(self) -> None:
        policy = DecisionPolicy(
            policy_id="custom-policy",
            version="2026.08.1",
            rules=(
                DecisionRule(
                    rule_id="critical-kev",
                    outcome=DecisionOutcome.BLOCK_IMMEDIATELY,
                    all_of=(
                        Condition("normalised_severity", "equals", "critical"),
                        Condition("cisa_kev", "equals", True),
                    ),
                    explanation="Critical CISA KEV finding.",
                ),
            ),
            default_outcome=DecisionOutcome.INVESTIGATE,
        )

        snapshot = policy.to_dict()
        self.assertEqual(snapshot["policy_id"], "custom-policy")
        self.assertEqual(snapshot["version"], "2026.08.1")
        self.assertEqual(
            snapshot["rules"][0]["conditions"][1],
            {"component": "cisa_kev", "operator": "equals", "expected": True},
        )
        self.assertEqual(DecisionPolicy.from_dict(snapshot), policy)

    def test_policy_rejects_duplicate_rule_ids(self) -> None:
        rule = DecisionRule(
            rule_id="duplicate",
            outcome=DecisionOutcome.MONITOR,
            all_of=(Condition("normalised_severity", "equals", "low"),),
            explanation="Low severity finding.",
        )

        with self.assertRaisesRegex(ValueError, "duplicate rule id"):
            DecisionPolicy(
                policy_id="invalid",
                version="1",
                rules=(rule, rule),
                default_outcome=DecisionOutcome.INVESTIGATE,
            )


if __name__ == "__main__":
    unittest.main()
