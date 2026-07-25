from copy import deepcopy
import unittest

from trustgate.confidence import build_confidence_components
from trustgate.correlation import (
    CorrelationConfig,
    ScannerContradiction,
    correlate_findings,
)

from tests.unit.schemas.test_schema_contracts import valid_finding


def finding(scanner: str, identity: str, **overrides: object) -> dict[str, object]:
    result = valid_finding()
    result.update(
        {
            "scanner": scanner,
            "finding_id": f"finding-{identity}",
            "fingerprint": f"v2:sha256:{identity:0<64}"[:74],
            "rule_id": f"{scanner}-sql-rule",
            "start_line": 42,
            "end_line": 42,
            "evidence": [],
            "raw_report_reference": {
                "path": f"reports/{scanner}.json",
                "sha256": identity[0] * 64,
                "scanner_finding_id": identity,
            },
        }
    )
    result.update(overrides)
    return result


RELIABILITY = {
    "displayed_estimate": 0.7,
    "gating_estimate": 0.45,
    "sample_size": 20,
    "maturity": "Directional",
    "decision_tier": "Directional",
    "true_positives": 14,
    "false_positives": 6,
    "interval": {"confidence_level": 0.95},
}


class CorroborationTests(unittest.TestCase):
    def test_independent_scanners_raise_validity_with_confidence_limits(self) -> None:
        bandit = finding("bandit", "a")
        semgrep = finding("semgrep", "b")
        single = correlate_findings([bandit])[0]
        corroborated = correlate_findings([bandit, semgrep])[0]

        self.assertGreater(
            corroborated["corroboration"]["estimate"],
            single["corroboration"]["estimate"],
        )
        self.assertGreater(
            corroborated["corroboration"]["conservative_bound"],
            single["corroboration"]["conservative_bound"],
        )
        interval = corroborated["corroboration"]["confidence_interval"]
        self.assertLess(interval["lower"], interval["upper"])
        self.assertEqual(interval["confidence_level"], 0.95)
        self.assertEqual(
            corroborated["corroboration"]["independent_scanner_count"],
            2,
        )

        single_confidence = build_confidence_components(single, RELIABILITY)
        corroborated_confidence = build_confidence_components(
            corroborated, RELIABILITY
        )
        self.assertGreater(
            corroborated_confidence["finding_validity_confidence"]["estimate"],
            single_confidence["finding_validity_confidence"]["estimate"],
        )
        self.assertIsNone(
            corroborated_confidence["exploitability_confidence"]["estimate"]
        )
        self.assertIn(
            "not exploitability",
            corroborated["corroboration"]["explanation"],
        )

    def test_shared_rule_ancestry_is_tracked_and_not_double_counted(self) -> None:
        bandit = finding("bandit", "c", rule_id="B608")
        semgrep = finding(
            "semgrep",
            "d",
            rule_id="python.shared.sqli",
        )
        config = CorrelationConfig(
            rule_ancestry={
                "bandit:B608": "shared/sql-injection-rule",
                "semgrep:python.shared.sqli": "shared/sql-injection-rule",
            }
        )

        issue = correlate_findings(
            [bandit, semgrep],
            config=config,
        )[0]

        self.assertEqual(
            issue["corroboration"]["independent_scanner_count"],
            1,
        )
        self.assertEqual(
            issue["corroboration"]["shared_rule_ancestry"],
            [
                {
                    "ancestry": "shared/sql-injection-rule",
                    "scanners": ["bandit", "semgrep"],
                }
            ],
        )
        self.assertEqual(issue["agreement_strength"], 0.0)
        self.assertFalse(
            any(item["kind"] == "corroboration" for item in issue["evidence"])
        )

    def test_rule_ancestry_keys_are_scanner_case_insensitive(self) -> None:
        bandit = finding("Bandit", "7", rule_id="B608")
        semgrep = finding(
            "Semgrep",
            "8",
            rule_id="python.shared.sqli",
        )

        issue = correlate_findings(
            [bandit, semgrep],
            config=CorrelationConfig(
                rule_ancestry={
                    "bandit:b608": "shared/sql",
                    "semgrep:python.shared.sqli": "shared/sql",
                }
            ),
        )[0]

        self.assertEqual(
            issue["corroboration"]["independent_scanner_count"],
            1,
        )

    def test_dast_and_human_confirmation_remain_separate(self) -> None:
        sast = finding(
            "semgrep",
            "e",
            evidence=[
                {
                    "kind": "human_confirmation",
                    "summary": "Reviewed by application security.",
                    "reference": "review:123",
                    "excerpt": "Confirmed vulnerable.",
                }
            ],
        )
        dast = finding(
            "zap",
            "f",
            category="dast",
        )

        issue = correlate_findings([sast, dast])[0]

        self.assertEqual(issue["corroboration"]["dast_confirmations"], ["zap"])
        self.assertEqual(
            issue["corroboration"]["human_confirmations"],
            [sast["evidence"][0]],
        )
        self.assertNotIn(
            "exploit_validation",
            {item["kind"] for item in issue["evidence"]},
        )

    def test_contradiction_reduces_conservative_corroboration_bound(self) -> None:
        bandit = finding("bandit", "1")
        semgrep = finding("semgrep", "2")
        without_contradiction = correlate_findings([bandit, semgrep])[0]
        with_contradiction = correlate_findings(
            [bandit, semgrep],
            contradictions=[
                ScannerContradiction(
                    scanner="review-tool",
                    finding_identity=str(bandit["fingerprint"]),
                    reason="Sanitizer is effective.",
                )
            ],
        )[0]

        self.assertLess(
            with_contradiction["corroboration"]["conservative_bound"],
            without_contradiction["corroboration"]["conservative_bound"],
        )

    def test_validity_uplift_scales_with_conservative_evidence_strength(self) -> None:
        bandit = finding("bandit", "4")
        semgrep = finding("semgrep", "5")
        gosec = finding("gosec", "6")

        two_sources = correlate_findings([bandit, semgrep])[0]
        three_sources = correlate_findings([bandit, semgrep, gosec])[0]
        two_confidence = build_confidence_components(two_sources, RELIABILITY)
        three_confidence = build_confidence_components(
            three_sources, RELIABILITY
        )

        self.assertGreater(
            three_confidence["finding_validity_confidence"]["estimate"],
            two_confidence["finding_validity_confidence"]["estimate"],
        )

    def test_configuration_and_inputs_are_defensively_copied(self) -> None:
        ancestry = {"bandit:B608": "shared"}
        config = CorrelationConfig(rule_ancestry=ancestry)
        ancestry["bandit:B608"] = "mutated"
        source = finding("bandit", "3", rule_id="B608")
        original = deepcopy(source)

        issue = correlate_findings([source], config=config)[0]

        self.assertEqual(source, original)
        self.assertEqual(
            issue["corroboration"]["independent_sources"],
            ["shared"],
        )


if __name__ == "__main__":
    unittest.main()
