"""Tests for explainable benchmark ground-truth matching."""

from __future__ import annotations

import unittest

from trustgate.benchmarks.matching import (
    adjudication_key,
    code_region_hash,
    match_finding,
)


GROUND_TRUTH = [
    {
        "id": "VULN-001",
        "file": "app.py",
        "line": 20,
        "symbol": "login",
        "cwe": "CWE-89",
        "source": "request.form",
        "sink": "execute",
        "code_region_hash": code_region_hash("query = user_input\nexecute(query)"),
        "scanner_rules": {
            "Bandit": ["B608"],
        },
    }
]


class BenchmarkMatchingTests(unittest.TestCase):
    def test_line_proximity_alone_never_creates_a_true_positive(self) -> None:
        decision = match_finding(
            {
                "tool": "Bandit",
                "rule_id": "B999",
                "file": "app.py",
                "line": 21,
            },
            GROUND_TRUTH,
        )

        self.assertEqual(decision["status"], "unmatched")
        self.assertTrue(decision["included_in_metrics"])
        self.assertIn(
            "Line proximity alone",
            decision["matching_reason"][0]["detail"],
        )

    def test_vulnerability_id_is_a_direct_match(self) -> None:
        decision = match_finding(
            {
                "tool": "Example",
                "rule_id": "RULE",
                "vulnerability_id": "VULN-001",
            },
            GROUND_TRUTH,
        )

        self.assertEqual(decision["status"], "matched")
        self.assertEqual(decision["ground_truth_id"], "VULN-001")
        self.assertEqual(
            decision["matching_reason"][0]["signal"],
            "vulnerability_id",
        )

    def test_scanner_rule_requires_the_same_file(self) -> None:
        wrong_file = match_finding(
            {
                "tool": "Bandit",
                "rule_id": "B608",
                "file": "other.py",
                "line": 20,
            },
            GROUND_TRUTH,
        )
        right_file = match_finding(
            {
                "tool": "Bandit",
                "rule_id": "B608",
                "file": "test-app/app.py",
                "line": 100,
            },
            GROUND_TRUTH,
        )

        self.assertEqual(wrong_file["status"], "unmatched")
        self.assertEqual(right_file["status"], "matched")
        self.assertNotIn(
            "line_proximity",
            {
                reason["signal"]
                for reason in right_file["matching_reason"]
            },
        )

    def test_file_symbol_and_cwe_match_without_line_proximity(self) -> None:
        decision = match_finding(
            {
                "tool": "Other",
                "rule_id": "RULE",
                "file": "app.py",
                "line": 200,
                "symbol": "login",
                "cwe": ["CWE-89"],
            },
            GROUND_TRUTH,
        )

        self.assertEqual(decision["status"], "matched")
        self.assertEqual(
            {
                reason["signal"]
                for reason in decision["matching_reason"]
            },
            {"file", "symbol", "cwe"},
        )

    def test_source_sink_and_region_hash_are_independent_identity_signals(self) -> None:
        source_sink = match_finding(
            {
                "tool": "Other",
                "rule_id": "RULE-A",
                "file": "app.py",
                "source": "request.form",
                "sink": "execute",
            },
            GROUND_TRUTH,
        )
        region_hash = match_finding(
            {
                "tool": "Other",
                "rule_id": "RULE-B",
                "file": "app.py",
                "code_region_hash": code_region_hash(
                    "# nearby comment changed\n"
                    "query = user_input\n\nexecute(query)"
                ),
            },
            GROUND_TRUTH,
        )

        self.assertEqual(source_sink["status"], "matched")
        self.assertEqual(region_hash["status"], "matched")

    def test_dense_file_with_equivalent_candidates_is_ambiguous(self) -> None:
        dense_truth = [
            {
                **GROUND_TRUTH[0],
                "id": "VULN-001",
                "line": 20,
            },
            {
                **GROUND_TRUTH[0],
                "id": "VULN-002",
                "line": 23,
            },
        ]
        finding = {
            "tool": "Bandit",
            "rule_id": "B608",
            "file": "app.py",
            "line": 21,
        }

        decision = match_finding(finding, dense_truth)

        self.assertEqual(decision["status"], "ambiguous")
        self.assertTrue(decision["ambiguous"])
        self.assertFalse(decision["included_in_metrics"])
        self.assertEqual(
            decision["candidate_ids"],
            ["VULN-001", "VULN-002"],
        )

    def test_manual_adjudication_resolves_an_ambiguous_match(self) -> None:
        dense_truth = [
            GROUND_TRUTH[0],
            {
                **GROUND_TRUTH[0],
                "id": "VULN-002",
            },
        ]
        finding = {
            "tool": "Bandit",
            "rule_id": "B608",
            "file": "app.py",
            "line": 21,
        }
        adjudications = {
            adjudication_key(finding): {
                "status": "approved",
                "ground_truth_id": "VULN-001",
                "reviewer": "security-reviewer",
                "reviewed_at": "2026-07-25T12:00:00Z",
                "reason": "The scanner trace reaches the first query sink.",
            }
        }

        decision = match_finding(
            finding,
            dense_truth,
            adjudications=adjudications,
        )

        self.assertEqual(decision["status"], "matched")
        self.assertEqual(decision["ground_truth_id"], "VULN-001")
        self.assertTrue(decision["included_in_metrics"])
        self.assertEqual(
            decision["matching_reason"][0]["signal"],
            "manual_adjudication",
        )


if __name__ == "__main__":
    unittest.main()
