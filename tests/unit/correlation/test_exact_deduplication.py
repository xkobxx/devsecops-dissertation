from copy import deepcopy
import unittest

from trustgate.correlation import deduplicate_findings

from tests.unit.schemas.test_schema_contracts import valid_finding


def finding(**overrides: object) -> dict[str, object]:
    result = valid_finding()
    result.update(overrides)
    return result


class ExactDeduplicationTests(unittest.TestCase):
    def test_merges_repeated_same_scanner_findings_and_preserves_provenance(self) -> None:
        first = finding(
            start_line=40,
            end_line=40,
            evidence=[
                {
                    "kind": "code",
                    "summary": "Bandit occurrence one",
                    "reference": "bandit:one",
                    "excerpt": "execute(query)",
                }
            ],
            raw_report_reference={
                "path": "reports/bandit-1.json",
                "sha256": "1" * 64,
                "scanner_finding_id": "one",
            },
        )
        second = finding(
            start_line=44,
            end_line=45,
            evidence=[
                {
                    "kind": "code",
                    "summary": "Bandit occurrence two",
                    "reference": "bandit:two",
                    "excerpt": "execute(sql)",
                }
            ],
            raw_report_reference={
                "path": "reports/bandit-2.json",
                "sha256": "2" * 64,
                "scanner_finding_id": "two",
            },
        )
        original = deepcopy([first, second])

        deduplicated = deduplicate_findings([first, second])

        self.assertEqual(len(deduplicated), 1)
        issue = deduplicated[0]
        self.assertEqual(issue["occurrence_count"], 2)
        self.assertEqual(
            issue["locations"],
            [
                {
                    "file": "src/app.py",
                    "start_line": 40,
                    "end_line": 40,
                    "symbol": "search",
                },
                {
                    "file": "src/app.py",
                    "start_line": 44,
                    "end_line": 45,
                    "symbol": "search",
                },
            ],
        )
        self.assertEqual(len(issue["raw_evidence_references"]), 2)
        self.assertEqual(len(issue["evidence"]), 2)
        self.assertEqual([first, second], original)

    def test_sums_prior_occurrence_counts_and_removes_duplicate_evidence(self) -> None:
        evidence = {
            "kind": "code",
            "summary": "Same evidence",
            "reference": "scanner:item",
            "excerpt": None,
        }
        first = finding(occurrence_count=2, evidence=[evidence])
        second = finding(occurrence_count=3, evidence=[deepcopy(evidence)])

        issue = deduplicate_findings([first, second])[0]

        self.assertEqual(issue["occurrence_count"], 5)
        self.assertEqual(issue["evidence"], [evidence])

    def test_keeps_different_scanners_and_fingerprints_separate(self) -> None:
        same_issue_other_scanner = finding(
            scanner="bandit",
            finding_id="finding-bandit",
        )
        unrelated = finding(
            scanner="semgrep",
            finding_id="finding-unrelated",
            fingerprint="v2:sha256:" + "f" * 64,
            rule_id="different-rule",
        )

        deduplicated = deduplicate_findings(
            [same_issue_other_scanner, unrelated]
        )

        self.assertEqual(len(deduplicated), 2)

    def test_empty_input_is_deterministic(self) -> None:
        self.assertEqual(deduplicate_findings([]), [])


if __name__ == "__main__":
    unittest.main()
