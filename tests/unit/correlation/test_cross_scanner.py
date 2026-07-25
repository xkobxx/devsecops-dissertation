from copy import deepcopy
import unittest

from trustgate.correlation import ScannerContradiction, correlate_findings

from tests.unit.schemas.test_schema_contracts import valid_finding


def finding(scanner: str, identity: str, **overrides: object) -> dict[str, object]:
    result = valid_finding()
    result.update(
        {
            "scanner": scanner,
            "finding_id": f"finding-{identity}",
            "fingerprint": f"v2:sha256:{identity:0<64}"[:74],
            "raw_report_reference": {
                "path": f"reports/{scanner}-{identity}.json",
                "sha256": identity[0] * 64,
                "scanner_finding_id": identity,
            },
            "evidence": [
                {
                    "kind": "code",
                    "summary": f"{scanner} evidence",
                    "reference": f"{scanner}:{identity}",
                    "excerpt": "security evidence",
                }
            ],
        }
    )
    result.update(overrides)
    return result


class CrossScannerCorrelationTests(unittest.TestCase):
    def test_bandit_and_semgrep_sql_injection_become_one_auditable_issue(self) -> None:
        bandit = finding(
            "bandit",
            "a",
            rule_id="B608",
            start_line=42,
            end_line=42,
        )
        semgrep = finding(
            "semgrep",
            "b",
            rule_id="python.lang.security.sqli",
            start_line=44,
            end_line=45,
        )
        original = deepcopy([bandit, semgrep])

        correlated = correlate_findings([bandit, semgrep])

        self.assertEqual(len(correlated), 1)
        issue = correlated[0]
        self.assertEqual(issue["supporting_scanners"], ["bandit", "semgrep"])
        self.assertEqual(issue["contradicting_scanners"], [])
        self.assertTrue(
            {"cwe", "file", "code_region"}.issubset(
                issue["correlation_signals"]
            )
        )
        self.assertIn("CWE", issue["correlation_reason"])
        self.assertEqual(len(issue["raw_evidence_references"]), 2)
        self.assertEqual(len(issue["evidence"]), 3)
        self.assertEqual([bandit, semgrep], original)

    def test_same_file_and_cwe_at_unrelated_regions_do_not_merge(self) -> None:
        first = finding(
            "bandit",
            "c",
            start_line=10,
            end_line=10,
            symbol="first_query",
            source="request.args['first']",
            sink="cursor.execute",
        )
        second = finding(
            "semgrep",
            "d",
            start_line=200,
            end_line=200,
            symbol="second_query",
            source="request.args['second']",
            sink="database.raw",
        )

        correlated = correlate_findings([first, second])

        self.assertEqual(len(correlated), 2)
        self.assertEqual(
            [item["supporting_scanners"] for item in correlated],
            [["bandit"], ["semgrep"]],
        )

    def test_all_roadmap_identity_signals_are_recorded(self) -> None:
        code_first = finding(
            "bandit",
            "e",
            symbol="search",
            source="request.args",
            sink="cursor.execute",
            code_region_hash="region-123",
        )
        code_second = finding(
            "semgrep",
            "f",
            symbol="search",
            source="request.args",
            sink="cursor.execute",
            code_region_hash="region-123",
        )
        dependency = {
            "name": "example",
            "version": "1.0",
            "ecosystem": "pypi",
            "purl": "pkg:pypi/example@1.0",
            "direct": True,
        }
        sca_first = finding(
            "pip-audit",
            "1",
            category="sca",
            file="requirements.txt",
            cwe=[],
            cve=["CVE-2026-12345"],
            dependency=dependency,
            symbol=None,
            source=None,
            sink=None,
            start_line=None,
            end_line=None,
        )
        sca_second = finding(
            "trivy",
            "2",
            category="sca",
            file="requirements.txt",
            cwe=[],
            cve=["CVE-2026-12345"],
            dependency=deepcopy(dependency),
            symbol=None,
            source=None,
            sink=None,
            start_line=None,
            end_line=None,
        )
        iac_first = finding(
            "checkov",
            "3",
            category="iac",
            cwe=[],
            file="infra/main.tf",
            infrastructure_resource="aws_s3_bucket.data",
            start_line=None,
            end_line=None,
        )
        iac_second = finding(
            "trivy",
            "4",
            category="iac",
            cwe=[],
            file="infra/main.tf",
            infrastructure_resource="aws_s3_bucket.data",
            start_line=None,
            end_line=None,
        )
        secret_first = finding(
            "gitleaks",
            "5",
            category="secrets",
            cwe=[],
            file=".env",
            secret_fingerprint="sha256:secret",
            start_line=3,
            end_line=3,
        )
        secret_second = finding(
            "trufflehog",
            "6",
            category="secrets",
            cwe=[],
            file=".env",
            secret_fingerprint="sha256:secret",
            start_line=3,
            end_line=3,
        )

        correlated = correlate_findings(
            [
                code_first,
                code_second,
                sca_first,
                sca_second,
                iac_first,
                iac_second,
                secret_first,
                secret_second,
            ]
        )
        signal_sets = [set(item["correlation_signals"]) for item in correlated]

        self.assertEqual(len(correlated), 4)
        self.assertTrue(
            any(
                {
                    "cwe",
                    "file",
                    "symbol",
                    "source",
                    "sink",
                    "code_region",
                }.issubset(signals)
                for signals in signal_sets
            )
        )
        self.assertTrue(
            any({"dependency", "cve"}.issubset(signals) for signals in signal_sets)
        )
        self.assertTrue(
            any("infrastructure_resource" in signals for signals in signal_sets)
        )
        self.assertTrue(
            any("secret_fingerprint" in signals for signals in signal_sets)
        )

    def test_explicit_contradiction_is_attached_to_the_matching_issue(self) -> None:
        bandit = finding("bandit", "7", start_line=42)
        semgrep = finding("semgrep", "8", start_line=43)

        issue = correlate_findings(
            [bandit, semgrep],
            contradictions=[
                ScannerContradiction(
                    scanner="manual-review-tool",
                    finding_identity=str(bandit["fingerprint"]),
                    reason="Data flow is sanitized.",
                )
            ],
        )[0]

        self.assertEqual(
            issue["contradicting_scanners"],
            ["manual-review-tool"],
        )
        self.assertIn("1 contradiction", issue["correlation_reason"])


if __name__ == "__main__":
    unittest.main()
