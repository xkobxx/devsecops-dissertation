"""Tests for the management plane dashboard."""

from __future__ import annotations

import unittest

from trustgate.management.dashboard import (
    MANAGEMENT_SCHEMA_VERSION,
    ManagementPlaneError,
    benchmark_drift_summary,
    finding_ownership_summary,
    mean_time_to_remediation,
    multi_repository_dashboard,
    organisation_risk_overview,
    policy_compliance_summary,
    repository_trends,
    scanner_health_summary,
    suppression_expiry_summary,
    threat_intelligence_changes,
)


def _finding(
    severity: str = "high",
    scanner: str = "Bandit",
    **kwargs: object,
) -> dict:
    return {"severity": severity, "scanner": scanner, **kwargs}


def _repo(name: str, findings: list | None = None) -> dict:
    return {"name": name, "findings": findings or []}


class MultiRepositoryDashboardTests(unittest.TestCase):

    def test_empty_repos(self):
        result = multi_repository_dashboard([])
        self.assertEqual(result["repository_count"], 0)
        self.assertEqual(result["total_findings"], 0)

    def test_single_repo_counts(self):
        repos = [_repo("myapp", [_finding("high"), _finding("low")])]
        result = multi_repository_dashboard(repos)
        self.assertEqual(result["repository_count"], 1)
        self.assertEqual(result["total_findings"], 2)
        self.assertEqual(result["total_by_severity"]["high"], 1)
        self.assertEqual(result["total_by_severity"]["low"], 1)

    def test_multiple_repos_aggregated(self):
        repos = [
            _repo("app-a", [_finding("critical")]),
            _repo("app-b", [_finding("high"), _finding("high")]),
        ]
        result = multi_repository_dashboard(repos)
        self.assertEqual(result["total_findings"], 3)
        self.assertEqual(result["total_by_severity"]["critical"], 1)
        self.assertEqual(result["total_by_severity"]["high"], 2)

    def test_invalid_input_rejected(self):
        with self.assertRaises(ManagementPlaneError):
            multi_repository_dashboard("not a list")

    def test_schema_version(self):
        result = multi_repository_dashboard([])
        self.assertEqual(result["schema_version"], MANAGEMENT_SCHEMA_VERSION)


class OrganisationRiskOverviewTests(unittest.TestCase):

    def test_risk_score_weights_severity(self):
        repos = [_repo("app", [_finding("critical"), _finding("low")])]
        result = organisation_risk_overview(repos, organisation="acme")
        # critical=10, low=1 → 11
        self.assertEqual(result["risk_score"], 11)
        self.assertEqual(result["organisation"], "acme")

    def test_highest_risk_repos_ranked(self):
        repos = [
            _repo("safe", [_finding("low")]),
            _repo("risky", [_finding("critical"), _finding("critical")]),
        ]
        result = organisation_risk_overview(repos)
        self.assertEqual(result["highest_risk_repositories"][0], "risky")

    def test_empty_repos_zero_risk(self):
        result = organisation_risk_overview([])
        self.assertEqual(result["risk_score"], 0)


class RepositoryTrendsTests(unittest.TestCase):

    def test_empty_snapshots(self):
        result = repository_trends([])
        self.assertEqual(result["direction"], "stable")

    def test_improving_trend(self):
        snaps = [
            {"timestamp": 1, "findings": [_finding() for _ in range(10)]},
            {"timestamp": 2, "findings": [_finding() for _ in range(5)]},
        ]
        result = repository_trends(snaps)
        self.assertEqual(result["direction"], "improving")

    def test_worsening_trend(self):
        snaps = [
            {"timestamp": 1, "findings": [_finding()]},
            {"timestamp": 2, "findings": [_finding() for _ in range(5)]},
        ]
        result = repository_trends(snaps)
        self.assertEqual(result["direction"], "worsening")

    def test_stable_trend(self):
        snaps = [
            {"timestamp": 1, "findings": [_finding()]},
            {"timestamp": 2, "findings": [_finding()]},
        ]
        result = repository_trends(snaps)
        self.assertEqual(result["direction"], "stable")


class ScannerHealthTests(unittest.TestCase):

    def test_single_scanner_success_rate(self):
        runs = [
            {"scanner": "Bandit", "success": True, "duration_seconds": 1.0},
            {"scanner": "Bandit", "success": False, "duration_seconds": 2.0},
        ]
        result = scanner_health_summary(runs)
        bandit = result["scanners"]["Bandit"]
        self.assertEqual(bandit["total_runs"], 2)
        self.assertAlmostEqual(bandit["success_rate"], 0.5)

    def test_multiple_scanners_separated(self):
        runs = [
            {"scanner": "Bandit", "success": True, "duration_seconds": 1.0},
            {"scanner": "Semgrep", "success": True, "duration_seconds": 3.0},
        ]
        result = scanner_health_summary(runs)
        self.assertIn("Bandit", result["scanners"])
        self.assertIn("Semgrep", result["scanners"])

    def test_avg_duration_calculated(self):
        runs = [
            {"scanner": "Bandit", "success": True, "duration_seconds": 2.0},
            {"scanner": "Bandit", "success": True, "duration_seconds": 4.0},
        ]
        result = scanner_health_summary(runs)
        self.assertAlmostEqual(
            result["scanners"]["Bandit"]["avg_duration_seconds"], 3.0,
        )


class PolicyComplianceTests(unittest.TestCase):

    def test_all_passing(self):
        evals = [
            {"repository": "app", "policy": "sev-gate", "passed": True},
            {"repository": "app", "policy": "sev-gate", "passed": True},
        ]
        result = policy_compliance_summary(evals)
        self.assertAlmostEqual(result["compliance_rate"], 1.0)

    def test_mixed_results(self):
        evals = [
            {"repository": "app", "policy": "sev-gate", "passed": True},
            {"repository": "app", "policy": "sev-gate", "passed": False},
        ]
        result = policy_compliance_summary(evals)
        self.assertAlmostEqual(result["compliance_rate"], 0.5)

    def test_empty_evaluations(self):
        result = policy_compliance_summary([])
        self.assertAlmostEqual(result["compliance_rate"], 1.0)


class MeanTimeToRemediationTests(unittest.TestCase):

    def test_no_remediated_findings(self):
        result = mean_time_to_remediation([_finding()])
        self.assertIsNone(result["mttr_seconds"])
        self.assertEqual(result["sample_size"], 0)

    def test_mttr_calculated(self):
        findings = [
            {**_finding(), "opened_at": 0.0, "resolved_at": 86400.0},
            {**_finding(), "opened_at": 0.0, "resolved_at": 172800.0},
        ]
        result = mean_time_to_remediation(findings)
        # Average: (86400 + 172800) / 2 = 129600 → 1.5 days
        self.assertAlmostEqual(result["mttr_days"], 1.5)
        self.assertEqual(result["sample_size"], 2)

    def test_mttr_by_severity(self):
        findings = [
            {**_finding("critical"), "opened_at": 0.0, "resolved_at": 86400.0},
            {**_finding("low"), "opened_at": 0.0, "resolved_at": 864000.0},
        ]
        result = mean_time_to_remediation(findings)
        self.assertIn("critical", result["by_severity"])
        self.assertIn("low", result["by_severity"])
        self.assertLess(
            result["by_severity"]["critical"],
            result["by_severity"]["low"],
        )


class FindingOwnershipTests(unittest.TestCase):

    def test_unassigned_findings(self):
        findings = [_finding()]  # no owner field
        result = finding_ownership_summary(findings)
        self.assertEqual(result["unassigned"], 1)
        self.assertEqual(result["assigned"], 0)

    def test_assigned_findings(self):
        findings = [
            {**_finding(), "owner": "alice"},
            {**_finding(), "owner": "alice"},
            {**_finding(), "owner": "bob"},
        ]
        result = finding_ownership_summary(findings)
        self.assertEqual(result["assigned"], 3)
        self.assertEqual(result["owners"]["alice"]["total"], 2)
        self.assertEqual(result["owners"]["bob"]["total"], 1)


class SuppressionExpiryTests(unittest.TestCase):

    def test_no_suppressions(self):
        result = suppression_expiry_summary([])
        self.assertEqual(result["total"], 0)

    def test_expired_detected(self):
        suppressions = [
            {"finding_fingerprint": "abc", "expires_at": 1000.0},
        ]
        result = suppression_expiry_summary(
            suppressions, current_time=2000.0,
        )
        self.assertEqual(result["expired"], 1)

    def test_expiring_soon_detected(self):
        now = 1000.0
        suppressions = [
            {"finding_fingerprint": "abc", "expires_at": now + 3 * 86400},
        ]
        result = suppression_expiry_summary(
            suppressions, current_time=now,
        )
        self.assertEqual(result["expiring_within_7_days"], 1)

    def test_permanent_suppression_stays_active(self):
        suppressions = [{"finding_fingerprint": "abc"}]  # no expires_at
        result = suppression_expiry_summary(
            suppressions, current_time=1000.0,
        )
        self.assertEqual(result["active"], 1)


class BenchmarkDriftTests(unittest.TestCase):

    def test_no_drift(self):
        metrics = {"tools": {"Bandit": {"precision": 0.9, "recall": 0.8}}}
        result = benchmark_drift_summary(metrics, metrics)
        self.assertFalse(result["has_drift"])

    def test_drift_detected(self):
        baseline = {"tools": {"Bandit": {"precision": 0.9}}}
        current = {"tools": {"Bandit": {"precision": 0.7}}}
        result = benchmark_drift_summary(baseline, current)
        self.assertTrue(result["has_drift"])
        self.assertEqual(result["drifts"][0]["metric"], "precision")

    def test_small_change_ignored(self):
        baseline = {"tools": {"Bandit": {"f1": 0.90}}}
        current = {"tools": {"Bandit": {"f1": 0.905}}}
        result = benchmark_drift_summary(baseline, current)
        self.assertFalse(result["has_drift"])


class ThreatIntelligenceChangesTests(unittest.TestCase):

    def test_no_changes(self):
        enrichments = [{"cve_id": "CVE-2024-1234", "epss_score": 0.5}]
        result = threat_intelligence_changes(enrichments, enrichments)
        self.assertEqual(result["total_changes"], 0)

    def test_new_cve_detected(self):
        baseline = []
        current = [{"cve_id": "CVE-2024-9999", "epss_score": 0.9}]
        result = threat_intelligence_changes(baseline, current)
        self.assertIn("CVE-2024-9999", result["new_cves"])

    def test_removed_cve_detected(self):
        baseline = [{"cve_id": "CVE-2024-1111", "epss_score": 0.1}]
        current = []
        result = threat_intelligence_changes(baseline, current)
        self.assertIn("CVE-2024-1111", result["removed_cves"])

    def test_score_change_detected(self):
        baseline = [{"cve_id": "CVE-2024-5555", "epss_score": 0.1}]
        current = [{"cve_id": "CVE-2024-5555", "epss_score": 0.9}]
        result = threat_intelligence_changes(baseline, current)
        self.assertEqual(len(result["changed"]), 1)
        self.assertEqual(
            result["changed"][0]["changes"]["epss_score"]["now"], 0.9,
        )


if __name__ == "__main__":
    unittest.main()
