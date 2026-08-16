"""Tests for management success metrics (PDF p. 40)."""

import unittest

from trustgate.management.dashboard import (
    autofix_acceptance_rate,
    autofix_verification_rate,
    developer_hours_saved,
    reopened_finding_rate,
    security_engineer_hours_saved,
    suppression_expiry_rate,
)


class TestSuppressionExpiryRate(unittest.TestCase):

    def test_no_suppressions_gives_zero_rate(self):
        result = suppression_expiry_rate([], current_time=1000.0)
        self.assertEqual(result["rate"], 0.0)
        self.assertEqual(result["total"], 0)

    def test_all_expired(self):
        suppressions = [
            {"expires_at": 500.0},
            {"expires_at": 800.0},
        ]
        result = suppression_expiry_rate(suppressions, current_time=1000.0)
        self.assertEqual(result["rate"], 1.0)
        self.assertEqual(result["expired"], 2)

    def test_some_active(self):
        suppressions = [
            {"expires_at": 500.0},
            {"expires_at": 2000.0},
        ]
        result = suppression_expiry_rate(suppressions, current_time=1000.0)
        self.assertAlmostEqual(result["rate"], 0.5)

    def test_permanent_not_expired(self):
        suppressions = [{"expires_at": None}]
        result = suppression_expiry_rate(suppressions, current_time=1000.0)
        self.assertEqual(result["expired"], 0)


class TestReopenedFindingRate(unittest.TestCase):

    def test_no_findings(self):
        result = reopened_finding_rate([])
        self.assertEqual(result["rate"], 0.0)

    def test_no_reopened(self):
        findings = [
            {"state_history": [{"to_state": "open"}, {"to_state": "resolved"}]},
        ]
        result = reopened_finding_rate(findings)
        self.assertEqual(result["resolved"], 1)
        self.assertEqual(result["reopened"], 0)

    def test_reopened_finding(self):
        findings = [
            {
                "state_history": [
                    {"to_state": "open"},
                    {"to_state": "resolved"},
                    {"to_state": "open"},
                ]
            },
        ]
        result = reopened_finding_rate(findings)
        self.assertEqual(result["reopened"], 1)
        self.assertAlmostEqual(result["rate"], 1.0)


class TestAutofixAcceptanceRate(unittest.TestCase):

    def test_no_remediations(self):
        result = autofix_acceptance_rate([])
        self.assertEqual(result["rate"], 0.0)

    def test_all_accepted(self):
        remediations = [
            {"proposed": True, "accepted": True},
            {"proposed": True, "accepted": True},
        ]
        result = autofix_acceptance_rate(remediations)
        self.assertEqual(result["rate"], 1.0)

    def test_partial_acceptance(self):
        remediations = [
            {"proposed": True, "accepted": True},
            {"proposed": True, "accepted": False},
        ]
        result = autofix_acceptance_rate(remediations)
        self.assertAlmostEqual(result["rate"], 0.5)


class TestAutofixVerificationRate(unittest.TestCase):

    def test_no_accepted(self):
        result = autofix_verification_rate([])
        self.assertEqual(result["rate"], 0.0)

    def test_all_verified(self):
        remediations = [
            {"accepted": True, "verified": True},
        ]
        result = autofix_verification_rate(remediations)
        self.assertEqual(result["rate"], 1.0)

    def test_unverified_fix(self):
        remediations = [
            {"accepted": True, "verified": False},
        ]
        result = autofix_verification_rate(remediations)
        self.assertEqual(result["rate"], 0.0)


class TestDeveloperHoursSaved(unittest.TestCase):

    def test_no_fixes(self):
        result = developer_hours_saved([])
        self.assertEqual(result["estimated_hours_saved"], 0.0)

    def test_hours_calculated(self):
        remediations = [
            {"accepted": True, "verified": True},
            {"accepted": True, "verified": True},
        ]
        result = developer_hours_saved(remediations, manual_hours_per_fix=3.0)
        self.assertEqual(result["estimated_hours_saved"], 6.0)

    def test_unverified_not_counted(self):
        remediations = [{"accepted": True, "verified": False}]
        result = developer_hours_saved(remediations)
        self.assertEqual(result["estimated_hours_saved"], 0.0)


class TestSecurityEngineerHoursSaved(unittest.TestCase):

    def test_no_runs(self):
        result = security_engineer_hours_saved([])
        self.assertEqual(result["estimated_hours_saved"], 0.0)

    def test_hours_calculated(self):
        runs = [
            {"findings_count": 10, "auto_triaged": True},
            {"findings_count": 5, "auto_triaged": True},
        ]
        result = security_engineer_hours_saved(runs, manual_hours_per_triage=1.0)
        self.assertEqual(result["estimated_hours_saved"], 15.0)


if __name__ == "__main__":
    unittest.main()
