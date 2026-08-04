from __future__ import annotations

import unittest

from trustgate.policy.context import POLICY_FIELDS, build_policy_context


def scan_run() -> dict[str, object]:
    return {
        "repository": "example/trustgate",
        "ref": "refs/heads/main",
        "trigger": "pull_request",
        "scanners": [
            {
                "scanner": "semgrep",
                "healthy": True,
                "state": "FINDINGS",
            }
        ],
    }


def finding() -> dict[str, object]:
    return {
        "finding_id": "finding-policy",
        "scanner": "semgrep",
        "normalised_severity": "critical",
        "cwe": ["CWE-89"],
        "cve": ["CVE-2026-1234"],
        "reachability": "reachable",
        "status": "open",
        "finding_validity_confidence": {
            "estimate": 0.96,
            "conservative_bound": 0.84,
        },
        "threat_intelligence": {
            "epss_probability": 0.91,
            "kev_status": True,
            "fixed_versions": ["2.0.1"],
        },
        "environment": {
            "runtime_environment": "production",
            "asset_criticality": "critical",
            "secret_validation_status": "valid",
            "suppression_expiry": "expired",
        },
    }


class PolicyContextTests(unittest.TestCase):
    def test_context_contains_all_seventeen_policy_fields(self) -> None:
        context = build_policy_context(
            scan_run(),
            finding(),
            runtime_context={"introduced_in_pull_request": True},
        )

        self.assertEqual(set(context.to_dict()["values"]), set(POLICY_FIELDS))
        self.assertEqual(len(POLICY_FIELDS), 17)
        self.assertEqual(context.value("severity"), "critical")
        self.assertEqual(context.value("cwe"), ["CWE-89"])
        self.assertEqual(context.value("cve"), ["CVE-2026-1234"])
        self.assertEqual(context.value("epss"), 0.91)
        self.assertIs(context.value("kev"), True)
        self.assertEqual(context.value("reachability"), "confirmed")
        self.assertEqual(context.value("environment"), "production")
        self.assertEqual(context.value("repository"), "example/trustgate")
        self.assertEqual(context.value("branch"), "main")
        self.assertEqual(context.value("asset_criticality"), "critical")
        self.assertEqual(context.value("confidence_lower_bound"), 0.84)
        self.assertEqual(context.value("finding_status"), "open")
        self.assertIs(context.value("introduced_in_pull_request"), True)
        self.assertIs(context.value("fix_availability"), True)
        self.assertEqual(context.value("scanner_health"), "healthy")
        self.assertEqual(context.value("secret_validation_status"), "valid")
        self.assertEqual(context.value("suppression_expiry"), "expired")

    def test_missing_inputs_remain_none_with_provenance(self) -> None:
        context = build_policy_context(
            {"repository": None, "ref": None, "trigger": "local", "scanners": []},
            {
                "finding_id": "incomplete",
                "scanner": "unknown",
                "normalised_severity": "unknown",
                "cwe": [],
                "cve": [],
                "reachability": "unknown",
                "status": "open",
                "environment": {},
            },
        )

        self.assertIsNone(context.value("epss"))
        self.assertIsNone(context.value("kev"))
        self.assertIsNone(context.value("repository"))
        self.assertIn("epss", context.unresolved_fields())
        self.assertEqual(context.evidence("severity"), "finding.normalised_severity")

    def test_suppression_expiry_comes_from_current_lifecycle_state(self) -> None:
        lifecycle_finding = finding()
        lifecycle_finding["status"] = "suppressed"
        lifecycle_finding["environment"].pop("suppression_expiry")
        lifecycle_finding["state_history"] = [
            {
                "to_state": "suppressed",
                "expires_at": "2026-08-10T12:00:00Z",
            }
        ]

        context = build_policy_context(scan_run(), lifecycle_finding)

        self.assertEqual(
            context.value("suppression_expiry"),
            "2026-08-10T12:00:00Z",
        )
        self.assertEqual(
            context.evidence("suppression_expiry"),
            "finding.state_history[-1].expires_at",
        )


if __name__ == "__main__":
    unittest.main()
