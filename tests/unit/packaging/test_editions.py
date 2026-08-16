"""Tests for product edition definitions and feature gating."""

from __future__ import annotations

import unittest

from trustgate.packaging.editions import (
    Edition,
    PackagingError,
    check_feature_access,
    edition_features,
    list_editions,
)


class ListEditionsTests(unittest.TestCase):

    def test_three_editions(self):
        editions = list_editions()
        self.assertEqual(len(editions), 3)

    def test_community_has_open_source(self):
        editions = list_editions()
        community = next(e for e in editions if e["edition"] == "community")
        self.assertGreater(community["open_source_features"], 0)

    def test_enterprise_has_most_features(self):
        editions = list_editions()
        counts = {e["edition"]: e["feature_count"] for e in editions}
        self.assertGreater(counts["enterprise"], counts["professional"])
        self.assertGreater(counts["professional"], counts["community"])


class EditionFeaturesTests(unittest.TestCase):

    def test_community_includes_core_scanners(self):
        features = edition_features("community")
        names = {f["name"] for f in features}
        self.assertIn("core_scanners", names)

    def test_community_includes_sarif(self):
        features = edition_features("community")
        names = {f["name"] for f in features}
        self.assertIn("sarif", names)

    def test_community_includes_basic_gate(self):
        features = edition_features("community")
        names = {f["name"] for f in features}
        self.assertIn("basic_gate", names)

    def test_community_includes_local_reports(self):
        features = edition_features("community")
        names = {f["name"] for f in features}
        self.assertIn("local_reports", names)

    def test_professional_includes_policy_packs(self):
        features = edition_features("professional")
        names = {f["name"] for f in features}
        self.assertIn("standard_policy_packs", names)

    def test_professional_includes_epss(self):
        features = edition_features("professional")
        names = {f["name"] for f in features}
        self.assertIn("epss_kev_enrichment", names)

    def test_enterprise_includes_dashboard(self):
        features = edition_features("enterprise")
        names = {f["name"] for f in features}
        self.assertIn("multi_repo_dashboard", names)

    def test_enterprise_includes_sso(self):
        features = edition_features("enterprise")
        names = {f["name"] for f in features}
        self.assertIn("sso", names)

    def test_enterprise_includes_rbac(self):
        features = edition_features("enterprise")
        names = {f["name"] for f in features}
        self.assertIn("rbac", names)

    def test_enterprise_includes_data_residency(self):
        features = edition_features("enterprise")
        names = {f["name"] for f in features}
        self.assertIn("data_residency", names)

    def test_enterprise_includes_compliance(self):
        features = edition_features("enterprise")
        names = {f["name"] for f in features}
        self.assertIn("compliance_evidence", names)

    def test_enterprise_includes_sla(self):
        features = edition_features("enterprise")
        names = {f["name"] for f in features}
        self.assertIn("enterprise_sla", names)

    def test_unknown_edition_rejected(self):
        with self.assertRaises(PackagingError):
            edition_features("ultimate")


class FeatureAccessTests(unittest.TestCase):

    def test_open_source_always_accessible(self):
        result = check_feature_access(
            "core_scanners", edition="community", license_valid=False,
        )
        self.assertTrue(result["accessible"])

    def test_paid_feature_needs_licence(self):
        result = check_feature_access(
            "multi_repo_dashboard", edition="enterprise", license_valid=False,
        )
        self.assertFalse(result["accessible"])

    def test_paid_feature_needs_edition(self):
        result = check_feature_access(
            "multi_repo_dashboard", edition="community", license_valid=True,
        )
        self.assertFalse(result["accessible"])

    def test_licenced_enterprise_feature_accessible(self):
        result = check_feature_access(
            "multi_repo_dashboard", edition="enterprise", license_valid=True,
        )
        self.assertTrue(result["accessible"])

    def test_unknown_feature_rejected(self):
        with self.assertRaises(PackagingError):
            check_feature_access("teleportation")

    def test_licence_failure_cannot_hide_findings(self):
        """Safety: raw findings accessible even without licence."""
        for feature in ("core_scanners", "sarif", "basic_gate", "local_reports"):
            result = check_feature_access(
                feature, edition="community", license_valid=False,
            )
            self.assertTrue(
                result["accessible"],
                f"{feature} must remain accessible without licence",
            )

    def test_licence_failure_cannot_produce_clean_result(self):
        """Paid feature failure should degrade, not pass silently."""
        result = check_feature_access(
            "evidence_prioritisation", edition="professional",
            license_valid=False,
        )
        self.assertFalse(result["accessible"])
        self.assertEqual(result["reason"], "license_invalid")


class ThirdPartyNoticesTests(unittest.TestCase):

    def test_notices_file_exists(self):
        from pathlib import Path
        notices = Path(__file__).parents[3] / "THIRD_PARTY_NOTICES.md"
        self.assertTrue(notices.exists())


class LicensingArchitectureTests(unittest.TestCase):

    def test_licensing_docs_exist(self):
        from pathlib import Path
        docs = Path(__file__).parents[3] / "docs" / "LICENSING_ARCHITECTURE.md"
        self.assertTrue(docs.exists())

    def test_licensing_module_importable(self):
        from trustgate.licensing import verify
        self.assertTrue(callable(verify))

    def test_invalid_key_degrades_gracefully(self):
        from trustgate.licensing import verify
        valid, message, payload = verify("")
        self.assertFalse(valid)

    def test_malformed_key_degrades_gracefully(self):
        from trustgate.licensing import verify
        valid, message, payload = verify("not.a.valid.key")
        self.assertFalse(valid)


if __name__ == "__main__":
    unittest.main()
