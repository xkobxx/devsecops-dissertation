"""Tests for compliance framework mappings."""

from __future__ import annotations

import unittest

from trustgate.compliance.mappings import (
    COMPLIANCE_SCHEMA_VERSION,
    FRAMEWORKS,
    ComplianceMappingError,
    build_evidence_report,
    framework_mapping,
    list_frameworks,
)


class ListFrameworksTests(unittest.TestCase):

    def test_nine_frameworks_registered(self):
        frameworks = list_frameworks()
        self.assertEqual(len(frameworks), 9)

    def test_owasp_top_10_present(self):
        ids = {f["id"] for f in list_frameworks()}
        self.assertIn("owasp-top-10", ids)

    def test_owasp_asvs_present(self):
        ids = {f["id"] for f in list_frameworks()}
        self.assertIn("owasp-asvs", ids)

    def test_owasp_samm_present(self):
        ids = {f["id"] for f in list_frameworks()}
        self.assertIn("owasp-samm", ids)

    def test_nist_ssdf_present(self):
        ids = {f["id"] for f in list_frameworks()}
        self.assertIn("nist-ssdf", ids)

    def test_cwe_present(self):
        ids = {f["id"] for f in list_frameworks()}
        self.assertIn("cwe", ids)

    def test_pci_dss_present(self):
        ids = {f["id"] for f in list_frameworks()}
        self.assertIn("pci-dss", ids)

    def test_iso_27001_present(self):
        ids = {f["id"] for f in list_frameworks()}
        self.assertIn("iso-27001", ids)

    def test_soc_2_present(self):
        ids = {f["id"] for f in list_frameworks()}
        self.assertIn("soc-2", ids)

    def test_cyber_essentials_present(self):
        ids = {f["id"] for f in list_frameworks()}
        self.assertIn("cyber-essentials", ids)

    def test_every_framework_has_mapping_version(self):
        for fw in list_frameworks():
            self.assertIn("mapping_version", fw)
            self.assertTrue(fw["mapping_version"])


class FrameworkMappingTests(unittest.TestCase):

    def test_unknown_framework_rejected(self):
        with self.assertRaises(ComplianceMappingError):
            framework_mapping("gdpr")

    def test_mapping_has_disclaimer(self):
        mapping = framework_mapping("owasp-top-10")
        self.assertIn("does not claim", mapping["disclaimer"])

    def test_mapping_has_schema_version(self):
        mapping = framework_mapping("pci-dss")
        self.assertEqual(mapping["schema_version"], COMPLIANCE_SCHEMA_VERSION)

    def test_controls_have_automated_evidence(self):
        mapping = framework_mapping("owasp-top-10")
        for control in mapping["controls"]:
            self.assertIn("automated_evidence", control)
            self.assertIsInstance(control["automated_evidence"], list)

    def test_controls_have_manual_verification(self):
        mapping = framework_mapping("owasp-top-10")
        for control in mapping["controls"]:
            self.assertIn("manual_verification_required", control)
            self.assertIsInstance(control["manual_verification_required"], list)

    def test_no_mapping_claims_compliance(self):
        """Every framework mapping's disclaimer disclaims compliance."""
        for fw_id in FRAMEWORKS:
            mapping = framework_mapping(fw_id)
            disclaimer = mapping["disclaimer"].lower()
            self.assertIn("does not claim", disclaimer)

    def test_every_mapping_has_versioned_id(self):
        for fw_id in FRAMEWORKS:
            mapping = framework_mapping(fw_id)
            self.assertIn("mapping_version", mapping)
            self.assertTrue(mapping["mapping_version"])


class BuildEvidenceReportTests(unittest.TestCase):

    def test_report_without_scans(self):
        report = build_evidence_report("owasp-top-10")
        self.assertEqual(report["type"], "compliance_evidence_report")
        self.assertIn("disclaimer", report)
        # Without scans, all evidence should be "not_evaluated"
        for ctrl in report["controls"]:
            for ev in ctrl["automated_evidence"]:
                self.assertEqual(ev["status"], "not_evaluated")

    def test_report_says_evidence_available_not_compliant(self):
        report = build_evidence_report("pci-dss")
        self.assertNotIn("compliant", report["disclaimer"].lower())
        self.assertIn("evidence", report["disclaimer"].lower())

    def test_report_with_matching_scans(self):
        scans = [
            {"category": "sast", "scanner": "Bandit", "finding_id": "1"},
            {"category": "sast", "scanner": "Semgrep", "finding_id": "2"},
        ]
        report = build_evidence_report("owasp-top-10", scan_results=scans)
        # At least some controls should have evidence_available
        statuses = [
            ev["status"]
            for ctrl in report["controls"]
            for ev in ctrl["automated_evidence"]
        ]
        self.assertIn("evidence_available", statuses)

    def test_report_summary_counts(self):
        report = build_evidence_report("cwe")
        summary = report["summary"]
        self.assertIn("total_controls", summary)
        self.assertIn("manual_verification_items", summary)
        self.assertGreater(summary["total_controls"], 0)

    def test_report_includes_manual_items(self):
        report = build_evidence_report("iso-27001")
        total_manual = report["summary"]["manual_verification_items"]
        self.assertGreater(total_manual, 0)

    def test_report_organisation_recorded(self):
        report = build_evidence_report(
            "soc-2", organisation="acme-corp",
        )
        self.assertEqual(report["organisation"], "acme-corp")

    def test_unknown_framework_rejected(self):
        with self.assertRaises(ComplianceMappingError):
            build_evidence_report("hipaa")


if __name__ == "__main__":
    unittest.main()
