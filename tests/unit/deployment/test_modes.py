"""Tests for deployment mode configuration."""

from __future__ import annotations

import unittest

from trustgate.deployment.modes import (
    DEPLOYMENT_MODES,
    DeploymentConfig,
    DeploymentMode,
    DeploymentModeError,
    NetworkMode,
    validate_deployment_config,
)


class DeploymentModeTests(unittest.TestCase):

    def test_default_is_local(self):
        config = validate_deployment_config()
        self.assertEqual(config.mode, DeploymentMode.LOCAL)

    def test_none_config_is_local(self):
        config = validate_deployment_config(None)
        self.assertEqual(config.mode, DeploymentMode.LOCAL)

    # --- Local mode ---

    def test_local_scanning_in_ci(self):
        config = validate_deployment_config({"mode": "local"})
        self.assertEqual(config.network_mode, NetworkMode.DISABLED)

    def test_local_findings_remain_local(self):
        config = validate_deployment_config({"mode": "local"})
        self.assertTrue(config.findings_local)

    def test_local_policies_remain_local(self):
        config = validate_deployment_config({"mode": "local"})
        self.assertTrue(config.policies_local)

    def test_local_reporting_remains_local(self):
        config = validate_deployment_config({"mode": "local"})
        self.assertTrue(config.reporting_local)

    def test_local_threat_feeds_cached(self):
        config = validate_deployment_config({"mode": "local"})
        self.assertTrue(config.threat_feeds_cached)

    def test_local_no_telemetry(self):
        config = validate_deployment_config({"mode": "local"})
        self.assertFalse(config.telemetry_consent)

    def test_local_rejects_network_enabled(self):
        with self.assertRaises(DeploymentModeError):
            validate_deployment_config({
                "mode": "local",
                "network_mode": "full",
            })

    def test_local_rejects_telemetry(self):
        with self.assertRaises(DeploymentModeError):
            validate_deployment_config({
                "mode": "local",
                "telemetry_consent": True,
            })

    # --- Hybrid mode ---

    def test_hybrid_source_stays_local(self):
        config = validate_deployment_config({"mode": "hybrid"})
        self.assertTrue(config.source_code_local)

    def test_hybrid_uses_metadata_only_network(self):
        config = validate_deployment_config({"mode": "hybrid"})
        self.assertEqual(config.network_mode, NetworkMode.METADATA_ONLY)

    def test_hybrid_redacts_source_code(self):
        config = validate_deployment_config({"mode": "hybrid"})
        self.assertTrue(config.redaction.redact_source_code)

    def test_hybrid_has_upload_allowlist(self):
        config = validate_deployment_config({"mode": "hybrid"})
        self.assertTrue(config.upload_allowlist.require_approval)

    def test_hybrid_transmitted_fields_documented(self):
        config = validate_deployment_config({"mode": "hybrid"})
        self.assertTrue(config.transmitted_fields_documented)

    def test_hybrid_allowed_fields_present(self):
        config = validate_deployment_config({"mode": "hybrid"})
        self.assertIn("finding_id", config.redaction.allowed_fields)
        self.assertIn("severity", config.redaction.allowed_fields)

    # --- Full mode ---

    def test_full_mode_source_still_local(self):
        config = validate_deployment_config({"mode": "full"})
        self.assertTrue(config.source_code_local)

    def test_full_mode_telemetry_still_requires_consent(self):
        config = validate_deployment_config({"mode": "full"})
        self.assertFalse(config.telemetry_consent)

    # --- Validation ---

    def test_unknown_mode_rejected(self):
        with self.assertRaises(DeploymentModeError):
            validate_deployment_config({"mode": "enterprise-cloud"})

    def test_unknown_network_mode_rejected(self):
        with self.assertRaises(DeploymentModeError):
            validate_deployment_config({
                "mode": "full",
                "network_mode": "turbo",
            })

    def test_to_dict(self):
        config = validate_deployment_config({"mode": "local"})
        d = config.to_dict()
        self.assertEqual(d["mode"], "local")
        self.assertIn("redaction", d)
        self.assertIn("upload_allowlist", d)

    def test_all_three_modes_exist(self):
        self.assertEqual(len(DEPLOYMENT_MODES), 3)
        self.assertIn("local", DEPLOYMENT_MODES)
        self.assertIn("hybrid", DEPLOYMENT_MODES)
        self.assertIn("full", DEPLOYMENT_MODES)


if __name__ == "__main__":
    unittest.main()
