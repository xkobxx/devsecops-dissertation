"""Tests for structured error messages."""

from __future__ import annotations

import unittest

from trustgate.errors import (
    TrustGateError,
    baseline_missing,
    configuration_error,
    network_unavailable,
    no_findings_produced,
    policy_evaluation_error,
    sarif_parse_error,
    scanner_failed,
    scanner_not_found,
)


class TrustGateErrorTests(unittest.TestCase):

    def test_render_includes_what_failed(self):
        err = TrustGateError(what_failed="X broke", why="reasons")
        self.assertIn("X broke", err.render())

    def test_render_includes_why(self):
        err = TrustGateError(what_failed="X", why="because Y")
        self.assertIn("because Y", err.render())

    def test_render_includes_coverage_impact(self):
        err = TrustGateError(
            what_failed="X", why="Y", coverage_impact="incomplete",
        )
        self.assertIn("incomplete", err.render())

    def test_render_includes_gate_trustworthy(self):
        err = TrustGateError(
            what_failed="X", why="Y", gate_trustworthy=False,
        )
        self.assertIn("unreliable", err.render())

    def test_render_includes_how_to_resolve(self):
        err = TrustGateError(
            what_failed="X", why="Y", how_to_resolve="do Z",
        )
        self.assertIn("do Z", err.render())

    def test_render_includes_log_location(self):
        err = TrustGateError(
            what_failed="X", why="Y", log_location="/var/log/tg.log",
        )
        self.assertIn("/var/log/tg.log", err.render())

    def test_render_omits_none_fields(self):
        err = TrustGateError(what_failed="X", why="Y")
        rendered = err.render()
        self.assertNotIn("Coverage:", rendered)
        self.assertNotIn("Gate trustworthy:", rendered)


class ErrorFactoryTests(unittest.TestCase):

    def test_scanner_not_found_mentions_scanner(self):
        err = scanner_not_found("Bandit")
        self.assertIn("Bandit", err.render())
        self.assertFalse(err.gate_trustworthy)

    def test_scanner_failed_includes_exit_code(self):
        err = scanner_failed("Semgrep", exit_code=2)
        self.assertIn("2", err.render())

    def test_sarif_parse_error_mentions_file(self):
        err = sarif_parse_error("report.sarif")
        self.assertIn("report.sarif", err.render())

    def test_policy_evaluation_error_suggests_validate(self):
        err = policy_evaluation_error("gate.yaml")
        self.assertIn("validate", err.render().lower())

    def test_baseline_missing_suggests_create(self):
        err = baseline_missing("main")
        self.assertIn("create", err.render().lower())

    def test_no_findings_exit_code_zero(self):
        err = no_findings_produced()
        self.assertEqual(err.exit_code, 0)

    def test_configuration_error_references_docs(self):
        err = configuration_error("bad-setting")
        self.assertIn("CONFIGURATION_REFERENCE", err.render())

    def test_network_unavailable_gate_still_trustworthy(self):
        err = network_unavailable("upload")
        self.assertTrue(err.gate_trustworthy)


if __name__ == "__main__":
    unittest.main()
