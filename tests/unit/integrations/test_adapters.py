"""Tests for integration adapters."""

from __future__ import annotations

import unittest

from trustgate.integrations.adapters import (
    INTEGRATION_SCHEMA_VERSION,
    IntegrationAdapter,
    IntegrationError,
    IntegrationType,
    create_adapter,
    email_adapter,
    jira_adapter,
    linear_adapter,
    microsoft_teams_adapter,
    siem_adapter,
    slack_adapter,
    webhook_adapter,
)


def _finding(**kwargs: object) -> dict:
    return {
        "finding_id": "f-001",
        "fingerprint": "abc123",
        "severity": "high",
        "scanner": "Bandit",
        "rule_id": "B101",
        "description": "Use of exec detected",
        "file_path": "app.py",
        "line": 42,
        **kwargs,
    }


class IntegrationAdapterBaseTests(unittest.TestCase):

    def test_format_finding_has_schema_version(self):
        adapter = IntegrationAdapter(
            integration_type=IntegrationType.WEBHOOK, name="test",
        )
        result = adapter.format_finding(_finding())
        self.assertEqual(result["schema_version"], INTEGRATION_SCHEMA_VERSION)

    def test_format_finding_includes_severity(self):
        adapter = IntegrationAdapter(
            integration_type=IntegrationType.WEBHOOK, name="test",
        )
        result = adapter.format_finding(_finding())
        self.assertEqual(result["severity"], "high")

    def test_format_batch(self):
        adapter = IntegrationAdapter(
            integration_type=IntegrationType.WEBHOOK, name="test",
        )
        results = adapter.format_batch([_finding(), _finding(severity="low")])
        self.assertEqual(len(results), 2)

    def test_title_format(self):
        adapter = IntegrationAdapter(
            integration_type=IntegrationType.WEBHOOK, name="test",
        )
        result = adapter.format_finding(_finding())
        self.assertIn("HIGH", result["title"])
        self.assertIn("B101", result["title"])


class LinearAdapterTests(unittest.TestCase):

    def test_linear_adapter_type(self):
        adapter = linear_adapter(team_id="team-1")
        self.assertEqual(adapter.integration_type, IntegrationType.LINEAR)

    def test_linear_includes_labels(self):
        adapter = linear_adapter()
        result = adapter.format_finding(_finding())
        self.assertIn("security:high", result["labels"])

    def test_linear_includes_team_id(self):
        adapter = linear_adapter(team_id="team-1")
        result = adapter.format_finding(_finding())
        self.assertEqual(result["team_id"], "team-1")


class JiraAdapterTests(unittest.TestCase):

    def test_jira_adapter_type(self):
        adapter = jira_adapter(project_key="SEC")
        self.assertEqual(adapter.integration_type, IntegrationType.JIRA)

    def test_jira_default_issue_type(self):
        adapter = jira_adapter()
        result = adapter.format_finding(_finding())
        self.assertEqual(result["issue_type"], "Bug")

    def test_jira_custom_issue_type(self):
        adapter = jira_adapter(issue_type="Security")
        result = adapter.format_finding(_finding())
        self.assertEqual(result["issue_type"], "Security")


class SlackAdapterTests(unittest.TestCase):

    def test_slack_includes_text(self):
        adapter = slack_adapter(channel="#security")
        result = adapter.format_finding(_finding())
        self.assertIn("HIGH", result["text"])
        self.assertEqual(result["channel"], "#security")


class MicrosoftTeamsAdapterTests(unittest.TestCase):

    def test_teams_card_text(self):
        adapter = microsoft_teams_adapter(webhook_url="https://example.com")
        result = adapter.format_finding(_finding())
        self.assertIn("HIGH", result["card_text"])


class EmailAdapterTests(unittest.TestCase):

    def test_email_subject(self):
        adapter = email_adapter(to="sec@example.com")
        result = adapter.format_finding(_finding())
        self.assertIn("HIGH", result["subject"])
        self.assertEqual(result["to"], "sec@example.com")


class WebhookAdapterTests(unittest.TestCase):

    def test_webhook_payload_structure(self):
        adapter = webhook_adapter(url="https://hook.example.com")
        result = adapter.format_finding(_finding())
        self.assertEqual(result["payload"]["event"], "finding.created")
        self.assertEqual(result["webhook_url"], "https://hook.example.com")


class SIEMAdapterTests(unittest.TestCase):

    def test_siem_cef_severity(self):
        adapter = siem_adapter()
        result = adapter.format_finding(_finding())
        self.assertEqual(result["cef_severity"], 7)  # high = 7
        self.assertEqual(result["event_type"], "security_finding")

    def test_siem_critical_severity(self):
        adapter = siem_adapter()
        result = adapter.format_finding(_finding(severity="critical"))
        self.assertEqual(result["cef_severity"], 10)


class CreateAdapterFactoryTests(unittest.TestCase):

    def test_create_all_types(self):
        for t in IntegrationType:
            adapter = create_adapter(t.value)
            self.assertEqual(adapter.integration_type, t)

    def test_unknown_type_rejected(self):
        with self.assertRaises(IntegrationError):
            create_adapter("carrier_pigeon")


if __name__ == "__main__":
    unittest.main()
