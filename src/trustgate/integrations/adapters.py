"""Integration adapters for external services.

Each adapter formats a finding payload for its target system.
Sending is the caller's responsibility — adapters never make
network calls themselves.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

INTEGRATION_SCHEMA_VERSION = "1.0.0"


class IntegrationType(str, Enum):
    LINEAR = "linear"
    JIRA = "jira"
    SLACK = "slack"
    MICROSOFT_TEAMS = "microsoft_teams"
    EMAIL = "email"
    WEBHOOK = "webhook"
    SIEM = "siem"


class IntegrationError(ValueError):
    """Raised when integration configuration or payload is invalid."""


@dataclass
class IntegrationAdapter:
    """Base integration adapter that formats payloads for a target."""

    integration_type: IntegrationType
    name: str
    config: dict[str, Any] = field(default_factory=dict)

    def format_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Format a finding for this integration's target format."""
        base = {
            "integration_type": self.integration_type.value,
            "schema_version": INTEGRATION_SCHEMA_VERSION,
            "finding_id": finding.get("finding_id", finding.get("fingerprint")),
            "title": self._title(finding),
            "severity": finding.get("severity", "info"),
            "scanner": finding.get("scanner", "unknown"),
            "rule_id": finding.get("rule_id"),
        }
        base.update(self._extra_fields(finding))
        return base

    def format_batch(
        self, findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Format multiple findings."""
        return [self.format_finding(f) for f in findings]

    def _title(self, finding: dict[str, Any]) -> str:
        rule = finding.get("rule_id", "unknown")
        sev = finding.get("severity", "info").upper()
        scanner = finding.get("scanner", "")
        return f"[{sev}] {scanner}: {rule}"

    def _extra_fields(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Override in specific adapters to add target-specific fields."""
        return {}


# --- Concrete adapters ---


def _ticket_adapter(
    integration_type: IntegrationType,
    finding: dict[str, Any],
) -> dict[str, Any]:
    """Common fields for ticket-tracker integrations."""
    return {
        "description": finding.get("description", ""),
        "file_path": finding.get("file_path"),
        "line": finding.get("line"),
        "labels": [
            f"security:{finding.get('severity', 'info')}",
            f"scanner:{finding.get('scanner', 'unknown')}",
        ],
    }


def linear_adapter(**config: Any) -> IntegrationAdapter:
    """Create a Linear integration adapter."""
    adapter = IntegrationAdapter(
        integration_type=IntegrationType.LINEAR,
        name="Linear",
        config=config,
    )
    adapter._extra_fields = lambda f: {  # type: ignore[assignment]
        **_ticket_adapter(IntegrationType.LINEAR, f),
        "team_id": config.get("team_id"),
        "project_id": config.get("project_id"),
    }
    return adapter


def jira_adapter(**config: Any) -> IntegrationAdapter:
    """Create a Jira integration adapter."""
    adapter = IntegrationAdapter(
        integration_type=IntegrationType.JIRA,
        name="Jira",
        config=config,
    )
    adapter._extra_fields = lambda f: {  # type: ignore[assignment]
        **_ticket_adapter(IntegrationType.JIRA, f),
        "project_key": config.get("project_key"),
        "issue_type": config.get("issue_type", "Bug"),
    }
    return adapter


def slack_adapter(**config: Any) -> IntegrationAdapter:
    """Create a Slack integration adapter."""
    adapter = IntegrationAdapter(
        integration_type=IntegrationType.SLACK,
        name="Slack",
        config=config,
    )
    adapter._extra_fields = lambda f: {  # type: ignore[assignment]
        "channel": config.get("channel"),
        "text": (
            f":warning: *{f.get('severity', 'info').upper()}* finding "
            f"in `{f.get('scanner', '?')}`: {f.get('rule_id', '?')}"
        ),
    }
    return adapter


def microsoft_teams_adapter(**config: Any) -> IntegrationAdapter:
    """Create a Microsoft Teams integration adapter."""
    adapter = IntegrationAdapter(
        integration_type=IntegrationType.MICROSOFT_TEAMS,
        name="Microsoft Teams",
        config=config,
    )
    adapter._extra_fields = lambda f: {  # type: ignore[assignment]
        "webhook_url": config.get("webhook_url"),
        "card_title": f"Security Finding: {f.get('rule_id', '?')}",
        "card_text": (
            f"**{f.get('severity', 'info').upper()}** from "
            f"{f.get('scanner', 'unknown')}"
        ),
    }
    return adapter


def email_adapter(**config: Any) -> IntegrationAdapter:
    """Create an email integration adapter."""
    adapter = IntegrationAdapter(
        integration_type=IntegrationType.EMAIL,
        name="Email",
        config=config,
    )
    adapter._extra_fields = lambda f: {  # type: ignore[assignment]
        "to": config.get("to"),
        "subject": (
            f"[TrustGate] {f.get('severity', 'info').upper()} "
            f"finding: {f.get('rule_id', '?')}"
        ),
    }
    return adapter


def webhook_adapter(**config: Any) -> IntegrationAdapter:
    """Create a generic webhook integration adapter."""
    adapter = IntegrationAdapter(
        integration_type=IntegrationType.WEBHOOK,
        name="Webhook",
        config=config,
    )
    adapter._extra_fields = lambda f: {  # type: ignore[assignment]
        "webhook_url": config.get("url"),
        "payload": {
            "event": "finding.created",
            "finding": {
                k: f.get(k)
                for k in (
                    "finding_id", "fingerprint", "severity",
                    "scanner", "rule_id", "file_path", "line",
                )
            },
        },
    }
    return adapter


def siem_adapter(**config: Any) -> IntegrationAdapter:
    """Create a SIEM export adapter.

    Formats findings as structured events suitable for SIEM ingestion
    (CEF-style flat key-value pairs).
    """
    adapter = IntegrationAdapter(
        integration_type=IntegrationType.SIEM,
        name="SIEM",
        config=config,
    )
    adapter._extra_fields = lambda f: {  # type: ignore[assignment]
        "event_type": "security_finding",
        "siem_format": config.get("format", "json"),
        "cef_severity": {
            "critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0,
        }.get(f.get("severity", "info"), 0),
        "src_scanner": f.get("scanner"),
        "src_file": f.get("file_path"),
        "src_line": f.get("line"),
        "category": f.get("category", "application-security"),
    }
    return adapter


_ADAPTER_FACTORIES = {
    IntegrationType.LINEAR: linear_adapter,
    IntegrationType.JIRA: jira_adapter,
    IntegrationType.SLACK: slack_adapter,
    IntegrationType.MICROSOFT_TEAMS: microsoft_teams_adapter,
    IntegrationType.EMAIL: email_adapter,
    IntegrationType.WEBHOOK: webhook_adapter,
    IntegrationType.SIEM: siem_adapter,
}


def create_adapter(
    integration_type: str,
    **config: Any,
) -> IntegrationAdapter:
    """Factory for integration adapters by type string."""
    try:
        itype = IntegrationType(integration_type)
    except ValueError as e:
        raise IntegrationError(
            f"unknown integration type: {integration_type}; "
            f"expected one of {', '.join(t.value for t in IntegrationType)}"
        ) from e
    return _ADAPTER_FACTORIES[itype](**config)
