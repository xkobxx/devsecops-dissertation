"""External integrations for Trust Gate.

Adapter-based integration layer supporting ticket trackers,
messaging, webhooks, and SIEM export.  All adapters are local-first:
they format payloads but never send without explicit configuration.
"""

from .adapters import (
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
from .tickets import (
    TicketState,
    TicketStore,
    TicketSyncError,
    assign_finding,
    sync_ticket_close,
)

__all__ = [
    "INTEGRATION_SCHEMA_VERSION",
    "IntegrationAdapter",
    "IntegrationError",
    "IntegrationType",
    "TicketState",
    "TicketStore",
    "TicketSyncError",
    "assign_finding",
    "create_adapter",
    "email_adapter",
    "jira_adapter",
    "linear_adapter",
    "microsoft_teams_adapter",
    "siem_adapter",
    "slack_adapter",
    "sync_ticket_close",
    "webhook_adapter",
]
