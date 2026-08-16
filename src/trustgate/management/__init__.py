"""Management plane for multi-repository and organisation oversight.

Aggregates findings, scanner health, policy compliance, and remediation
metrics across repositories.  All data stays local unless a deployment
mode explicitly permits upload.
"""

from .dashboard import (
    MANAGEMENT_SCHEMA_VERSION,
    ManagementPlaneError,
    autofix_acceptance_rate,
    autofix_verification_rate,
    benchmark_drift_summary,
    developer_hours_saved,
    finding_ownership_summary,
    mean_time_to_remediation,
    multi_repository_dashboard,
    organisation_risk_overview,
    policy_compliance_summary,
    reopened_finding_rate,
    repository_trends,
    scanner_health_summary,
    security_engineer_hours_saved,
    suppression_expiry_rate,
    suppression_expiry_summary,
    threat_intelligence_changes,
)

__all__ = [
    "MANAGEMENT_SCHEMA_VERSION",
    "ManagementPlaneError",
    "autofix_acceptance_rate",
    "autofix_verification_rate",
    "benchmark_drift_summary",
    "developer_hours_saved",
    "finding_ownership_summary",
    "mean_time_to_remediation",
    "multi_repository_dashboard",
    "organisation_risk_overview",
    "policy_compliance_summary",
    "reopened_finding_rate",
    "repository_trends",
    "scanner_health_summary",
    "security_engineer_hours_saved",
    "suppression_expiry_rate",
    "suppression_expiry_summary",
    "threat_intelligence_changes",
]
