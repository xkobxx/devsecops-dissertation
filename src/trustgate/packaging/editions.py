"""Product edition definitions and feature gating.

Three editions: community (open source), professional, enterprise.

Safety invariants:
- Licensing failure never produces an incorrect clean result.
- Users can always access their raw security findings.
- Paid feature failure cannot suppress a real vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

PACKAGING_SCHEMA_VERSION = "1.0.0"


class Edition(str, Enum):
    COMMUNITY = "community"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class PackagingError(ValueError):
    """Raised when packaging/edition configuration is invalid."""


@dataclass(frozen=True)
class EditionFeature:
    """A feature available in one or more editions."""
    name: str
    description: str
    editions: tuple[Edition, ...]
    open_source: bool = False


# --- Feature registry ---

_FEATURES: list[EditionFeature] = [
    # Community (open source)
    EditionFeature("core_scanners", "Core scanner adapters", (Edition.COMMUNITY, Edition.PROFESSIONAL, Edition.ENTERPRISE), open_source=True),
    EditionFeature("sarif", "SARIF 2.1.0 generation", (Edition.COMMUNITY, Edition.PROFESSIONAL, Edition.ENTERPRISE), open_source=True),
    EditionFeature("basic_gate", "Basic security gate (severity-based)", (Edition.COMMUNITY, Edition.PROFESSIONAL, Edition.ENTERPRISE), open_source=True),
    EditionFeature("local_reports", "Local HTML/Markdown reports", (Edition.COMMUNITY, Edition.PROFESSIONAL, Edition.ENTERPRISE), open_source=True),
    # Professional
    EditionFeature("standard_policy_packs", "Standard policy packs", (Edition.PROFESSIONAL, Edition.ENTERPRISE)),
    EditionFeature("evidence_prioritisation", "Evidence-based prioritisation", (Edition.PROFESSIONAL, Edition.ENTERPRISE)),
    EditionFeature("epss_kev_enrichment", "EPSS and KEV threat enrichment", (Edition.PROFESSIONAL, Edition.ENTERPRISE)),
    EditionFeature("differential_scanning", "Differential/changed-file scanning", (Edition.PROFESSIONAL, Edition.ENTERPRISE)),
    EditionFeature("deduplication", "Cross-scanner deduplication", (Edition.PROFESSIONAL, Edition.ENTERPRISE)),
    EditionFeature("expiring_suppressions", "Expiring suppressions with revalidation", (Edition.PROFESSIONAL, Edition.ENTERPRISE)),
    EditionFeature("guided_remediation", "Guided remediation suggestions", (Edition.PROFESSIONAL, Edition.ENTERPRISE)),
    EditionFeature("private_repositories", "Private repository support", (Edition.PROFESSIONAL, Edition.ENTERPRISE)),
    # Enterprise
    EditionFeature("multi_repo_dashboard", "Multi-repository dashboard", (Edition.ENTERPRISE,)),
    EditionFeature("central_policies", "Central policy management", (Edition.ENTERPRISE,)),
    EditionFeature("assignment", "Finding assignment and ownership", (Edition.ENTERPRISE,)),
    EditionFeature("integrations", "External integrations (Jira, Linear, Slack, etc.)", (Edition.ENTERPRISE,)),
    EditionFeature("finding_lifecycle", "Full finding lifecycle management", (Edition.ENTERPRISE,)),
    EditionFeature("org_calibration", "Organisation-level calibration", (Edition.ENTERPRISE,)),
    EditionFeature("audit_logs", "Audit logging", (Edition.ENTERPRISE,)),
    EditionFeature("self_hosting", "Self-hosted deployment", (Edition.ENTERPRISE,)),
    EditionFeature("sso", "SSO authentication", (Edition.ENTERPRISE,)),
    EditionFeature("scim", "SCIM user provisioning", (Edition.ENTERPRISE,)),
    EditionFeature("rbac", "Role-based access control", (Edition.ENTERPRISE,)),
    EditionFeature("data_residency", "Data residency controls", (Edition.ENTERPRISE,)),
    EditionFeature("compliance_evidence", "Compliance evidence reports", (Edition.ENTERPRISE,)),
    EditionFeature("custom_policy_packs", "Custom policy packs", (Edition.ENTERPRISE,)),
    EditionFeature("enterprise_sla", "Enterprise SLA", (Edition.ENTERPRISE,)),
]

_FEATURE_MAP = {f.name: f for f in _FEATURES}


def list_editions() -> list[dict[str, Any]]:
    """List all editions with their feature counts."""
    result = []
    for edition in Edition:
        features = [f for f in _FEATURES if edition in f.editions]
        result.append({
            "edition": edition.value,
            "feature_count": len(features),
            "open_source_features": sum(1 for f in features if f.open_source),
        })
    return result


def edition_features(edition: str) -> list[dict[str, str]]:
    """List features available in an edition."""
    try:
        ed = Edition(edition)
    except ValueError as e:
        raise PackagingError(
            f"unknown edition: {edition}; "
            f"expected one of {', '.join(e.value for e in Edition)}"
        ) from e

    return [
        {"name": f.name, "description": f.description, "open_source": f.open_source}
        for f in _FEATURES
        if ed in f.editions
    ]


def check_feature_access(
    feature_name: str,
    *,
    edition: str = "community",
    license_valid: bool = True,
) -> dict[str, Any]:
    """Check whether a feature is accessible.

    Safety: if the feature protects security-critical functionality
    (gate, findings, reports), license failure degrades gracefully —
    raw findings are always accessible.
    """
    feature = _FEATURE_MAP.get(feature_name)
    if feature is None:
        raise PackagingError(f"unknown feature: {feature_name}")

    try:
        ed = Edition(edition)
    except ValueError:
        ed = Edition.COMMUNITY

    in_edition = ed in feature.editions

    # Safety invariant: open source features always work
    if feature.open_source:
        return {
            "feature": feature_name,
            "accessible": True,
            "reason": "open_source",
        }

    # Safety invariant: license failure cannot hide findings
    if not license_valid and feature_name in (
        "core_scanners", "sarif", "basic_gate", "local_reports",
    ):
        return {
            "feature": feature_name,
            "accessible": True,
            "reason": "safety_fallback",
            "warning": "License invalid but security features remain accessible",
        }

    if not in_edition:
        return {
            "feature": feature_name,
            "accessible": False,
            "reason": "edition_required",
            "required_edition": [
                e.value for e in feature.editions
            ],
        }

    if not license_valid:
        return {
            "feature": feature_name,
            "accessible": False,
            "reason": "license_invalid",
        }

    return {
        "feature": feature_name,
        "accessible": True,
        "reason": "licensed",
    }
