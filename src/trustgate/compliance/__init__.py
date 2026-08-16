"""Compliance framework mappings for Trust Gate.

Maps security evidence to regulatory and industry frameworks.
Every mapping states what automated evidence supports and what
requires manual verification.  No mapping claims complete compliance.
"""

from .mappings import (
    COMPLIANCE_SCHEMA_VERSION,
    FRAMEWORKS,
    ComplianceMappingError,
    build_evidence_report,
    framework_mapping,
    list_frameworks,
)

__all__ = [
    "COMPLIANCE_SCHEMA_VERSION",
    "ComplianceMappingError",
    "FRAMEWORKS",
    "build_evidence_report",
    "framework_mapping",
    "list_frameworks",
]
