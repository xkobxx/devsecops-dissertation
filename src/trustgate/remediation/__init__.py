"""Deterministic, framework-aware source remediation."""

from .ai import (
    AIRemediationError,
    prepare_ai_context,
    publish_ai_remediation,
    request_ai_patch,
    stage_ai_patch,
    verify_ai_remediation,
)
from .engine import (
    RemediationError,
    RemediationIntegrityError,
    apply_remediation_plan,
    rollback_remediation,
)
from .guidance import generate_guidance
from .rules import supported_rules

__all__ = [
    "AIRemediationError",
    "RemediationError",
    "RemediationIntegrityError",
    "apply_remediation_plan",
    "generate_guidance",
    "prepare_ai_context",
    "publish_ai_remediation",
    "rollback_remediation",
    "request_ai_patch",
    "stage_ai_patch",
    "supported_rules",
    "verify_ai_remediation",
]
