"""Source-specific, explainable severity decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


CANONICAL_SEVERITIES = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "unknown",
)

SCANNER_SEVERITY_MAPPINGS: dict[str, dict[str, str]] = {
    "bandit": {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    },
    "semgrep": {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "info",
    },
    "pip-audit": {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "MODERATE": "medium",
        "LOW": "low",
        "INFO": "info",
        "UNKNOWN": "unknown",
    },
    "trivy": {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "UNKNOWN": "unknown",
    },
    "gitleaks": {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
        "UNKNOWN": "unknown",
    },
    "zap": {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFORMATIONAL": "info",
        "INFO": "info",
    },
    "osv-scanner": {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MODERATE": "medium",
        "MEDIUM": "medium",
        "LOW": "low",
        "UNKNOWN": "unknown",
    },
    "grype": {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "NEGLIGIBLE": "info",
        "UNKNOWN": "unknown",
    },
    "checkov": {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
        "UNKNOWN": "unknown",
    },
    "hadolint": {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "info",
        "STYLE": "info",
        "IGNORE": "unknown",
    },
    "gosec": {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    },
    "brakeman": {
        "UNKNOWN": "unknown",
    },
    "spotbugs": {
        "1": "high",
        "2": "medium",
        "3": "low",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    },
    "eslint-security": {
        "ERROR": "high",
        "WARNING": "medium",
    },
    "trufflehog": {
        "HIGH": "high",
        "MEDIUM": "medium",
    },
    "codeql-sarif": {
        "CRITICAL": "critical",
        "ERROR": "high",
        "HIGH": "high",
        "WARNING": "medium",
        "MEDIUM": "medium",
        "NOTE": "info",
        "LOW": "low",
        "INFO": "info",
        "NONE": "unknown",
    },
}

_GENERIC_MAPPING = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "ERROR": "high",
    "MEDIUM": "medium",
    "MODERATE": "medium",
    "WARNING": "medium",
    "LOW": "low",
    "INFO": "info",
    "UNKNOWN": "unknown",
}

_HIGH_IMPACT_SECRET_TYPES = (
    "private-key",
    "private_key",
    "aws-access",
    "github-pat",
    "github-token",
    "gitlab-pat",
    "slack-access-token",
    "stripe-access-token",
)
_MEDIUM_IMPACT_SECRET_TYPES = (
    "api-key",
    "api_key",
    "password",
    "credential",
    "token",
)


@dataclass(frozen=True, slots=True)
class SeverityDecision:
    """One source-aware severity mapping with an evidence-quality indicator."""

    original: str | None
    normalised: str
    reason: str
    quality: str
    quality_reason: str
    rule: str


def normalise_scanner_severity(scanner: str, value: Any) -> SeverityDecision:
    """Map a scanner-native label without losing or guessing its source value."""

    scanner_key = scanner.strip().lower()
    original = None if value is None else str(value)
    if original is None or not original.strip():
        return SeverityDecision(
            original=original,
            normalised="unknown",
            reason=(
                f"{scanner} severity is missing; Trust Gate preserves it as unknown."
            ),
            quality="low",
            quality_reason="No scanner-native severity or validated advisory score.",
            rule=f"{scanner_key}:missing->unknown",
        )

    source_label = original.strip().upper()
    mapping = SCANNER_SEVERITY_MAPPINGS.get(scanner_key, _GENERIC_MAPPING)
    normalised = mapping.get(source_label, "unknown")
    if source_label in mapping:
        return SeverityDecision(
            original=original,
            normalised=normalised,
            reason=(
                f"{scanner} scanner severity {original} maps to Trust Gate "
                f"severity {normalised} using rule "
                f"{scanner_key}:{source_label}->{normalised}."
            ),
            quality=("low" if normalised == "unknown" else "high"),
            quality_reason=(
                "Scanner explicitly reported UNKNOWN."
                if normalised == "unknown"
                else "Direct scanner-native severity mapping."
            ),
            rule=f"{scanner_key}:{source_label}->{normalised}",
        )
    return SeverityDecision(
        original=original,
        normalised="unknown",
        reason=(
            f"{scanner} scanner severity {original} is not recognized by the "
            f"{scanner_key} mapping and remains unknown."
        ),
        quality="low",
        quality_reason="Unrecognized scanner-native severity label.",
        rule=f"{scanner_key}:{source_label}->unknown-unrecognized",
    )


def cvss_severity_decision(
    scanner: str,
    original: Any,
    *,
    score: float,
    version: int,
    source: str,
) -> SeverityDecision:
    """Return an indirect severity decision from a validated CVSS base score."""

    if score == 0:
        normalised = "info"
    elif score < 4:
        normalised = "low"
    elif score < 7:
        normalised = "medium"
    elif score < 9:
        normalised = "high"
    else:
        normalised = "critical"
    original_value = None if original is None else str(original)
    return SeverityDecision(
        original=original_value,
        normalised=normalised,
        reason=(
            f"{scanner} severity was missing or UNKNOWN; {source} CVSS v{version} "
            f"base score {score:g} maps to Trust Gate severity {normalised}."
        ),
        quality="medium",
        quality_reason=(
            "Validated CVSS base score fallback; no usable scanner-native label."
        ),
        rule=f"cvss-v{version}:{score:g}->{normalised}",
    )


def secret_severity_decision(
    rule_id: Any,
    explicit_severity: Any,
    *,
    verified: bool | None,
) -> SeverityDecision:
    """Consider secret type and validation while preserving explicit severity."""

    explicit = normalise_scanner_severity("gitleaks", explicit_severity)
    if explicit.original is not None and explicit.original.strip():
        return explicit

    secret_type = str(rule_id or "unknown").lower()
    if any(marker in secret_type for marker in _HIGH_IMPACT_SECRET_TYPES):
        base = "high"
        type_quality = "high"
    elif any(marker in secret_type for marker in _MEDIUM_IMPACT_SECRET_TYPES):
        base = "medium"
        type_quality = "medium"
    else:
        base = "unknown"
        type_quality = "low"

    if verified is True:
        normalised = "medium" if base == "unknown" else base
        quality = "medium" if type_quality == "low" else "high"
        validation = "verified"
    elif verified is False:
        normalised = (
            "medium"
            if base == "high"
            else "low"
            if base == "medium"
            else "unknown"
        )
        quality = "medium" if normalised != "unknown" else "low"
        validation = "explicitly unverified"
    else:
        normalised = "medium" if base == "high" else base
        quality = "medium" if normalised != "unknown" else "low"
        validation = "not validated"

    return SeverityDecision(
        original=None,
        normalised=normalised,
        reason=(
            f"Gitleaks severity is missing; secret type {secret_type} with "
            f"status {validation} maps to Trust Gate severity {normalised}."
        ),
        quality=quality,
        quality_reason=(
            f"Severity inferred from secret type and validation status ({validation})."
        ),
        rule=f"gitleaks-secret:{secret_type}:{validation}->{normalised}",
    )


def severity_quality_evidence(
    decision: SeverityDecision,
    *,
    reference: str,
) -> dict[str, str | None]:
    """Encode severity quality in the existing canonical evidence contract."""

    return {
        "kind": "severity_quality",
        "summary": (
            f"quality={decision.quality}; rule={decision.rule}; "
            f"{decision.quality_reason}"
        ),
        "reference": reference,
        "excerpt": decision.original,
    }


__all__ = [
    "CANONICAL_SEVERITIES",
    "SCANNER_SEVERITY_MAPPINGS",
    "SeverityDecision",
    "cvss_severity_decision",
    "normalise_scanner_severity",
    "secret_severity_decision",
    "severity_quality_evidence",
]
