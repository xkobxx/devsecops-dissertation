"""Deployment mode definitions and validation.

Controls what data leaves the runner, where findings are stored,
and whether network calls are made.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DeploymentMode(str, Enum):
    LOCAL = "local"
    HYBRID = "hybrid"
    FULL = "full"


class NetworkMode(str, Enum):
    DISABLED = "disabled"
    METADATA_ONLY = "metadata-only"
    FULL = "full"


DEPLOYMENT_MODES = tuple(m.value for m in DeploymentMode)


class DeploymentModeError(ValueError):
    """Raised when deployment configuration is invalid."""


@dataclass
class RedactionConfig:
    """Field-level redaction for hybrid mode uploads."""

    redact_source_code: bool = True
    redact_file_paths: bool = False
    redact_descriptions: bool = False
    allowed_fields: list[str] = field(default_factory=lambda: [
        "finding_id", "fingerprint", "scanner", "rule_id",
        "category", "cwe", "severity", "confidence", "status",
    ])


@dataclass
class UploadAllowlist:
    """Controls which finding metadata may be uploaded in hybrid mode."""

    allowed_scanners: list[str] = field(default_factory=list)
    allowed_severities: list[str] = field(default_factory=lambda: [
        "critical", "high",
    ])
    require_approval: bool = True


@dataclass
class DeploymentConfig:
    """Complete deployment configuration."""

    mode: DeploymentMode = DeploymentMode.LOCAL
    network_mode: NetworkMode = NetworkMode.DISABLED

    # Local-only guarantees
    findings_local: bool = True
    policies_local: bool = True
    reporting_local: bool = True
    threat_feeds_cached: bool = True
    telemetry_consent: bool = False

    # Hybrid mode
    source_code_local: bool = True
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    upload_allowlist: UploadAllowlist = field(default_factory=UploadAllowlist)
    customer_managed_keys: bool = False
    transmitted_fields_documented: bool = False

    # Enterprise
    containerised: bool = False
    offline_threat_import: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "network_mode": self.network_mode.value,
            "findings_local": self.findings_local,
            "policies_local": self.policies_local,
            "reporting_local": self.reporting_local,
            "threat_feeds_cached": self.threat_feeds_cached,
            "telemetry_consent": self.telemetry_consent,
            "source_code_local": self.source_code_local,
            "redaction": {
                "redact_source_code": self.redaction.redact_source_code,
                "redact_file_paths": self.redaction.redact_file_paths,
                "allowed_fields": self.redaction.allowed_fields,
            },
            "upload_allowlist": {
                "allowed_scanners": self.upload_allowlist.allowed_scanners,
                "allowed_severities": self.upload_allowlist.allowed_severities,
                "require_approval": self.upload_allowlist.require_approval,
            },
            "customer_managed_keys": self.customer_managed_keys,
            "transmitted_fields_documented": self.transmitted_fields_documented,
        }


def _local_config() -> DeploymentConfig:
    return DeploymentConfig(
        mode=DeploymentMode.LOCAL,
        network_mode=NetworkMode.DISABLED,
        findings_local=True,
        policies_local=True,
        reporting_local=True,
        threat_feeds_cached=True,
        telemetry_consent=False,
        source_code_local=True,
    )


def _hybrid_config() -> DeploymentConfig:
    return DeploymentConfig(
        mode=DeploymentMode.HYBRID,
        network_mode=NetworkMode.METADATA_ONLY,
        findings_local=True,  # raw findings stay local
        policies_local=True,
        reporting_local=True,
        threat_feeds_cached=True,
        telemetry_consent=False,
        source_code_local=True,
        redaction=RedactionConfig(redact_source_code=True),
        upload_allowlist=UploadAllowlist(require_approval=True),
        transmitted_fields_documented=True,
    )


def _full_config() -> DeploymentConfig:
    return DeploymentConfig(
        mode=DeploymentMode.FULL,
        network_mode=NetworkMode.FULL,
        findings_local=False,
        policies_local=False,
        reporting_local=False,
        threat_feeds_cached=True,
        telemetry_consent=False,  # still requires explicit consent
        source_code_local=True,   # source never leaves by default
    )


_MODE_FACTORIES = {
    DeploymentMode.LOCAL: _local_config,
    DeploymentMode.HYBRID: _hybrid_config,
    DeploymentMode.FULL: _full_config,
}


def validate_deployment_config(
    config: dict[str, Any] | None = None,
) -> DeploymentConfig:
    """Create and validate a deployment configuration.

    If config is None, defaults to local mode.
    """
    if config is None:
        return _local_config()

    mode_str = config.get("mode", "local")
    try:
        mode = DeploymentMode(mode_str)
    except ValueError as e:
        raise DeploymentModeError(
            f"unknown deployment mode: {mode_str}; "
            f"expected one of {', '.join(DEPLOYMENT_MODES)}"
        ) from e

    result = _MODE_FACTORIES[mode]()

    # Apply overrides
    if "network_mode" in config:
        try:
            result.network_mode = NetworkMode(config["network_mode"])
        except ValueError as e:
            raise DeploymentModeError(
                f"unknown network mode: {config['network_mode']}"
            ) from e

    if "telemetry_consent" in config:
        result.telemetry_consent = bool(config["telemetry_consent"])

    # Local mode constraints
    if mode == DeploymentMode.LOCAL:
        if result.network_mode != NetworkMode.DISABLED:
            raise DeploymentModeError(
                "local mode requires network-mode: disabled"
            )
        if result.telemetry_consent:
            raise DeploymentModeError(
                "local mode does not support telemetry"
            )

    # Hybrid mode constraints
    if mode == DeploymentMode.HYBRID:
        if not result.source_code_local:
            raise DeploymentModeError(
                "hybrid mode requires source code to stay local"
            )

    return result
