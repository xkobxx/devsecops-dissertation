"""Public configuration contracts for bounded DAST execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class DastConfigurationError(ValueError):
    """Raised when a DAST request is unsafe or internally inconsistent."""


class DastMode(StrEnum):
    BASELINE = "baseline"
    API = "api"


class ScanMode(StrEnum):
    SAFE = "safe"
    ACTIVE = "active"


class TargetEnvironment(StrEnum):
    LOCAL = "local"
    PREVIEW = "preview"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass(frozen=True)
class DastConfig:
    target_url: str
    mode: DastMode = DastMode.BASELINE
    scan_mode: ScanMode = ScanMode.SAFE
    environment: TargetEnvironment = TargetEnvironment.PREVIEW
    scope_allowlist: tuple[str, ...] = ()
    rate_limit_per_second: int = 5
    request_limit: int = 500
    max_duration_seconds: int = 300
    openapi_path: str | None = None
    auth_type: str = "none"
    auth_header_name: str = "Authorization"
    auth_secret_environment: str = field(
        default="TRUSTGATE_DAST_AUTH_SECRET", repr=False
    )
    public_target_acknowledged: bool = False
    active_scan_acknowledged: bool = False
    production_scan_acknowledged: bool = False
    allow_private_target: bool = False


@dataclass(frozen=True)
class DastPlan:
    config: DastConfig
    target_host: str
    automation: dict[str, Any]
    sender_gate_script: str = field(repr=False)

    @property
    def rate_limit_per_second(self) -> int:
        return self.config.rate_limit_per_second

    @property
    def request_limit(self) -> int:
        return self.config.request_limit

    @property
    def timeout_seconds(self) -> int:
        return self.config.max_duration_seconds

    @property
    def authenticated(self) -> bool:
        return self.config.auth_type != "none"

    @property
    def redacted_configuration(self) -> dict[str, Any]:
        return {
            "target_url": self.config.target_url,
            "mode": self.config.mode.value,
            "scan_mode": self.config.scan_mode.value,
            "environment": self.config.environment.value,
            "scope_allowlist": list(self.config.scope_allowlist),
            "rate_limit_per_second": self.config.rate_limit_per_second,
            "request_limit": self.config.request_limit,
            "max_duration_seconds": self.config.max_duration_seconds,
            "openapi_path": self.config.openapi_path,
            "auth_type": self.config.auth_type,
            "auth_header_name": self.config.auth_header_name,
            "auth_secret": "[REDACTED]" if self.authenticated else None,
            "public_target_acknowledged": self.config.public_target_acknowledged,
            "active_scan_acknowledged": self.config.active_scan_acknowledged,
            "production_scan_acknowledged": (
                self.config.production_scan_acknowledged
            ),
            "allow_private_target": self.config.allow_private_target,
        }

