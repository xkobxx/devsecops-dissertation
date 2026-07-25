"""Typed contracts shared by TrustGate scanner adapters."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from trustgate.repository import RepositoryContext


class AdapterCapability(StrEnum):
    """Security capability supplied by an adapter."""

    SAST = "sast"
    SCA = "sca"
    IAC = "iac"
    SECRETS = "secrets"
    DAST = "dast"
    SBOM = "sbom"
    SARIF_IMPORT = "sarif-import"


@dataclass(frozen=True, slots=True)
class AdapterMetadata:
    """Discoverable metadata needed to plan and execute a scanner."""

    name: str
    version: str
    category: str
    supported_languages: tuple[str, ...]
    supported_files: tuple[str, ...]
    required_runtime: tuple[str, ...]
    default_timeout: float
    licence: str
    data_leaves_runner: bool
    report_format: str
    capabilities: tuple[AdapterCapability, ...]

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("adapter name must not be empty")
        if not self.version.strip():
            raise ValueError("adapter version must not be empty")
        if self.default_timeout <= 0:
            raise ValueError("default timeout must be greater than zero")
        if not self.report_format.strip():
            raise ValueError("report format must not be empty")

    def with_name(self, name: str) -> AdapterMetadata:
        """Return a copy using a different registry name."""

        return replace(self, name=name)


@dataclass(frozen=True, slots=True)
class AdapterConfig:
    """Runtime settings common to every adapter."""

    enabled: bool = True
    required: bool = True
    timeout_seconds: float | None = None
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("adapter timeout must be greater than zero")
        object.__setattr__(self, "options", MappingProxyType(dict(self.options)))


@dataclass(frozen=True, slots=True)
class AdapterContext:
    """Resolved context passed to each adapter lifecycle method."""

    repository: RepositoryContext
    reports_dir: Path
    config: AdapterConfig
    metadata: AdapterMetadata
    timeout_seconds: float

    @classmethod
    def create(
        cls,
        *,
        repository: RepositoryContext,
        reports_dir: Path,
        config: AdapterConfig,
        metadata: AdapterMetadata,
    ) -> AdapterContext:
        return cls(
            repository=repository,
            reports_dir=reports_dir,
            config=config,
            metadata=metadata,
            timeout_seconds=(
                config.timeout_seconds
                if config.timeout_seconds is not None
                else metadata.default_timeout
            ),
        )


class AdapterParseStatus(StrEnum):
    """Outcome of parsing an individual scanner report."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True, slots=True)
class AdapterParseResult:
    """Isolated output from one adapter parser."""

    adapter: str
    status: AdapterParseStatus
    findings: tuple[dict[str, Any], ...] = ()
    error: str | None = None


__all__ = [
    "AdapterCapability",
    "AdapterConfig",
    "AdapterContext",
    "AdapterMetadata",
    "AdapterParseResult",
    "AdapterParseStatus",
    "RepositoryContext",
]
