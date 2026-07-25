"""Immutable scan-plan contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping


class PlanningConfigurationError(ValueError):
    """Raised when scanner-planning overrides are contradictory or invalid."""


@dataclass(frozen=True, slots=True)
class PlanningOverrides:
    """Explicit operator choices that take precedence over auto-detection."""

    enable_scanners: frozenset[str] = field(default_factory=frozenset)
    disable_scanners: frozenset[str] = field(default_factory=frozenset)
    timeouts: Mapping[str, float] = field(default_factory=dict)
    dry_run: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "timeouts", MappingProxyType(dict(self.timeouts)))


@dataclass(frozen=True, slots=True)
class DataHandling:
    """How a scanner treats repository data."""

    data_leaves_runner: bool
    behaviour: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "data_leaves_runner": self.data_leaves_runner,
            "behaviour": self.behaviour,
        }


@dataclass(frozen=True, slots=True)
class ScanDecision:
    """One explainable scanner-selection decision."""

    scanner: str
    enabled: bool
    reason: str
    target_directories: tuple[str, ...]
    expected_outputs: tuple[str, ...]
    timeout_seconds: float
    data_handling: DataHandling
    decision_source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "enabled": self.enabled,
            "reason": self.reason,
            "target_directories": list(self.target_directories),
            "expected_outputs": list(self.expected_outputs),
            "timeout_seconds": self.timeout_seconds,
            "data_handling": self.data_handling.to_dict(),
            "decision_source": self.decision_source,
        }


@dataclass(frozen=True, slots=True)
class ScanPlan:
    """Complete pre-execution plan for a repository."""

    target: str
    detected_technologies: Mapping[str, Any]
    decisions: tuple[ScanDecision, ...]
    dry_run: bool = False
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "detected_technologies",
            MappingProxyType(dict(self.detected_technologies)),
        )

    @property
    def enabled_scanners(self) -> tuple[str, ...]:
        return tuple(
            decision.scanner for decision in self.decisions if decision.enabled
        )

    @property
    def skipped_scanners(self) -> tuple[str, ...]:
        return tuple(
            decision.scanner for decision in self.decisions if not decision.enabled
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "dry_run": self.dry_run,
            "detected_technologies": dict(self.detected_technologies),
            "enabled_scanners": list(self.enabled_scanners),
            "skipped_scanners": list(self.skipped_scanners),
            "decisions": [decision.to_dict() for decision in self.decisions],
        }


__all__ = [
    "DataHandling",
    "PlanningConfigurationError",
    "PlanningOverrides",
    "ScanDecision",
    "ScanPlan",
]
