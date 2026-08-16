"""Performance execution infrastructure.

Parallel scanner execution, caching, incremental scanning,
resource limits, and duration tracking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PERFORMANCE_SCHEMA_VERSION = "1.0.0"


class PerformanceError(ValueError):
    """Raised when performance configuration is invalid."""


@dataclass
class ResourceLimits:
    """Resource limits for scanner execution."""

    max_memory_mb: int = 2048
    max_cpu_seconds: int = 600
    max_output_bytes: int = 50 * 1024 * 1024  # 50 MB
    max_parallel_scanners: int = 4

    def validate(self) -> None:
        if self.max_memory_mb <= 0:
            raise PerformanceError("max_memory_mb must be positive")
        if self.max_cpu_seconds <= 0:
            raise PerformanceError("max_cpu_seconds must be positive")
        if self.max_parallel_scanners < 1:
            raise PerformanceError("max_parallel_scanners must be >= 1")


@dataclass
class CacheConfig:
    """Cache configuration for scanner installations and data."""

    cache_scanner_installations: bool = True
    cache_threat_data: bool = True
    cache_dependency_graphs: bool = True
    cache_dir: str | None = None
    max_cache_size_mb: int = 1024

    def to_dict(self) -> dict[str, Any]:
        return {
            "cache_scanner_installations": self.cache_scanner_installations,
            "cache_threat_data": self.cache_threat_data,
            "cache_dependency_graphs": self.cache_dependency_graphs,
            "cache_dir": self.cache_dir,
            "max_cache_size_mb": self.max_cache_size_mb,
        }


@dataclass
class ScannerDuration:
    """Duration record for a scanner run."""

    scanner: str
    duration_seconds: float
    success: bool
    files_scanned: int = 0
    findings_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "duration_seconds": round(self.duration_seconds, 3),
            "success": self.success,
            "files_scanned": self.files_scanned,
            "findings_count": self.findings_count,
        }


def build_scan_plan(
    scanners: list[str],
    *,
    limits: ResourceLimits | None = None,
    changed_files: list[str] | None = None,
) -> dict[str, Any]:
    """Build an execution plan for parallel scanner runs.

    Groups independent scanners for parallel execution within
    resource limits.
    """
    limits = limits or ResourceLimits()
    limits.validate()

    # ponytail: round-robin into parallel groups
    groups: list[list[str]] = []
    for i, scanner in enumerate(scanners):
        group_idx = i // limits.max_parallel_scanners
        if group_idx >= len(groups):
            groups.append([])
        groups[group_idx].append(scanner)

    return {
        "schema_version": PERFORMANCE_SCHEMA_VERSION,
        "type": "scan_plan",
        "total_scanners": len(scanners),
        "parallel_groups": [{"scanners": g} for g in groups],
        "resource_limits": {
            "max_memory_mb": limits.max_memory_mb,
            "max_cpu_seconds": limits.max_cpu_seconds,
            "max_parallel": limits.max_parallel_scanners,
        },
        "changed_files_only": changed_files is not None,
        "changed_file_count": len(changed_files) if changed_files else None,
    }


def changed_file_filter(
    all_files: list[str],
    changed_files: list[str],
) -> list[str]:
    """Filter to only changed files for incremental scanning."""
    changed_set = set(changed_files)
    return [f for f in all_files if f in changed_set]


def incremental_scan_filter(
    packages: list[dict[str, Any]],
    *,
    previous_checksums: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Filter packages to only rescan changed ones.

    Each package has 'name' and 'checksum'. Unchanged packages
    (matching previous checksum) are skipped.
    """
    if not previous_checksums:
        return packages  # no baseline = scan everything

    return [
        p for p in packages
        if p.get("checksum") != previous_checksums.get(p.get("name", ""))
    ]


def duration_tracker() -> dict[str, list[ScannerDuration]]:
    """Create a fresh duration tracking dict."""
    return {"durations": []}
