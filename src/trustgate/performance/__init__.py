"""Performance and reliability infrastructure for Trust Gate.

Provides parallel scanner execution, caching, incremental scanning,
resource limits, and duration tracking.
"""

from .execution import (
    PERFORMANCE_SCHEMA_VERSION,
    CacheConfig,
    PerformanceError,
    ResourceLimits,
    ScannerDuration,
    build_scan_plan,
    changed_file_filter,
    duration_tracker,
    incremental_scan_filter,
)
from .reliability import (
    PerformanceBenchmark,
    ReliabilityDashboard,
    failure_rate_report,
    regression_threshold_check,
)

__all__ = [
    "CacheConfig",
    "PERFORMANCE_SCHEMA_VERSION",
    "PerformanceBenchmark",
    "PerformanceError",
    "ReliabilityDashboard",
    "ResourceLimits",
    "ScannerDuration",
    "build_scan_plan",
    "changed_file_filter",
    "duration_tracker",
    "failure_rate_report",
    "incremental_scan_filter",
    "regression_threshold_check",
]
