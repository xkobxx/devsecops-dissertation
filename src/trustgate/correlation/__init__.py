"""Deduplication, cross-scanner correlation, and corroboration."""

from trustgate.correlation.engine import (
    CorrelationConfig,
    ScannerContradiction,
    correlate_findings,
    deduplicate_findings,
)

__all__ = [
    "ScannerContradiction",
    "CorrelationConfig",
    "correlate_findings",
    "deduplicate_findings",
]
