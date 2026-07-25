"""Failure-isolated adapter lifecycle helpers."""

from __future__ import annotations

from pathlib import Path

from .base import ScannerAdapter
from .models import (
    AdapterContext,
    AdapterParseResult,
    AdapterParseStatus,
)


def parse_with_isolation(
    adapter: ScannerAdapter,
    report: Path,
    context: AdapterContext,
) -> AdapterParseResult:
    """Parse one report without allowing its adapter to corrupt other results."""

    name = adapter.metadata().name
    try:
        findings = tuple(
            adapter.normalize(finding, context)
            for finding in adapter.parse(report, context)
        )
    except Exception as error:
        return AdapterParseResult(
            adapter=name,
            status=AdapterParseStatus.FAILED,
            error=f"{type(error).__name__}: {error}",
        )
    return AdapterParseResult(
        adapter=name,
        status=AdapterParseStatus.SUCCESS,
        findings=findings,
    )


__all__ = ["parse_with_isolation"]
