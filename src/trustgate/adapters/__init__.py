"""Public scanner-adapter SDK."""

from .base import ScannerAdapter
from .models import (
    AdapterCapability,
    AdapterConfig,
    AdapterContext,
    AdapterMetadata,
    AdapterParseResult,
    AdapterParseStatus,
    RepositoryContext,
)
from .registry import AdapterRegistry
from .runner import parse_with_isolation

__all__ = [
    "AdapterCapability",
    "AdapterConfig",
    "AdapterContext",
    "AdapterMetadata",
    "AdapterParseResult",
    "AdapterParseStatus",
    "AdapterRegistry",
    "RepositoryContext",
    "ScannerAdapter",
    "parse_with_isolation",
]
