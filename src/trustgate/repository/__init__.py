"""Repository discovery contracts used by scan planning and adapters."""

from trustgate.repository.models import (
    DependencyInfo,
    DependencyScope,
    PackageContext,
    RepositoryContext,
)

__all__ = [
    "DependencyInfo",
    "DependencyScope",
    "PackageContext",
    "RepositoryContext",
]
