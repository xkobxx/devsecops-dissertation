"""Base class for independently installable scanner adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Iterable, Mapping

from trustgate.fingerprints import fingerprint_finding
from trustgate.scanners.models import ScannerResult

from .models import AdapterContext, AdapterMetadata, RepositoryContext


class ScannerAdapter(ABC):
    """Lifecycle contract implemented by every TrustGate scanner adapter."""

    @abstractmethod
    def metadata(self) -> AdapterMetadata:
        """Describe scanner applicability, runtime, and capabilities."""

    @abstractmethod
    def is_applicable(self, repository_context: RepositoryContext) -> bool:
        """Return whether the scanner should run for this repository."""

    def prepare(self, context: AdapterContext) -> AdapterContext:
        """Prepare adapter execution without mutating global process state."""

        return context

    @abstractmethod
    def execute(self, target: Path, context: AdapterContext) -> ScannerResult:
        """Execute the scanner and return explicit health evidence."""

    def health_check(self, result: ScannerResult) -> bool:
        """Return whether execution produced a trustworthy scanner outcome."""

        return result.healthy

    @abstractmethod
    def parse(
        self, report: Path, context: AdapterContext
    ) -> Iterable[Mapping[str, Any]]:
        """Parse a native report into candidate findings."""

    def normalize(
        self, finding: Mapping[str, Any], context: AdapterContext
    ) -> dict[str, Any]:
        """Return an owned canonical-finding mapping."""

        normalized = dict(finding)
        normalized.setdefault("scanner", context.metadata.name)
        return normalized

    def fingerprint(
        self, finding: Mapping[str, Any], context: AdapterContext
    ) -> tuple[str, str]:
        """Create stable scanner and cross-scanner finding identifiers."""

        return fingerprint_finding(
            dict(finding),
            repository_root=context.repository.root,
        )

    def cleanup(self, context: AdapterContext) -> None:
        """Release adapter-local resources."""

        return None


__all__ = ["ScannerAdapter"]
