"""Common scanner execution and health result model."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any


class ScannerState(StrEnum):
    """Outcome of one configured scanner."""

    CLEAN = "CLEAN"
    FINDINGS = "FINDINGS"
    FAILED_SCANNER = "FAILED_SCANNER"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"


class ParserStatus(StrEnum):
    """Whether a produced scanner report was parsed successfully."""

    NOT_RUN = "NOT_RUN"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class ScannerResult:
    """Evidence required to distinguish a clean scan from a failed scanner."""

    scanner: str
    state: ScannerState
    started_at: datetime
    ended_at: datetime
    exit_code: int | None
    timed_out: bool
    report_path: str
    report_produced: bool
    parser_status: ParserStatus
    version: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    finding_count: int = 0
    error: str | None = None
    required: bool = True

    @property
    def healthy(self) -> bool:
        return self.state in {ScannerState.CLEAN, ScannerState.FINDINGS}

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.ended_at - self.started_at).total_seconds())

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "state": self.state.value,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "report_path": self.report_path,
            "report_produced": self.report_produced,
            "parser_status": self.parser_status.value,
            "version": self.version,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
            "finding_count": self.finding_count,
            "error": self.error,
            "required": self.required,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScannerResult:
        """Restore a result from its JSON-compatible representation."""

        return cls(
            scanner=str(data["scanner"]),
            state=ScannerState(data["state"]),
            started_at=datetime.fromisoformat(data["started_at"]),
            ended_at=datetime.fromisoformat(data["ended_at"]),
            exit_code=data.get("exit_code"),
            timed_out=bool(data["timed_out"]),
            report_path=str(data["report_path"]),
            report_produced=bool(data["report_produced"]),
            parser_status=ParserStatus(data["parser_status"]),
            version=data.get("version"),
            stdout_path=data.get("stdout_path"),
            stderr_path=data.get("stderr_path"),
            finding_count=int(data.get("finding_count", 0)),
            error=data.get("error"),
            required=bool(data.get("required", True)),
        )
