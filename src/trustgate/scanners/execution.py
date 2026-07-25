"""Execute scanner commands without hiding failures."""

from __future__ import annotations

from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as package_version
import json
from pathlib import Path
import subprocess
from collections.abc import Sequence, Set

from .models import ParserStatus, ScannerResult, ScannerState

SCANNER_DISTRIBUTIONS = {
    "bandit": "bandit",
    "semgrep": "semgrep",
    "pip-audit": "pip-audit",
}


def detect_scanner_version(scanner: str) -> str | None:
    distribution = SCANNER_DISTRIBUTIONS.get(scanner)
    if distribution is None:
        return None
    try:
        return package_version(distribution)
    except PackageNotFoundError:
        return None


def _as_text(output: str | bytes | None) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output


def execute_scanner(
    *,
    scanner: str,
    command: Sequence[str],
    report_path: Path,
    metadata_path: Path,
    logs_dir: Path,
    timeout_seconds: float,
    finding_exit_codes: Set[int],
    version: str | None = None,
) -> ScannerResult:
    """Run one scanner and persist complete execution-health evidence."""

    report_path = report_path.resolve()
    metadata_path = metadata_path.resolve()
    logs_dir = logs_dir.resolve()
    logs_dir.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path = logs_dir / f"{scanner}.stdout.log"
    stderr_path = logs_dir / f"{scanner}.stderr.log"
    started_at = datetime.now(timezone.utc)
    exit_code: int | None = None
    timed_out = False
    error: str | None = None
    stdout = ""
    stderr = ""

    try:
        completed = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as timeout:
        timed_out = True
        stdout = _as_text(timeout.stdout)
        stderr = _as_text(timeout.stderr)
        error = f"Scanner timed out after {timeout_seconds:g} seconds."
    except OSError as execution_error:
        error = f"{type(execution_error).__name__}: {execution_error}"
        stderr = error + "\n"

    ended_at = datetime.now(timezone.utc)
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    report_produced = report_path.is_file()

    if timed_out or error is not None:
        state = ScannerState.FAILED_SCANNER
    elif exit_code not in {0, *finding_exit_codes}:
        state = ScannerState.FAILED_SCANNER
        error = f"Unexpected scanner exit code {exit_code}."
    elif not report_produced:
        state = ScannerState.FAILED_SCANNER
        error = "Expected scanner report was not produced."
    elif exit_code in finding_exit_codes:
        state = ScannerState.FINDINGS
    else:
        state = ScannerState.CLEAN

    result = ScannerResult(
        scanner=scanner,
        state=state,
        started_at=started_at,
        ended_at=ended_at,
        exit_code=exit_code,
        timed_out=timed_out,
        report_path=str(report_path),
        report_produced=report_produced,
        parser_status=ParserStatus.NOT_RUN,
        version=version if version is not None else detect_scanner_version(scanner),
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        error=error,
    )
    metadata_path.write_text(
        json.dumps(result.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )
    return result


def record_external_scanner(
    *,
    scanner: str,
    outcome: str,
    report_path: Path,
    metadata_path: Path,
    started_at: datetime,
    version: str | None,
) -> ScannerResult:
    """Record health for a scanner executed by an external GitHub Action."""

    ended_at = datetime.now(timezone.utc)
    report_path = report_path.resolve()
    metadata_path = metadata_path.resolve()
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    report_produced = report_path.is_file()
    successful = outcome == "success" and report_produced
    errors = []
    if outcome != "success":
        errors.append(f"External scanner action outcome was {outcome!r}.")
    if not report_produced:
        errors.append("Expected scanner report was not produced.")

    result = ScannerResult(
        scanner=scanner,
        state=ScannerState.CLEAN if successful else ScannerState.FAILED_SCANNER,
        started_at=started_at,
        ended_at=ended_at,
        exit_code=0 if outcome == "success" else 2,
        timed_out=False,
        report_path=str(report_path),
        report_produced=report_produced,
        parser_status=ParserStatus.NOT_RUN,
        version=version,
        error=" ".join(errors) or None,
    )
    metadata_path.write_text(
        json.dumps(result.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )
    return result


__all__ = [
    "detect_scanner_version",
    "execute_scanner",
    "record_external_scanner",
]
