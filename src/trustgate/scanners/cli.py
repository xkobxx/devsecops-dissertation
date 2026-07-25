"""CLI boundary for health-aware scanner command execution."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from .execution import execute_scanner, record_external_scanner

SCANNER_NAMES = ("bandit", "semgrep", "pip-audit", "trivy", "gitleaks", "zap")
DEFAULT_FINDING_EXIT_CODES = {
    "bandit": {1},
    "semgrep": set(),
    "pip-audit": {1},
    "trivy": set(),
    # Gitleaks defaults to 1 for both leaks and errors. Trust Gate invokes it
    # with --exit-code 3 so a completed scan with leaks cannot be confused
    # with a scanner failure.
    "gitleaks": {3},
    "zap": set(),
}


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scanner", choices=SCANNER_NAMES, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, default=None)
    parser.add_argument("--logs-dir", type=Path, default=None)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--version", dest="scanner_version", default=None)
    parser.add_argument(
        "--finding-exit-code",
        action="append",
        type=int,
        default=None,
        help="Exit code meaning findings were produced; repeat as needed.",
    )
    parser.add_argument(
        "scanner_command",
        nargs=argparse.REMAINDER,
        help="Scanner command and arguments, preceded by --",
    )


def run(args: argparse.Namespace) -> int:
    command = list(args.scanner_command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        print("Scanner command is required after --.")
        return 2
    if args.timeout <= 0:
        print("Scanner timeout must be greater than zero.")
        return 2

    metadata_path = args.metadata or args.report.with_name(
        f"{args.scanner}_execution.json"
    )
    logs_dir = args.logs_dir or args.report.parent / "logs"
    finding_exit_codes = set(
        args.finding_exit_code
        if args.finding_exit_code is not None
        else DEFAULT_FINDING_EXIT_CODES[args.scanner]
    )
    result = execute_scanner(
        scanner=args.scanner,
        command=command,
        report_path=args.report,
        metadata_path=metadata_path,
        logs_dir=logs_dir,
        timeout_seconds=args.timeout,
        finding_exit_codes=finding_exit_codes,
        version=args.scanner_version,
    )
    print(
        f"{args.scanner}: {result.state.value} "
        f"(exit={result.exit_code}, report={result.report_produced}, "
        f"metadata={metadata_path})"
    )
    return 0 if result.healthy else 2


def add_record_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scanner", choices=SCANNER_NAMES, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument(
        "--outcome",
        choices=["success", "failure", "cancelled", "skipped"],
        required=True,
    )
    parser.add_argument("--version", dest="scanner_version", required=True)


def run_record(args: argparse.Namespace) -> int:
    try:
        started_at = datetime.fromisoformat(args.started_at)
    except ValueError:
        print("Scanner start time must be an ISO-8601 timestamp.")
        return 2
    if started_at.tzinfo is None:
        print("Scanner start time must include a timezone.")
        return 2

    result = record_external_scanner(
        scanner=args.scanner,
        outcome=args.outcome,
        report_path=args.report,
        metadata_path=args.metadata,
        started_at=started_at,
        version=args.scanner_version,
    )
    print(
        f"{args.scanner}: recorded external outcome {args.outcome} "
        f"as {result.state.value}"
    )
    return 0


__all__ = [
    "DEFAULT_FINDING_EXIT_CODES",
    "SCANNER_NAMES",
    "add_arguments",
    "add_record_arguments",
    "run",
    "run_record",
]
