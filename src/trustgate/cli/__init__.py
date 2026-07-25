"""Command-line interface for Trust Gate."""

from argparse import ArgumentParser
from collections.abc import Sequence

from trustgate import __version__
from trustgate.aggregation import add_arguments as add_aggregation_arguments
from trustgate.aggregation import run as run_aggregation
from trustgate.benchmarks.cli import add_arguments as add_benchmark_arguments
from trustgate.benchmarks.cli import run as run_benchmark
from trustgate.reporting import add_arguments as add_reporting_arguments
from trustgate.reporting import run as run_reporting
from trustgate.scanners.cli import add_arguments as add_scanner_arguments
from trustgate.scanners.cli import add_record_arguments
from trustgate.scanners.cli import run as run_scanner
from trustgate.scanners.cli import run_record as record_scanner


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="trustgate",
        description="Trust Gate: a local-first application-security decision platform.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    commands = parser.add_subparsers(dest="command")
    aggregate = commands.add_parser(
        "aggregate",
        help="Aggregate scanner reports and evaluate the legacy severity gate.",
    )
    add_aggregation_arguments(aggregate)
    aggregate.set_defaults(handler=run_aggregation)
    report = commands.add_parser(
        "report",
        help="Generate a static HTML report from normalised findings.",
    )
    add_reporting_arguments(report)
    report.set_defaults(handler=run_reporting)
    benchmark = commands.add_parser(
        "benchmark",
        help="Generate or verify versioned benchmark publications.",
    )
    add_benchmark_arguments(benchmark)
    benchmark.set_defaults(handler=run_benchmark)
    scanner_run = commands.add_parser(
        "scanner-run",
        help="Run one scanner and persist authoritative health metadata.",
    )
    add_scanner_arguments(scanner_run)
    scanner_run.set_defaults(handler=run_scanner)
    scanner_record = commands.add_parser(
        "scanner-record",
        help="Record health metadata for a scanner run by an external Action.",
    )
    add_record_arguments(scanner_record)
    scanner_record.set_defaults(handler=record_scanner)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 0
    return handler(args)


__all__ = ["build_parser", "main"]
