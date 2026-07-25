"""Trust Gate report generation."""

import argparse
import os
import runpy
from typing import Any


DEFAULT_FINDINGS_PATH = "reports/findings.json"
DEFAULT_BENCHMARK_PATH = (
    "benchmarks/fixtures/python/flask_vulnerable/seeded_vulnerabilities.json"
)
DEFAULT_OUTPUT_PATH = "reports/dashboard.html"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--input",
        default=DEFAULT_FINDINGS_PATH,
        help=f"Normalised findings JSON (default: {DEFAULT_FINDINGS_PATH})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_PATH,
        help=f"Dashboard output path (default: {DEFAULT_OUTPUT_PATH})",
    )
    benchmark = parser.add_mutually_exclusive_group()
    benchmark.add_argument(
        "--benchmark-ground-truth",
        default=DEFAULT_BENCHMARK_PATH,
        help="Optional seeded benchmark ground-truth JSON",
    )
    benchmark.add_argument(
        "--no-benchmark-ground-truth",
        action="store_true",
        help="Generate a product report without benchmark metrics",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate the Trust Gate HTML report.")
    add_arguments(parser)
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def run(args: argparse.Namespace) -> int:
    benchmark_path = "" if args.no_benchmark_ground_truth else args.benchmark_ground_truth
    values = {
        "TRUSTGATE_FINDINGS_PATH": args.input,
        "TRUSTGATE_BENCHMARK_PATH": benchmark_path,
        "TRUSTGATE_REPORT_PATH": args.output,
    }
    previous: dict[str, Any] = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        runpy.run_module("trustgate.reporting.dashboard", run_name="__main__")
    except SystemExit as error:
        return int(error.code or 0)
    finally:
        for key, old_value in previous.items():
            if old_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_value
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(parse_args(argv))


__all__ = [
    "DEFAULT_BENCHMARK_PATH",
    "DEFAULT_FINDINGS_PATH",
    "DEFAULT_OUTPUT_PATH",
    "add_arguments",
    "build_parser",
    "main",
    "parse_args",
    "run",
]
