"""CLI integration for benchmark publication and consistency checks."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .publication import (
    BenchmarkPublicationError,
    DEFAULT_MANIFEST,
    check_publication,
    write_publication,
)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--manifest",
        default=DEFAULT_MANIFEST,
        help=f"Versioned benchmark manifest (default: {DEFAULT_MANIFEST})",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--write",
        action="store_true",
        help="Regenerate canonical metrics, confidence data, and documentation",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="Verify every published benchmark consumer is consistent",
    )


def run(args: argparse.Namespace) -> int:
    root = Path.cwd().resolve()
    manifest = (root / args.manifest).resolve()
    try:
        metrics = (
            write_publication(root, manifest)
            if args.write
            else check_publication(root, manifest)
        )
    except BenchmarkPublicationError as error:
        print(f"benchmark publication failed: {error}", file=sys.stderr)
        return 1
    mode = "generated" if args.write else "verified"
    print(
        f"Benchmark {metrics['benchmark_id']} "
        f"{metrics['benchmark_version']} {mode}: "
        f"{len(metrics['tools'])} scored tools."
    )
    return 0


__all__ = ["add_arguments", "run"]
