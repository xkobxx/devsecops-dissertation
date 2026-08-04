"""Command-line SARIF generation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from .generation import generate_sarif, write_sarif


DEFAULT_INPUT = "reports/findings.json"
DEFAULT_OUTPUT = "reports/trustgate.sarif"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT,
        help=f"Canonical scan-run JSON (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Validated SARIF 2.1.0 output (default: {DEFAULT_OUTPUT})",
    )


def _load_scan_run(path: str | Path) -> dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("input must contain a JSON object")
    return document


def run(args: argparse.Namespace) -> int:
    try:
        document = generate_sarif(_load_scan_run(args.input))
        output = write_sarif(args.output, document)
    except (OSError, ValueError) as error:
        print(f"SARIF error: {error}", file=sys.stderr)
        return 2
    result_count = len(document["runs"][0]["results"])
    noun = "result" if result_count == 1 else "results"
    print(f"Generated SARIF with {result_count} {noun} -> {output}")
    return 0


__all__ = ["DEFAULT_INPUT", "DEFAULT_OUTPUT", "add_arguments", "run"]
