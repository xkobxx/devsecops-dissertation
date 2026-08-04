"""Command-line CycloneDX VEX generation and signing."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from trustgate.supply_chain import ReleaseError, sign_release_artifacts

from .generation import VexError, generate_vex, write_vex

DEFAULT_INPUT = "reports/findings.json"
DEFAULT_ANALYSES = "vex-analyses.json"
DEFAULT_OUTPUT = "reports/trustgate.vex.cdx.json"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT,
        help=f"Canonical scan-run JSON (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--analyses",
        default=DEFAULT_ANALYSES,
        help=f"Approved VEX analysis JSON (default: {DEFAULT_ANALYSES})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"New CycloneDX VEX output (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--sign",
        action="store_true",
        help="Create a keyless Sigstore bundle for the VEX artifact",
    )
    parser.add_argument(
        "--cosign",
        default="cosign",
        help="Cosign executable used with --sign (default: cosign)",
    )


def _object(path: str | Path, label: str) -> dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise VexError(f"{label} must contain a JSON object")
    return document


def run(args: argparse.Namespace) -> int:
    try:
        document = generate_vex(
            _object(args.input, "input"),
            _object(args.analyses, "analyses"),
        )
        output = write_vex(args.output, document)
        bundles = (
            sign_release_artifacts([output], cosign=args.cosign) if args.sign else []
        )
    except (json.JSONDecodeError, OSError, ReleaseError, VexError) as error:
        print(f"VEX error: {error}", file=sys.stderr)
        return 2
    print(output)
    for bundle in bundles:
        print(bundle)
    return 0


__all__ = [
    "DEFAULT_ANALYSES",
    "DEFAULT_INPUT",
    "DEFAULT_OUTPUT",
    "add_arguments",
    "run",
]
