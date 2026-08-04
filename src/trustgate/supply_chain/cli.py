"""Command-line product SBOM generation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .release import ReleaseError, generate_cyclonedx_sbom, generate_spdx_sbom


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path("."),
        help="Git repository containing the product lockfiles (default: .)",
    )
    parser.add_argument(
        "--ref",
        default="HEAD",
        help="Git commit or tag to inventory (default: HEAD)",
    )
    parser.add_argument(
        "--tag",
        required=True,
        help="Expected release tag, which must equal v<package version>",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path("reports/sbom"),
        help="New SBOM output directory (default: reports/sbom)",
    )


def run(args: argparse.Namespace) -> int:
    cyclonedx = args.output_directory / f"trustgate-{args.tag}.cdx.json"
    spdx = args.output_directory / f"trustgate-{args.tag}.spdx.json"
    try:
        for output in (cyclonedx, spdx):
            if output.exists() or output.is_symlink():
                raise ReleaseError(f"refusing to overwrite release artifact: {output}")
        generated = [
            generate_cyclonedx_sbom(
                repository=args.repository,
                output=cyclonedx,
                ref=args.ref,
                expected_tag=args.tag,
            ),
            generate_spdx_sbom(
                repository=args.repository,
                output=spdx,
                ref=args.ref,
                expected_tag=args.tag,
            ),
        ]
    except (OSError, ReleaseError) as error:
        print(f"SBOM error: {error}", file=sys.stderr)
        return 2
    for output in generated:
        print(output)
    return 0


__all__ = ["add_arguments", "run"]
