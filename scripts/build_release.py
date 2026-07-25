#!/usr/bin/env python3
"""Build deterministic Trust Gate release archives and verification material."""

from __future__ import annotations

import argparse
from pathlib import Path

from trustgate.supply_chain.release import (
    ReleaseError,
    build_release_archives,
    generate_cyclonedx_sbom,
    generate_checksums,
    sign_release_artifacts,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", required=True, help="Git commit or tag to archive")
    parser.add_argument(
        "--tag",
        required=True,
        help="Expected release tag, which must equal v<package version>",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("release"),
        help="New output directory (default: release)",
    )
    parser.add_argument(
        "--sign",
        action="store_true",
        help="Create a keyless Sigstore bundle for each artifact",
    )
    parser.add_argument(
        "--cosign",
        default="cosign",
        help="Cosign executable used with --sign (default: cosign)",
    )
    args = parser.parse_args()

    repository = Path(__file__).resolve().parents[1]
    try:
        archives = build_release_archives(
            repository=repository,
            output_directory=args.output,
            ref=args.ref,
            expected_tag=args.tag,
        )
        sbom = generate_cyclonedx_sbom(
            repository=repository,
            output=args.output / f"trustgate-{args.tag}.cdx.json",
            ref=args.ref,
            expected_tag=args.tag,
        )
        checksum_manifest = generate_checksums(
            [*archives, sbom],
            args.output / "SHA256SUMS",
        )
        signed = (
            sign_release_artifacts(
                [*archives, sbom, checksum_manifest],
                cosign=args.cosign,
            )
            if args.sign
            else []
        )
    except ReleaseError as error:
        parser.error(str(error))

    for artifact in [*archives, sbom, checksum_manifest, *signed]:
        print(artifact)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
