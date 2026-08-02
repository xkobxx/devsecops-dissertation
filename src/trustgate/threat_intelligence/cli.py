"""CLI workflow for cache-backed threat-intelligence enrichment."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from trustgate.schema import write_validated_json

from .models import EnrichmentConfig, NetworkMode
from .service import enrich_scan_run


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--input",
        required=True,
        help="Canonical scan-run JSON to enrich.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Validated enriched scan-run output path.",
    )
    parser.add_argument(
        "--cache-dir",
        default=".trustgate/cache/threat-intelligence",
        help="Local threat-data cache directory.",
    )
    parser.add_argument(
        "--network-mode",
        choices=[mode.value for mode in NetworkMode],
        default=NetworkMode.METADATA_ONLY.value,
        help=(
            "disabled uses cache only; metadata-only sends advisory IDs; "
            "full may send dependency name, ecosystem, and version "
            "(default: metadata-only)."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds (default: 10).",
    )


def run(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    try:
        scan_run: Any = json.loads(input_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"could not load scan run {input_path}: {error}") from error
    if not isinstance(scan_run, dict):
        raise ValueError("scan-run input must be a JSON object")
    mode = NetworkMode(args.network_mode)
    enriched = enrich_scan_run(
        scan_run,
        config=EnrichmentConfig(
            cache_dir=Path(args.cache_dir),
            network_mode=mode,
            timeout_seconds=args.timeout,
            github_token=os.environ.get("GITHUB_TOKEN"),
            nvd_api_key=os.environ.get("NVD_API_KEY"),
        ),
    )
    write_validated_json(args.output, enriched, schema_name="scan-run")
    status = enriched["summary"]["threat_data"]["status"]
    if mode is NetworkMode.DISABLED:
        print(f"Threat enrichment completed offline from local cache ({status}).")
    else:
        print(f"Threat enrichment completed in {mode.value} mode ({status}).")
    return 0
