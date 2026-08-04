"""CLI for local reachability and data-flow analysis."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from trustgate.schema import write_validated_json

from .service import analyze_scan_run


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", required=True, help="Canonical scan-run JSON.")
    parser.add_argument("--output", required=True, help="Analyzed scan-run output.")
    parser.add_argument(
        "--repository-root",
        default=".",
        help="Repository source root to analyze (default: current directory).",
    )
    parser.add_argument(
        "--vulnerable-symbols",
        help="JSON object mapping dependency names to vulnerable symbols.",
    )
    parser.add_argument(
        "--deployment-inventory",
        help="JSON object with the package names included in deployment.",
    )
    parser.add_argument(
        "--dynamic-evidence",
        help="JSON array of DAST observations to correlate.",
    )


def run(args: argparse.Namespace) -> int:
    scan_run = _json(Path(args.input))
    if not isinstance(scan_run, dict):
        raise ValueError("scan-run input must be a JSON object")
    symbol_data = _json(Path(args.vulnerable_symbols)) if args.vulnerable_symbols else {}
    if not isinstance(symbol_data, dict) or not all(
        isinstance(key, str) and isinstance(value, list)
        for key, value in symbol_data.items()
    ):
        raise ValueError("vulnerable-symbols must map package names to arrays")
    deployment_data = (
        _json(Path(args.deployment_inventory))
        if args.deployment_inventory
        else None
    )
    if deployment_data is not None and (
        not isinstance(deployment_data, dict)
        or not isinstance(deployment_data.get("packages"), list)
    ):
        raise ValueError("deployment inventory must contain a packages array")
    dynamic_data = _json(Path(args.dynamic_evidence)) if args.dynamic_evidence else []
    if isinstance(dynamic_data, dict):
        dynamic_data = dynamic_data.get("observations")
    if not isinstance(dynamic_data, list):
        raise ValueError("dynamic evidence must be an array of observations")

    analyzed = analyze_scan_run(
        scan_run,
        repository_root=Path(args.repository_root),
        vulnerable_symbols=symbol_data,
        deployed_packages=(
            deployment_data["packages"] if deployment_data is not None else None
        ),
        dynamic_observations=dynamic_data,
    )
    write_validated_json(args.output, analyzed, schema_name="scan-run")
    summary = analyzed["summary"]["reachability_analysis"]
    print(
        "Reachability analysis completed: "
        f"{summary['confirmed_reachable']} dependency path(s), "
        f"{summary['source_paths_found']} source-to-sink path(s), "
        f"{summary['dynamically_confirmed']} dynamic confirmation(s)."
    )
    return 0


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"could not load JSON {path}: {error}") from error
