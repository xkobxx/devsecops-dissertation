"""Command-line audit-evidence generation and verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from .generation import (
    EvidenceError,
    generate_audit_evidence,
    verify_audit_evidence,
    write_audit_evidence,
)


DEFAULT_CONFIG = "audit-evidence.json"
DEFAULT_MANIFEST = "reports/audit-evidence.json"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="evidence_action", required=True)
    generate = commands.add_parser(
        "generate", help="Generate a content-addressed audit-evidence manifest."
    )
    generate.add_argument(
        "--root",
        default=".",
        help="Root containing all evidence artifacts (default: current directory)",
    )
    generate.add_argument(
        "--config",
        default=DEFAULT_CONFIG,
        help=f"Versioned evidence configuration (default: {DEFAULT_CONFIG})",
    )
    generate.add_argument(
        "--output",
        default=DEFAULT_MANIFEST,
        help=f"Manifest output (default: {DEFAULT_MANIFEST})",
    )
    generate.set_defaults(evidence_handler=_run_generate)

    verify = commands.add_parser(
        "verify", help="Verify a manifest and every referenced artifact."
    )
    verify.add_argument(
        "--root",
        default=".",
        help="Root containing all evidence artifacts (default: current directory)",
    )
    verify.add_argument(
        "--manifest",
        default=DEFAULT_MANIFEST,
        help=f"Manifest to verify (default: {DEFAULT_MANIFEST})",
    )
    verify.set_defaults(evidence_handler=_run_verify)


def _object(path: str | Path, label: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must contain a JSON object")
    return value


def _run_generate(args: argparse.Namespace) -> Path:
    document = generate_audit_evidence(
        args.root,
        _object(args.config, "evidence config"),
    )
    return write_audit_evidence(args.output, document)


def _run_verify(args: argparse.Namespace) -> Path:
    manifest = Path(args.manifest)
    verify_audit_evidence(args.root, _object(manifest, "audit manifest"))
    return manifest


def run(args: argparse.Namespace) -> int:
    handler = getattr(args, "evidence_handler", None)
    if handler is None:
        raise EvidenceError("an evidence action is required")
    try:
        output = handler(args)
    except (EvidenceError, json.JSONDecodeError, OSError) as error:
        print(f"Evidence error: {error}", file=sys.stderr)
        return 2
    print(output)
    return 0


__all__ = [
    "DEFAULT_CONFIG",
    "DEFAULT_MANIFEST",
    "add_arguments",
    "run",
]
