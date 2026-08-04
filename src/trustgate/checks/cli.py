"""Command-line GitHub Check summary publication."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from .summary import render_check_summary, write_check_summary


DEFAULT_INPUT = "reports/findings.json"
DEFAULT_POLICY_RESULT = "reports/policy-result.json"
DEFAULT_OUTPUT = "reports/check-summary.md"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--policy-result", default=DEFAULT_POLICY_RESULT)
    parser.add_argument("--baseline-diff")
    parser.add_argument("--baseline-gate")
    parser.add_argument("--artifact-url")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)


def _load_object(path: str | Path, label: str) -> dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return document


def run(args: argparse.Namespace) -> int:
    try:
        scan_run = _load_object(args.input, "input")
        policy_result = _load_object(args.policy_result, "policy result")
        baseline_difference = (
            _load_object(args.baseline_diff, "baseline difference")
            if args.baseline_diff
            else None
        )
        baseline_gate = (
            _load_object(args.baseline_gate, "baseline gate")
            if args.baseline_gate
            else None
        )
        content = render_check_summary(
            scan_run,
            policy_result,
            baseline_difference=baseline_difference,
            baseline_gate=baseline_gate,
            artifact_url=args.artifact_url,
        )
        output = write_check_summary(args.output, content)
    except (OSError, ValueError) as error:
        print(f"Check summary error: {error}", file=sys.stderr)
        return 2
    print(f"Generated GitHub Check summary -> {output}")
    return 0


__all__ = ["add_arguments", "run"]
