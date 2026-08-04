"""Command-line interface for contextual decision evaluation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from trustgate.schema import write_validated_json

from .models import DecisionPolicy
from .policy import default_policy
from .service import evaluate_scan_run


DEFAULT_INPUT = "reports/findings.json"
DEFAULT_OUTPUT = "reports/decisions.json"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT,
        help=f"Canonical scan-run JSON (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Evaluated scan-run JSON (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--runtime-context",
        help=(
            "JSON with optional shared and findings context objects; "
            "missing values remain explicit uncertainty"
        ),
    )
    parser.add_argument(
        "--policy",
        help="Optional inspectable decision-policy snapshot JSON",
    )


def _load_object(path: str | Path, label: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def run(args: argparse.Namespace) -> int:
    scan_run = _load_object(args.input, "input")
    if args.runtime_context:
        context_document = _load_object(
            args.runtime_context,
            "runtime context",
        )
        unexpected = set(context_document) - {"shared", "findings"}
        if unexpected:
            raise ValueError(
                f"unknown runtime context sections: {sorted(unexpected)}"
            )
        shared = context_document.get("shared", {})
        findings = context_document.get("findings", {})
        if not isinstance(shared, dict) or not isinstance(findings, dict):
            raise ValueError("runtime context shared and findings values must be objects")
    else:
        shared = {}
        findings = {}
    policy = (
        DecisionPolicy.from_dict(_load_object(args.policy, "policy"))
        if args.policy
        else default_policy()
    )
    evaluated = evaluate_scan_run(
        scan_run,
        policy=policy,
        runtime_context=shared,
        finding_contexts=findings,
    )
    output = write_validated_json(
        args.output,
        evaluated,
        schema_name="scan-run",
    )
    summary = evaluated["summary"]["decision_analysis"]
    counts = " ".join(
        f"{outcome}={count}"
        for outcome, count in summary["outcome_counts"].items()
        if count
    ) or "no findings"
    print(
        f"Evaluated {summary['total_decisions']} findings with "
        f"{summary['policy_id']}@{summary['policy_version']} -> {output}"
    )
    print(counts)
    return 0


__all__ = ["DEFAULT_INPUT", "DEFAULT_OUTPUT", "add_arguments", "run"]
