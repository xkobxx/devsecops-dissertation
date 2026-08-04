"""Command-line baseline creation and pull-request comparison."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from trustgate.schema import write_validated_json
from trustgate.policy.loading import load_effective_policy

from .comparison import compare_to_baseline
from .creation import create_baseline
from .gate import GateMode, evaluate_gate


DEFAULT_INPUT = "reports/findings.json"
DEFAULT_BASELINE = "reports/baseline.json"
DEFAULT_DIFFERENCE = "reports/baseline-diff.json"
DEFAULT_GATE = "reports/baseline-gate.json"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="baseline_command")

    create = commands.add_parser(
        "create",
        help="Create a baseline from a canonical default-branch scan",
    )
    create.add_argument("--input", default=DEFAULT_INPUT)
    create.add_argument("--output", default=DEFAULT_BASELINE)
    create.add_argument("--default-branch", default="main")

    compare = commands.add_parser(
        "compare",
        help="Compare a pull-request scan with a verified baseline",
    )
    compare.add_argument("--baseline", default=DEFAULT_BASELINE)
    compare.add_argument("--input", default=DEFAULT_INPUT)
    compare.add_argument("--output", default=DEFAULT_DIFFERENCE)

    gate = commands.add_parser(
        "gate",
        help="Evaluate a differential release gate against a verified baseline",
    )
    gate.add_argument("--baseline", default=DEFAULT_BASELINE)
    gate.add_argument("--input", default=DEFAULT_INPUT)
    gate.add_argument("--output", default=DEFAULT_GATE)
    gate.add_argument(
        "--gate-mode",
        choices=[mode.value for mode in GateMode],
        default=GateMode.NEW.value,
    )
    gate.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
    )
    gate.add_argument(
        "--enforce-legacy-risk",
        action="store_true",
        help="Explicitly include unchanged historical findings in the gate",
    )
    gate.add_argument(
        "--policy",
        help="Policy JSON/YAML path or pack:<name>; required by policy mode",
    )
    gate.add_argument(
        "--runtime-context",
        help="JSON with optional shared and findings policy context objects",
    )
    parser.set_defaults(baseline_parser=parser)


def _load_object(path: str | Path, label: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def _runtime_context(path: str | None) -> tuple[dict[str, Any], dict[str, Any]]:
    if path is None:
        return {}, {}
    document = _load_object(path, "runtime context")
    unexpected = sorted(set(document) - {"shared", "findings"})
    if unexpected:
        raise ValueError(f"unknown runtime context sections: {unexpected}")
    shared = document.get("shared", {})
    findings = document.get("findings", {})
    if not isinstance(shared, dict) or not isinstance(findings, dict):
        raise ValueError("runtime context shared and findings values must be objects")
    return shared, findings


def _run_command(args: argparse.Namespace) -> int:
    if args.baseline_command is None:
        args.baseline_parser.print_help()
        return 0
    if args.baseline_command == "create":
        baseline = create_baseline(
            _load_object(args.input, "input"),
            default_branch=args.default_branch,
        )
        output = write_validated_json(
            args.output,
            baseline,
            schema_name="baseline",
        )
        print(
            f"Created baseline with {len(baseline['findings'])} findings "
            f"from {baseline['repository']}@{baseline['commit']} -> {output}"
        )
        return 0
    if args.baseline_command == "compare":
        difference = compare_to_baseline(
            _load_object(args.baseline, "baseline"),
            _load_object(args.input, "input"),
        )
        output = write_validated_json(
            args.output,
            difference,
            schema_name="baseline-diff",
        )
        summary = difference["summary"]
        print(
            f"Compared pull request with baseline -> {output}\n"
            f"new={summary['new_findings']} "
            f"removed={summary['removed_findings']} "
            f"worsened={summary['worsened_findings']} "
            f"newly_reachable={summary['newly_reachable_findings']} "
            f"newly_exploited={summary['newly_exploited_dependencies']} "
            f"expired_suppressions={summary['expired_suppressions']} "
            f"coverage_regressions={summary['scanner_coverage_regressions']}"
        )
        return 0
    if args.baseline_command == "gate":
        scan_run = _load_object(args.input, "input")
        repository_value = scan_run.get("repository")
        repository = (
            str(repository_value) if repository_value is not None else None
        )
        policy = (
            load_effective_policy(args.policy, repository=repository)
            if args.policy
            else None
        )
        shared, findings = _runtime_context(args.runtime_context)
        gate_result = evaluate_gate(
            _load_object(args.baseline, "baseline"),
            scan_run,
            mode=args.gate_mode,
            fail_on=args.fail_on,
            enforce_legacy_risk=args.enforce_legacy_risk,
            policy=policy,
            runtime_context=shared,
            finding_contexts=findings,
        )
        output = write_validated_json(
            args.output,
            gate_result,
            schema_name="baseline-gate",
        )
        status = "passed" if gate_result["passed"] else "failed"
        summary = gate_result["summary"]
        print(
            f"Gate {status}: mode={gate_result['gate_mode']} "
            f"baseline_age={gate_result['baseline_age_seconds']:.0f}s "
            f"blocked={summary['blocked_findings']} "
            f"coverage_regressions={summary['scanner_coverage_regressions']} "
            f"-> {output}"
        )
        return 0 if gate_result["passed"] else 1
    raise ValueError(f"unknown baseline command {args.baseline_command!r}")


def run(args: argparse.Namespace) -> int:
    try:
        return _run_command(args)
    except (OSError, ValueError) as error:
        print(f"Baseline error: {error}", file=sys.stderr)
        return 2


__all__ = [
    "DEFAULT_BASELINE",
    "DEFAULT_DIFFERENCE",
    "DEFAULT_GATE",
    "DEFAULT_INPUT",
    "add_arguments",
    "run",
]
