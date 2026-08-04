"""Command-line policy validation, simulation, explanation, and tests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from .loading import load_effective_policy
from .models import PolicyDocument
from .tooling import (
    explain_policy_result,
    run_policy_tests,
    simulate_scan_run,
)


def _policy_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", required=True, help="Policy JSON or YAML file")


def _simulation_arguments(parser: argparse.ArgumentParser) -> None:
    _policy_argument(parser)
    parser.add_argument(
        "--input",
        required=True,
        help="Saved canonical scan-run JSON",
    )
    parser.add_argument(
        "--runtime-context",
        help="JSON with optional shared and findings context objects",
    )


def add_arguments(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="policy_command")

    validate = commands.add_parser("validate", help="Validate and resolve a policy")
    _policy_argument(validate)
    validate.add_argument(
        "--repository",
        help="Repository name used to select repository overrides",
    )

    simulate = commands.add_parser(
        "simulate",
        help="Evaluate a policy against a saved scan run",
    )
    _simulation_arguments(simulate)

    explain = commands.add_parser(
        "explain",
        help="Explain a saved finding's policy evaluation",
    )
    _simulation_arguments(explain)
    explain.add_argument("--finding-id", required=True)

    test = commands.add_parser(
        "test",
        help="Run policy unit tests against saved findings",
    )
    _simulation_arguments(test)
    test.add_argument(
        "--expectations",
        required=True,
        help="Policy expectations JSON",
    )
    parser.set_defaults(policy_parser=parser)


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


def _simulation_inputs(
    args: argparse.Namespace,
) -> tuple[
    dict[str, Any],
    PolicyDocument,
    dict[str, Any],
    dict[str, Any],
]:
    scan_run = _load_object(args.input, "input")
    repository_value = scan_run.get("repository")
    repository = str(repository_value) if repository_value is not None else None
    policy = load_effective_policy(args.policy, repository=repository)
    shared, findings = _runtime_context(args.runtime_context)
    return scan_run, policy, shared, findings


def _run_command(args: argparse.Namespace) -> int:
    if args.policy_command is None:
        args.policy_parser.print_help()
        return 0
    if args.policy_command == "validate":
        policy = load_effective_policy(args.policy, repository=args.repository)
        print(f"{policy.policy_id}@{policy.policy_version} is valid")
        return 0

    scan_run, policy, shared, findings = _simulation_inputs(args)
    if args.policy_command == "simulate":
        result = simulate_scan_run(
            policy,
            scan_run,
            runtime_context=shared,
            finding_contexts=findings,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.policy_command == "explain":
        result = simulate_scan_run(
            policy,
            scan_run,
            runtime_context=shared,
            finding_contexts=findings,
        )
        evaluation = next(
            (
                item
                for item in result["evaluations"]
                if item["context"]["finding_id"] == args.finding_id
            ),
            None,
        )
        if evaluation is None:
            raise ValueError(f"finding {args.finding_id!r} was not found")
        print(explain_policy_result(evaluation), end="")
        return 0
    if args.policy_command == "test":
        expectations = _load_object(args.expectations, "expectations")
        result = run_policy_tests(
            policy,
            scan_run,
            expectations,
            runtime_context=shared,
            finding_contexts=findings,
        )
        print(f"{result['passed']} passed, {result['failed']} failed")
        for test in result["tests"]:
            status = "PASS" if test["passed"] else "FAIL"
            print(f"{status}: {test['name']}")
        return 0 if result["failed"] == 0 else 1
    raise ValueError(f"unknown policy command {args.policy_command!r}")


def run(args: argparse.Namespace) -> int:
    try:
        return _run_command(args)
    except (OSError, ValueError) as error:
        print(f"Policy error: {error}", file=sys.stderr)
        return 2


__all__ = ["add_arguments", "run"]
