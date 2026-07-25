"""CLI rendering and override parsing for pre-execution scan plans."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from trustgate.adapters.builtin.catalog import builtin_registry
from trustgate.repository import RepositoryContext

from .models import PlanningConfigurationError, PlanningOverrides, ScanPlan
from .planner import build_scan_plan


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target", type=Path, default=Path("."))
    parser.add_argument(
        "--format",
        choices=("human", "json"),
        dest="plan_format",
        help="Plan output format (default: human).",
    )
    parser.add_argument(
        "--json",
        action="store_const",
        const="json",
        dest="plan_format",
        help="Shortcut for --format json.",
    )
    parser.set_defaults(plan_format="human")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Record that the plan is a no-execution dry run.",
    )
    parser.add_argument(
        "--enable-scanner",
        action="append",
        default=[],
        metavar="NAME",
        help="Enable a scanner explicitly; repeat as needed.",
    )
    parser.add_argument(
        "--disable-scanner",
        action="append",
        default=[],
        metavar="NAME",
        help="Disable a scanner explicitly; repeat as needed.",
    )
    parser.add_argument(
        "--timeout",
        action="append",
        default=[],
        metavar="NAME=SECONDS",
        help="Override a scanner timeout; repeat as needed.",
    )
    parser.add_argument(
        "--include-generated",
        action="store_true",
        help="Include detected generated files in scan contexts.",
    )
    parser.add_argument(
        "--include-vendored",
        action="store_true",
        help="Include detected vendored dependencies in scan contexts.",
    )


def _timeouts(values: list[str]) -> dict[str, float]:
    result: dict[str, float] = {}
    for value in values:
        scanner, separator, raw_timeout = value.partition("=")
        if not separator or not scanner.strip() or not raw_timeout.strip():
            raise PlanningConfigurationError(
                "scanner timeouts must use NAME=SECONDS"
            )
        try:
            timeout = float(raw_timeout)
        except ValueError as error:
            raise PlanningConfigurationError(
                f"invalid timeout for {scanner.strip()}: {raw_timeout}"
            ) from error
        result[scanner.strip()] = timeout
    return result


def _overrides(args: argparse.Namespace) -> PlanningOverrides:
    return PlanningOverrides(
        enable_scanners=frozenset(args.enable_scanner),
        disable_scanners=frozenset(args.disable_scanner),
        timeouts=_timeouts(args.timeout),
        dry_run=args.dry_run,
    )


def render_human(plan: ScanPlan) -> str:
    """Render a complete plan for terminal inspection."""

    detected = plan.detected_technologies
    lines = [
        f"TrustGate scan plan for {plan.target}",
        f"Mode: {'DRY RUN (no scanners executed)' if plan.dry_run else 'plan only (no scanners executed)'}",
        "",
        "Detected technologies",
    ]
    for label, key in (
        ("Languages", "languages"),
        ("Frameworks", "frameworks"),
        ("Package managers", "package_managers"),
        ("Lock files", "lock_files"),
        ("Build systems", "build_systems"),
        ("Container files", "container_files"),
        ("Kubernetes files", "kubernetes_files"),
        ("Terraform files", "terraform_files"),
        ("CloudFormation files", "cloudformation_files"),
        ("OpenAPI specifications", "openapi_specifications"),
        ("Test directories", "test_directories"),
        ("Generated files", "generated_files"),
        ("Vendored dependencies", "vendored_dependencies"),
    ):
        values = detected.get(key, [])
        lines.append(f"  {label}: {', '.join(values) if values else '-'}")
    packages = detected.get("packages", [])
    package_labels = [
        f"{package['name']} ({package['root']})" for package in packages
    ]
    lines.append(
        f"  Monorepo packages: {', '.join(package_labels) if package_labels else '-'}"
    )

    lines.extend(
        (
            "",
            "Enabled scanners",
            "  " + (", ".join(plan.enabled_scanners) or "-"),
            "",
            "Skipped scanners",
            "  " + (", ".join(plan.skipped_scanners) or "-"),
            "",
            "Scanner decisions",
        )
    )
    for decision in plan.decisions:
        status = "ENABLED" if decision.enabled else "SKIPPED"
        lines.extend(
            (
                f"  {decision.scanner}: {status}",
                f"    Reason: {decision.reason}",
                "    Target directories: "
                + (", ".join(decision.target_directories) or "-"),
                "    Expected outputs: "
                + (", ".join(decision.expected_outputs) or "-"),
                f"    Timeout: {decision.timeout_seconds:g} seconds",
                f"    Data handling: {decision.data_handling.behaviour}",
                f"    Decision source: {decision.decision_source}",
            )
        )
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> int:
    try:
        overrides = _overrides(args)
        repository = RepositoryContext.from_path(
            args.target,
            exclude_generated=not args.include_generated,
            exclude_vendored=not args.include_vendored,
        )
        plan = build_scan_plan(
            repository,
            builtin_registry(discover_plugins=True),
            overrides=overrides,
        )
    except PlanningConfigurationError as error:
        print(str(error))
        return 2

    if args.plan_format == "json":
        print(json.dumps(plan.to_dict(), indent=2))
    else:
        print(render_human(plan), end="")
    return 0


__all__ = ["add_arguments", "render_human", "run"]
