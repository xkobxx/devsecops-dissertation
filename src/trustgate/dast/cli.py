"""CLI for reusable, bounded DAST plan generation and execution."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .execution import (
    build_zap_container_command,
    execute_dast_plan,
    write_dast_plan,
)
from .models import (
    DastConfig,
    DastConfigurationError,
    DastMode,
    ScanMode,
    TargetEnvironment,
)
from .planner import build_dast_plan


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target-url", required=True)
    parser.add_argument(
        "--mode", choices=[value.value for value in DastMode], default="baseline"
    )
    parser.add_argument(
        "--scan-mode",
        choices=[value.value for value in ScanMode],
        default="safe",
    )
    parser.add_argument(
        "--environment",
        choices=[value.value for value in TargetEnvironment],
        default="preview",
    )
    parser.add_argument(
        "--scope-host",
        action="append",
        required=True,
        help="Allowed hostname or *.domain; repeat for each scope entry.",
    )
    parser.add_argument("--rate-limit", type=int, default=5)
    parser.add_argument("--request-limit", type=int, default=500)
    parser.add_argument("--max-duration-seconds", type=int, default=300)
    parser.add_argument("--openapi-path")
    parser.add_argument(
        "--auth-type",
        choices=["none", "bearer", "basic", "header"],
        default="none",
    )
    parser.add_argument("--auth-header-name", default="Authorization")
    parser.add_argument(
        "--auth-secret-environment", default="TRUSTGATE_DAST_AUTH_SECRET"
    )
    parser.add_argument("--public-target-acknowledged", action="store_true")
    parser.add_argument("--active-scan-acknowledged", action="store_true")
    parser.add_argument("--production-scan-acknowledged", action="store_true")
    parser.add_argument("--allow-private-target", action="store_true")
    parser.add_argument(
        "--plan-output", type=Path, default=Path("reports/dast-plan.yaml")
    )
    parser.add_argument(
        "--report", type=Path, default=Path("reports/zap_report.json")
    )
    parser.add_argument(
        "--metadata", type=Path, default=Path("reports/zap_execution.json")
    )
    parser.add_argument(
        "--logs-dir", type=Path, default=Path("reports/logs/zap")
    )
    parser.add_argument("--zap-executable", default="zap.sh")
    parser.add_argument(
        "--container-image",
        help="Digest-pinned ZAP image; runs the plan with Docker when supplied.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute the validated plan; otherwise only publish it.",
    )


def run(args: argparse.Namespace) -> int:
    try:
        config = DastConfig(
            target_url=args.target_url,
            mode=DastMode(args.mode),
            scan_mode=ScanMode(args.scan_mode),
            environment=TargetEnvironment(args.environment),
            scope_allowlist=tuple(args.scope_host),
            rate_limit_per_second=args.rate_limit,
            request_limit=args.request_limit,
            max_duration_seconds=args.max_duration_seconds,
            openapi_path=args.openapi_path,
            auth_type=args.auth_type,
            auth_header_name=args.auth_header_name,
            auth_secret_environment=args.auth_secret_environment,
            public_target_acknowledged=args.public_target_acknowledged,
            active_scan_acknowledged=args.active_scan_acknowledged,
            production_scan_acknowledged=args.production_scan_acknowledged,
            allow_private_target=args.allow_private_target,
        )
        runtime_report_path: Path = args.report.resolve()
        if args.container_image:
            runtime_report_path = _container_path(args.report, Path.cwd())
        plan = build_dast_plan(
            config,
            workspace=Path.cwd(),
            report_path=runtime_report_path,
        )
        plan_path = write_dast_plan(plan, args.plan_output)
        print(
            f"DAST plan written: {plan_path} "
            f"({plan.config.mode.value}/{plan.config.scan_mode.value}, "
            f"environment={plan.config.environment.value})."
        )
        if not args.execute:
            return 0
        command_prefix = None
        runtime_plan_path = None
        if args.container_image:
            command_prefix = build_zap_container_command(
                args.container_image,
                workspace=Path.cwd(),
                auth_secret_environment=(
                    plan.config.auth_secret_environment
                    if plan.authenticated
                    else None
                ),
            )
            runtime_plan_path = _container_path(plan_path, Path.cwd())
        result = execute_dast_plan(
            plan,
            plan_path=plan_path,
            report_path=args.report,
            metadata_path=args.metadata,
            logs_dir=args.logs_dir,
            zap_executable=args.zap_executable,
            command_prefix=command_prefix,
            runtime_plan_path=runtime_plan_path,
        )
        print(
            f"zap: {result.state.value} "
            f"(report={result.report_produced}, timed_out={result.timed_out})."
        )
        return 0 if result.healthy else 2
    except DastConfigurationError as error:
        print(f"DAST configuration rejected: {error}", file=sys.stderr)
        return 2


def _container_path(path: Path, workspace: Path) -> Path:
    root = workspace.resolve()
    try:
        relative = path.resolve().relative_to(root)
    except ValueError as error:
        raise DastConfigurationError(
            "Container DAST outputs must remain inside the workspace."
        ) from error
    return Path("/zap/wrk") / relative


__all__ = ["add_arguments", "run"]
