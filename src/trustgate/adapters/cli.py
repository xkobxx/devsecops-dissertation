"""CLI for discovering, planning, and running scanner adapters."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
from typing import Any

from trustgate.scanners.models import ParserStatus, ScannerState
from trustgate.planning import PlanningOverrides, build_scan_plan

from .builtin.catalog import BUILTIN_ADAPTER_NAMES, builtin_registry
from .models import (
    AdapterConfig,
    AdapterContext,
    AdapterParseStatus,
    RepositoryContext,
)
from .runner import parse_with_isolation


def add_list_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target", type=Path, default=Path("."))
    parser.add_argument("--json", action="store_true", dest="as_json")


def _metadata_record(adapter: Any, repository: RepositoryContext) -> dict[str, Any]:
    metadata = adapter.metadata()
    return {
        "name": metadata.name,
        "adapter_version": metadata.version,
        "category": metadata.category,
        "applicable": adapter.is_applicable(repository),
        "supported_languages": list(metadata.supported_languages),
        "supported_files": list(metadata.supported_files),
        "required_runtime": list(metadata.required_runtime),
        "default_timeout": metadata.default_timeout,
        "licence": metadata.licence,
        "data_leaves_runner": metadata.data_leaves_runner,
        "report_format": metadata.report_format,
        "capabilities": [capability.value for capability in metadata.capabilities],
    }


def run_list(args: argparse.Namespace) -> int:
    repository = RepositoryContext.from_path(args.target)
    registry = builtin_registry(discover_plugins=True)
    catalogue = [
        _metadata_record(registry.get(name), repository)
        for name in registry.names()
    ]
    if args.as_json:
        print(json.dumps(catalogue, indent=2))
    else:
        for entry in catalogue:
            status = "applicable" if entry["applicable"] else "not applicable"
            print(
                f"{entry['name']}: {status} "
                f"({', '.join(entry['capabilities'])})"
            )
    return 0


def add_run_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scanner", choices=BUILTIN_ADAPTER_NAMES, required=True)
    parser.add_argument("--target", type=Path, default=Path("."))
    parser.add_argument("--reports-dir", type=Path, default=Path("reports"))
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print this scanner's plan without executing it.",
    )
    parser.add_argument(
        "--optional",
        action="store_true",
        help="Treat execution or parsing failure as non-blocking.",
    )
    parser.add_argument(
        "--option",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Adapter-specific JSON value; repeat as needed.",
    )


def _options(values: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for value in values:
        key, separator, raw = value.partition("=")
        if not separator or not key.strip():
            raise ValueError("adapter options must use KEY=VALUE")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = raw
        result[key.strip()] = parsed
    return result


def run_adapter(args: argparse.Namespace) -> int:
    if args.timeout is not None and args.timeout <= 0:
        print("Adapter timeout must be greater than zero.")
        return 2
    registry = builtin_registry(discover_plugins=True)
    adapter = registry.get(args.scanner)
    repository = RepositoryContext.from_path(args.target)
    if args.dry_run:
        timeouts = (
            {args.scanner: args.timeout} if args.timeout is not None else {}
        )
        plan = build_scan_plan(
            repository,
            registry,
            overrides=PlanningOverrides(
                enable_scanners=frozenset({args.scanner}),
                timeouts=timeouts,
                dry_run=True,
            ),
        )
        decision = next(
            item for item in plan.decisions if item.scanner == args.scanner
        )
        print(f"{args.scanner}: DRY RUN")
        print(f"Reason: {decision.reason}")
        print(
            "Target directories: "
            + (", ".join(decision.target_directories) or "-")
        )
        print(
            "Expected outputs: "
            + (", ".join(decision.expected_outputs) or "-")
        )
        print(f"Timeout: {decision.timeout_seconds:g} seconds")
        print(f"Data handling: {decision.data_handling.behaviour}")
        return 0
    if not adapter.is_applicable(repository):
        print(f"{args.scanner}: SKIPPED (not applicable to this repository)")
        return 0
    try:
        options = _options(args.option)
        config = AdapterConfig(
            required=not args.optional,
            timeout_seconds=args.timeout,
            options=options,
        )
    except ValueError as error:
        print(str(error))
        return 2
    context = AdapterContext.create(
        repository=repository,
        reports_dir=args.reports_dir.resolve(),
        config=config,
        metadata=adapter.metadata(),
    )
    prepared = adapter.prepare(context)
    try:
        execution = adapter.execute(repository.root, prepared)
        report_path = Path(execution.report_path)
        if adapter.health_check(execution):
            parsed = parse_with_isolation(adapter, report_path, prepared)
        else:
            parsed = None
    except Exception as error:
        print(f"{args.scanner}: FAILED_SCANNER: {type(error).__name__}: {error}")
        return 2 if config.required else 0
    finally:
        adapter.cleanup(prepared)

    if parsed is None:
        final = execution
        findings: tuple[dict[str, Any], ...] = ()
    elif parsed.status is AdapterParseStatus.FAILED:
        final = replace(
            execution,
            state=(
                ScannerState.FAILED_SCANNER
                if config.required
                else ScannerState.PARTIAL
            ),
            parser_status=ParserStatus.FAILED,
            finding_count=0,
            error=parsed.error,
        )
        findings = ()
    else:
        findings = parsed.findings
        final = replace(
            execution,
            state=ScannerState.FINDINGS if findings else execution.state,
            parser_status=ParserStatus.SUCCESS,
            finding_count=len(findings),
        )

    context.reports_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = context.reports_dir / f"{args.scanner}_execution.json"
    metadata_path.write_text(
        json.dumps(final.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )
    findings_path = context.reports_dir / f"{args.scanner}_findings.json"
    findings_path.write_text(
        json.dumps(list(findings), indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"{args.scanner}: {final.state.value} "
        f"(parser={final.parser_status.value}, findings={len(findings)})"
    )
    return 0 if final.healthy or not config.required else 2


__all__ = [
    "add_list_arguments",
    "add_run_arguments",
    "run_adapter",
    "run_list",
]
