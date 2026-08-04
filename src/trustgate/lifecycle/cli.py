"""Command-line suppression creation, linting, application, and revalidation."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from typing import Any

from trustgate.schema import write_validated_json

from .suppressions import (
    apply_suppression,
    create_suppression,
    lint_suppression,
    revalidate_suppression,
)


DEFAULT_FINDING = "reports/finding.json"
DEFAULT_SUPPRESSION = "reports/suppression.json"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="suppression_command")

    create = commands.add_parser("create", help="Create a scoped suppression record")
    create.add_argument("--input", default=DEFAULT_FINDING)
    create.add_argument("--output", default=DEFAULT_SUPPRESSION)
    create.add_argument("--repository", required=True)
    create.add_argument("--reason", required=True)
    create.add_argument("--author", required=True)
    create.add_argument("--created-at")
    create.add_argument("--expires-at")
    create.add_argument("--scope")
    create.add_argument("--approval", required=True)
    create.add_argument("--evidence", required=True)
    create.add_argument("--policy-digest", required=True)
    create.add_argument("--allow-permanent", action="store_true")

    lint = commands.add_parser("lint", help="Lint one suppression record")
    lint.add_argument("--input", default=DEFAULT_SUPPRESSION)
    lint.add_argument("--evaluated-at")
    lint.add_argument("--warning-days", type=int, default=7)

    apply = commands.add_parser("apply", help="Apply a matching suppression")
    apply.add_argument("--finding", default=DEFAULT_FINDING)
    apply.add_argument("--suppression", default=DEFAULT_SUPPRESSION)
    apply.add_argument("--output", default=DEFAULT_FINDING)
    apply.add_argument("--repository", required=True)
    apply.add_argument("--ref")
    apply.add_argument("--environment")
    apply.add_argument("--changed-at")

    revalidate = commands.add_parser(
        "revalidate",
        help="Reopen a suppression when expiry or risk context changes",
    )
    revalidate.add_argument("--finding", default=DEFAULT_FINDING)
    revalidate.add_argument("--suppression", default=DEFAULT_SUPPRESSION)
    revalidate.add_argument("--output", default=DEFAULT_FINDING)
    revalidate.add_argument("--repository", required=True)
    revalidate.add_argument("--policy-digest", required=True)
    revalidate.add_argument("--ref")
    revalidate.add_argument("--environment")
    revalidate.add_argument("--evaluated-at")
    parser.set_defaults(suppression_parser=parser)


def _load_json(path: str | Path, label: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{label} is not valid JSON: {error}") from error


def _object(path: str | Path | None, label: str) -> dict[str, Any]:
    if path is None:
        return {}
    value = _load_json(path, label)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def _array(path: str | Path, label: str) -> list[dict[str, Any]]:
    value = _load_json(path, label)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{label} must contain an array of JSON objects")
    return value


def _datetime(value: str | None, *, default_now: bool = False) -> datetime | None:
    if value is None:
        return datetime.now(timezone.utc) if default_now else None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"invalid ISO date-time {value!r}") from error
    return parsed


def _run_command(args: argparse.Namespace) -> int:
    if args.suppression_command is None:
        args.suppression_parser.print_help()
        return 0
    if args.suppression_command == "create":
        document = create_suppression(
            _object(args.input, "finding"),
            repository=args.repository,
            reason=args.reason,
            author=args.author,
            created_at=_datetime(args.created_at, default_now=True),
            expires_at=_datetime(args.expires_at),
            scope=_object(args.scope, "scope"),
            approval=_object(args.approval, "approval"),
            evidence=_array(args.evidence, "evidence"),
            policy_digest=args.policy_digest,
            allow_permanent=args.allow_permanent,
        )
        output = write_validated_json(
            args.output,
            document,
            schema_name="suppression",
        )
        print(f"Created suppression {document['suppression_id']} -> {output}")
        return 0
    if args.suppression_command == "lint":
        issues = lint_suppression(
            _object(args.input, "suppression"),
            evaluated_at=_datetime(args.evaluated_at),
            warning_window=timedelta(days=args.warning_days),
        )
        for issue in issues:
            print(f"{issue['level']}: {issue['code']}: {issue['message']}")
        return 1 if any(issue["level"] == "error" for issue in issues) else 0
    if args.suppression_command == "apply":
        finding = apply_suppression(
            _object(args.finding, "finding"),
            _object(args.suppression, "suppression"),
            repository=args.repository,
            ref=args.ref,
            environment=args.environment,
            changed_at=_datetime(args.changed_at),
        )
        output = write_validated_json(args.output, finding, schema_name="finding")
        print(f"Applied suppression -> {output}")
        return 0
    if args.suppression_command == "revalidate":
        result = revalidate_suppression(
            _object(args.finding, "finding"),
            _object(args.suppression, "suppression"),
            repository=args.repository,
            policy_digest=args.policy_digest,
            ref=args.ref,
            environment=args.environment,
            evaluated_at=_datetime(args.evaluated_at),
        )
        output = write_validated_json(
            args.output,
            result["finding"],
            schema_name="finding",
        )
        reasons = ",".join(result["reasons"]) or "none"
        print(
            f"Revalidated suppression: active={str(result['active']).lower()} "
            f"reopened={str(result['reopened']).lower()} reasons={reasons} -> {output}"
        )
        return 1 if result["reopened"] else 0
    raise ValueError(f"unknown suppression command {args.suppression_command!r}")


def run(args: argparse.Namespace) -> int:
    try:
        return _run_command(args)
    except (OSError, ValueError) as error:
        print(f"Suppression error: {error}", file=sys.stderr)
        return 2


__all__ = ["DEFAULT_FINDING", "DEFAULT_SUPPRESSION", "add_arguments", "run"]
