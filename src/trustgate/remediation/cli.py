"""Command-line deterministic remediation and rollback."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
from typing import Any

from .ai import (
    prepare_ai_context,
    publish_ai_remediation,
    request_ai_patch,
    stage_ai_patch,
    verify_ai_remediation,
)
from .engine import (
    RemediationError,
    apply_remediation_plan,
    rollback_remediation,
)
from .guidance import generate_guidance
from .rules import supported_rules


DEFAULT_BACKUP_ROOT = ".trustgate/remediation-backups"
DEFAULT_GUIDANCE_INPUT = "reports/findings.json"
DEFAULT_GUIDANCE_REQUEST = "remediation-guidance.json"
DEFAULT_GUIDANCE_OUTPUT = "reports/remediation-guidance.json"
DEFAULT_PLAN = "remediation-plan.json"
DEFAULT_RECEIPT = "reports/remediation-receipt.json"
DEFAULT_ROLLBACK = "reports/remediation-rollback.json"
DEFAULT_RULES = "reports/remediation-rules.json"
DEFAULT_AI_CONTEXT = "reports/ai-remediation-context.json"
DEFAULT_AI_PROPOSAL = "reports/ai-remediation-proposal.json"
DEFAULT_AI_STAGE = "reports/ai-remediation-stage.json"
DEFAULT_AI_VERIFICATION = "reports/ai-remediation-verification.json"
DEFAULT_AI_PUBLICATION = "reports/ai-remediation-publication.json"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="remediation_action", required=True)

    rules = commands.add_parser(
        "rules", help="Publish supported rule and framework safety contracts."
    )
    rules.add_argument(
        "--output",
        default=DEFAULT_RULES,
        help=f"Rules JSON output (default: {DEFAULT_RULES})",
    )
    rules.set_defaults(remediation_handler=_run_rules)

    guide = commands.add_parser(
        "guide", help="Generate evidence-bound, guidance-only remediation advice."
    )
    guide.add_argument(
        "--input",
        default=DEFAULT_GUIDANCE_INPUT,
        help=f"Canonical scan-run JSON (default: {DEFAULT_GUIDANCE_INPUT})",
    )
    guide.add_argument(
        "--guidance",
        default=DEFAULT_GUIDANCE_REQUEST,
        help=(
            "Finding-to-rule guidance mapping "
            f"(default: {DEFAULT_GUIDANCE_REQUEST})"
        ),
    )
    guide.add_argument(
        "--output",
        default=DEFAULT_GUIDANCE_OUTPUT,
        help=f"Guidance report output (default: {DEFAULT_GUIDANCE_OUTPUT})",
    )
    guide.set_defaults(remediation_handler=_run_guide)

    apply = commands.add_parser(
        "apply", help="Apply a content-bound deterministic remediation plan."
    )
    apply.add_argument("--root", default=".", help="Repository root (default: .)")
    apply.add_argument(
        "--plan",
        default=DEFAULT_PLAN,
        help=f"Versioned remediation plan (default: {DEFAULT_PLAN})",
    )
    apply.add_argument(
        "--backup-root",
        default=DEFAULT_BACKUP_ROOT,
        help=f"Protected backup directory (default: {DEFAULT_BACKUP_ROOT})",
    )
    apply.add_argument(
        "--receipt",
        default=DEFAULT_RECEIPT,
        help=f"Applied-transaction receipt (default: {DEFAULT_RECEIPT})",
    )
    apply.set_defaults(remediation_handler=_run_apply)

    rollback = commands.add_parser(
        "rollback", help="Restore an applied transaction from verified backups."
    )
    rollback.add_argument("--root", default=".", help="Repository root (default: .)")
    rollback.add_argument(
        "--receipt",
        default=DEFAULT_RECEIPT,
        help=f"Applied-transaction receipt (default: {DEFAULT_RECEIPT})",
    )
    rollback.add_argument(
        "--backup-root",
        default=DEFAULT_BACKUP_ROOT,
        help=f"Protected backup directory (default: {DEFAULT_BACKUP_ROOT})",
    )
    rollback.add_argument(
        "--output",
        default=DEFAULT_ROLLBACK,
        help=f"Rollback receipt (default: {DEFAULT_ROLLBACK})",
    )
    rollback.set_defaults(remediation_handler=_run_rollback)

    ai_context = commands.add_parser(
        "ai-context",
        help="Preview bounded, redacted AI context without contacting a model.",
    )
    ai_context.add_argument("--root", default=".", help="Repository root (default: .)")
    ai_context.add_argument("--input", required=True, help="Canonical scan-run JSON")
    ai_context.add_argument("--request", required=True, help="AI context request JSON")
    ai_context.add_argument("--output", default=DEFAULT_AI_CONTEXT)
    ai_context.set_defaults(remediation_handler=_run_ai_context)

    ai_propose = commands.add_parser(
        "ai-propose",
        help="Explicitly opt in and request an unverified AI patch.",
    )
    ai_propose.add_argument("--context", required=True, help="AI context bundle JSON")
    ai_propose.add_argument(
        "--opt-in-ai-remediation",
        action="store_true",
        help="Explicitly authorize model invocation for the disclosed context.",
    )
    ai_propose.add_argument(
        "--acknowledge-context-digest",
        required=True,
        help="Exact disclosed context digest being authorized.",
    )
    ai_propose.add_argument(
        "--allow-remote-context",
        action="store_true",
        help="Separately authorize disclosed context to leave the runner.",
    )
    ai_propose.add_argument("--timeout-seconds", type=int, default=120)
    ai_propose.add_argument("--output", default=DEFAULT_AI_PROPOSAL)
    ai_propose.set_defaults(remediation_handler=_run_ai_propose)

    ai_stage = commands.add_parser(
        "ai-stage", help="Apply an unverified AI patch in an isolated Git worktree."
    )
    ai_stage.add_argument("--repository", default=".")
    ai_stage.add_argument("--proposal", required=True)
    ai_stage.add_argument("--worktree", required=True)
    ai_stage.add_argument("--branch", required=True)
    ai_stage.add_argument("--base-ref", default="HEAD")
    ai_stage.add_argument("--output", default=DEFAULT_AI_STAGE)
    ai_stage.set_defaults(remediation_handler=_run_ai_stage)

    ai_verify = commands.add_parser(
        "ai-verify", help="Run all checks and security comparisons for a staged patch."
    )
    ai_verify.add_argument("--stage", required=True)
    ai_verify.add_argument("--proposal", required=True)
    ai_verify.add_argument("--before-scan", required=True)
    ai_verify.add_argument("--config", required=True)
    ai_verify.add_argument("--output", default=DEFAULT_AI_VERIFICATION)
    ai_verify.set_defaults(remediation_handler=_run_ai_verify)

    ai_publish = commands.add_parser(
        "ai-publish", help="Push a verified patch and open a draft pull request."
    )
    ai_publish.add_argument("--stage", required=True)
    ai_publish.add_argument("--verification", required=True)
    ai_publish.add_argument("--title", required=True)
    ai_publish.add_argument("--body-file", required=True)
    ai_publish.add_argument("--gh", default="gh", help="GitHub CLI executable")
    ai_publish.add_argument("--output", default=DEFAULT_AI_PUBLICATION)
    ai_publish.set_defaults(remediation_handler=_run_ai_publish)


def _object(path: str | Path, label: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RemediationError(f"{label} must contain a JSON object")
    return value


def _write_json(path: str | Path, value: object) -> Path:
    output = Path(path)
    if output.is_symlink():
        raise OSError(f"refusing to replace symlinked output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            delete=False,
        ) as temporary:
            json.dump(value, temporary, indent=2, sort_keys=True)
            temporary.write("\n")
            temporary_path = Path(temporary.name)
        temporary_path.replace(output)
    except BaseException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise
    return output


def _run_rules(args: argparse.Namespace) -> Path:
    return _write_json(args.output, supported_rules())


def _run_guide(args: argparse.Namespace) -> Path:
    document = generate_guidance(
        _object(args.input, "canonical scan run"),
        _object(args.guidance, "guidance request"),
    )
    return _write_json(args.output, document)


def _run_apply(args: argparse.Namespace) -> Path:
    receipt = apply_remediation_plan(
        args.root,
        _object(args.plan, "remediation plan"),
        backup_root=args.backup_root,
    )
    try:
        return _write_json(args.receipt, receipt)
    except BaseException:
        rollback_remediation(
            args.root,
            receipt,
            backup_root=args.backup_root,
        )
        raise


def _run_rollback(args: argparse.Namespace) -> Path:
    receipt = rollback_remediation(
        args.root,
        _object(args.receipt, "remediation receipt"),
        backup_root=args.backup_root,
    )
    return _write_json(args.output, receipt)


def _run_ai_context(args: argparse.Namespace) -> Path:
    bundle = prepare_ai_context(
        args.root,
        _object(args.input, "canonical scan run"),
        _object(args.request, "AI context request"),
    )
    return _write_json(args.output, bundle)


def _run_ai_propose(args: argparse.Namespace) -> Path:
    proposal = request_ai_patch(
        _object(args.context, "AI context bundle"),
        opt_in=args.opt_in_ai_remediation,
        acknowledged_context_digest=args.acknowledge_context_digest,
        allow_remote_context=args.allow_remote_context,
        timeout_seconds=args.timeout_seconds,
    )
    return _write_json(args.output, proposal)


def _run_ai_stage(args: argparse.Namespace) -> Path:
    stage = stage_ai_patch(
        args.repository,
        _object(args.proposal, "AI proposal"),
        worktree=args.worktree,
        branch=args.branch,
        base_ref=args.base_ref,
    )
    return _write_json(args.output, stage)


def _run_ai_verify(args: argparse.Namespace) -> Path:
    verification = verify_ai_remediation(
        _object(args.stage, "AI stage"),
        _object(args.proposal, "AI proposal"),
        _object(args.before_scan, "pre-remediation scan run"),
        _object(args.config, "AI verification config"),
    )
    return _write_json(args.output, verification)


def _run_ai_publish(args: argparse.Namespace) -> Path:
    publication = publish_ai_remediation(
        _object(args.stage, "AI stage"),
        _object(args.verification, "AI verification"),
        title=args.title,
        body=Path(args.body_file).read_text(encoding="utf-8"),
        gh=args.gh,
    )
    return _write_json(args.output, publication)


def run(args: argparse.Namespace) -> int:
    handler = getattr(args, "remediation_handler", None)
    if handler is None:
        raise RemediationError("a remediation action is required")
    try:
        output = handler(args)
    except (json.JSONDecodeError, OSError, RemediationError) as error:
        print(f"Remediation error: {error}", file=sys.stderr)
        return 2
    print(output)
    return 0


__all__ = ["add_arguments", "run"]
