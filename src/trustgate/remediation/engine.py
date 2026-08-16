"""Transactional deterministic-remediation engine."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

from .rules import supported_rules


class RemediationError(ValueError):
    """Raised when a remediation request cannot be applied safely."""


class RemediationIntegrityError(RemediationError):
    """Raised when source, receipt, or backup integrity cannot be established."""


PLAN_FIELDS = frozenset({"schema_version", "plan_id", "requests"})
REQUEST_FIELDS = frozenset(
    {
        "request_id",
        "rule_id",
        "framework",
        "path",
        "expected_sha256",
        "parameters",
    }
)
RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "transaction_id",
        "plan_id",
        "status",
        "changes",
        "receipt_digest",
    }
)


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _canonical_digest(value: object) -> str:
    content = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _digest(content)


def _text(value: object, *, label: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RemediationError(f"{label} must be a non-empty string")
    result = value.strip()
    if len(result) > maximum or any(ord(character) < 32 for character in result):
        raise RemediationError(f"{label} contains unsafe text")
    return result


def _root(path: str | Path, *, label: str) -> Path:
    resolved = Path(path).resolve()
    if not resolved.is_dir():
        raise RemediationError(f"{label} is not a directory: {resolved}")
    return resolved


def _source_path(root: Path, value: object, *, backup_root: Path) -> tuple[str, Path]:
    logical = _text(value, label="source path")
    candidate = Path(logical)
    if candidate.is_absolute():
        raise RemediationError("source paths must remain within remediation root")
    unresolved = root / candidate
    if unresolved.is_symlink():
        raise RemediationError(f"refusing to remediate symlink: {logical}")
    resolved = unresolved.resolve()
    if not resolved.is_relative_to(root) or resolved.is_relative_to(backup_root):
        raise RemediationError("source paths must remain within remediation root")
    if not resolved.is_file():
        raise RemediationError(f"source file does not exist: {logical}")
    return resolved.relative_to(root).as_posix(), resolved


def _atomic_write(path: Path, content: bytes, *, mode: int) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=path.parent,
            prefix=f".{path.name}.trustgate-",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        temporary_path.chmod(stat.S_IMODE(mode))
        temporary_path.replace(path)
    except BaseException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def _validate_plan(plan: Mapping[str, Any]) -> tuple[str, list[Mapping[str, Any]]]:
    if not isinstance(plan, Mapping) or set(plan) != PLAN_FIELDS:
        raise RemediationError(
            "remediation plan must contain exactly documented fields"
        )
    if plan.get("schema_version") != "1.0.0":
        raise RemediationError("unsupported remediation plan schema version")
    plan_id = _text(plan["plan_id"], label="plan_id", maximum=256)
    requests = plan["requests"]
    if not isinstance(requests, list) or not requests:
        raise RemediationError("remediation plan requires at least one request")
    identifiers: set[str] = set()
    paths: set[str] = set()
    result: list[Mapping[str, Any]] = []
    for request in requests:
        if not isinstance(request, Mapping) or set(request) != REQUEST_FIELDS:
            raise RemediationError(
                "each remediation request must contain exactly documented fields"
            )
        request_id = _text(request["request_id"], label="request_id", maximum=256)
        logical = _text(request["path"], label="source path")
        if request_id in identifiers:
            raise RemediationError(f"duplicate remediation request_id {request_id}")
        if logical in paths:
            raise RemediationError(f"multiple requests for source path {logical}")
        identifiers.add(request_id)
        paths.add(logical)
        if not isinstance(request["parameters"], Mapping):
            raise RemediationError("remediation parameters must be an object")
        if not re_full_digest(request["expected_sha256"]):
            raise RemediationError("expected_sha256 must be a SHA-256 digest")
        result.append(request)
    return plan_id, result


def re_full_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _supports_path(rule_id: str, path: Path) -> bool:
    if rule_id == "TG-DEP-PY-001":
        return path.suffix.lower() in {".in", ".lock", ".txt"}
    if rule_id == "TG-DOCKER-USER-001":
        return path.name == "Dockerfile" or path.name.startswith("Dockerfile.")
    return path.suffix.lower() == ".py"


def apply_remediation_plan(
    root: str | Path,
    plan: Mapping[str, Any],
    *,
    backup_root: str | Path,
) -> dict[str, Any]:
    """Apply a content-bound remediation plan transactionally."""

    from .transformations import TRANSFORMERS

    remediation_root = _root(root, label="remediation root")
    backup_directory = Path(backup_root).resolve()
    if backup_directory == remediation_root:
        raise RemediationError("backup root cannot be the remediation root")
    if backup_directory.exists() and not backup_directory.is_dir():
        raise RemediationError("backup root must be a directory")
    plan_id, requests = _validate_plan(plan)
    rules = {rule["rule_id"]: rule for rule in supported_rules()}
    prepared: list[dict[str, Any]] = []
    for request in requests:
        rule_id = _text(request["rule_id"], label="rule_id", maximum=128)
        rule = rules.get(rule_id)
        transformer = TRANSFORMERS.get(rule_id)
        if rule is None or transformer is None:
            raise RemediationError(f"unsupported remediation rule {rule_id}")
        framework = _text(request["framework"], label="framework", maximum=128)
        if framework != rule["framework"]:
            raise RemediationError(
                f"rule {rule_id} requires framework {rule['framework']}"
            )
        logical, path = _source_path(
            remediation_root,
            request["path"],
            backup_root=backup_directory,
        )
        if not _supports_path(rule_id, path):
            raise RemediationError(
                f"rule {rule_id} does not support file type for {logical}"
            )
        before = path.read_bytes()
        if _digest(before) != request["expected_sha256"]:
            raise RemediationIntegrityError(
                f"source digest does not match remediation request: {logical}"
            )
        try:
            source = before.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RemediationError(f"source is not UTF-8: {logical}") from error
        transformed = transformer(source, request["parameters"])
        after = transformed.encode("utf-8")
        if after == before:
            raise RemediationError(f"rule {rule_id} made no change to {logical}")
        prepared.append(
            {
                "request": request,
                "rule": rule,
                "path": path,
                "logical": logical,
                "before": before,
                "after": after,
                "mode": path.stat().st_mode,
            }
        )

    identity = {
        "schema_version": "1.0.0",
        "plan_id": plan_id,
        "changes": [
            {
                "request_id": item["request"]["request_id"],
                "rule_id": item["request"]["rule_id"],
                "framework": item["request"]["framework"],
                "path": item["logical"],
                "before_sha256": _digest(item["before"]),
                "after_sha256": _digest(item["after"]),
            }
            for item in prepared
        ],
    }
    transaction_id = (
        "remediation-" + _canonical_digest(identity).removeprefix("sha256:")[:24]
    )
    transaction_backup = backup_directory / transaction_id
    changes: list[dict[str, Any]] = []
    for item in prepared:
        backup = transaction_backup / item["logical"]
        changes.append(
            {
                "request_id": item["request"]["request_id"],
                "rule_id": item["request"]["rule_id"],
                "framework": item["request"]["framework"],
                "path": item["logical"],
                "before_sha256": _digest(item["before"]),
                "after_sha256": _digest(item["after"]),
                "backup": backup.relative_to(backup_directory).as_posix(),
                "preconditions": deepcopy(item["rule"]["preconditions"]),
                "transformation": item["rule"]["transformation"],
                "tests": deepcopy(item["rule"]["tests"]),
                "rollback": item["rule"]["rollback"],
                "risk_notes": deepcopy(item["rule"]["risk_notes"]),
            }
        )

    backup_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup_directory.chmod(0o700)
    if transaction_backup.is_symlink():
        raise RemediationIntegrityError(
            "remediation backup transaction cannot be a symlink"
        )
    transaction_backup.mkdir(mode=0o700, parents=True, exist_ok=True)
    if transaction_backup.resolve().parent != backup_directory:
        raise RemediationIntegrityError(
            "remediation backup transaction escaped the backup root"
        )
    transaction_backup.chmod(0o700)
    for item, change in zip(prepared, changes, strict=True):
        backup = backup_directory / change["backup"]
        backup.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not backup.resolve(strict=False).is_relative_to(transaction_backup):
            raise RemediationIntegrityError(
                f"remediation backup path escaped transaction: {change['backup']}"
            )
        if backup.exists():
            if backup.is_symlink() or backup.read_bytes() != item["before"]:
                raise RemediationIntegrityError(
                    f"existing remediation backup is inconsistent: {change['backup']}"
                )
        else:
            backup.write_bytes(item["before"])
            backup.chmod(0o600)

    written: list[dict[str, Any]] = []
    try:
        for item in prepared:
            _atomic_write(item["path"], item["after"], mode=item["mode"])
            written.append(item)
    except BaseException as error:
        for item in reversed(written):
            _atomic_write(item["path"], item["before"], mode=item["mode"])
        raise RemediationError(
            f"remediation write failed and was rolled back: {error}"
        ) from error

    body: dict[str, Any] = {
        "schema_version": "1.0.0",
        "transaction_id": transaction_id,
        "plan_id": plan_id,
        "status": "applied",
        "changes": changes,
    }
    return {**body, "receipt_digest": _canonical_digest(body)}


def rollback_remediation(
    root: str | Path,
    receipt: Mapping[str, Any],
    *,
    backup_root: str | Path,
) -> dict[str, Any]:
    """Restore files from a verified remediation transaction backup."""

    remediation_root = _root(root, label="remediation root")
    backup_directory = _root(backup_root, label="backup root")
    if not isinstance(receipt, Mapping) or set(receipt) != RECEIPT_FIELDS:
        raise RemediationIntegrityError("invalid remediation receipt shape")
    if receipt.get("schema_version") != "1.0.0" or receipt.get("status") != "applied":
        raise RemediationIntegrityError(
            "receipt is not an applied version 1.0.0 receipt"
        )
    body = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    if receipt.get("receipt_digest") != _canonical_digest(body):
        raise RemediationIntegrityError("remediation receipt digest does not match")
    changes = receipt.get("changes")
    if not isinstance(changes, list) or not changes:
        raise RemediationIntegrityError("remediation receipt has no changes")
    prepared: list[dict[str, Any]] = []
    for change in changes:
        if not isinstance(change, Mapping):
            raise RemediationIntegrityError("invalid receipt change")
        logical, path = _source_path(
            remediation_root,
            change.get("path"),
            backup_root=backup_directory,
        )
        if _digest(path.read_bytes()) != change.get("after_sha256"):
            raise RemediationIntegrityError(
                f"current source no longer matches applied remediation: {logical}"
            )
        backup_value = _text(change.get("backup"), label="backup path")
        backup = (backup_directory / backup_value).resolve()
        if (
            not backup.is_relative_to(backup_directory)
            or backup.is_symlink()
            or not backup.is_file()
        ):
            raise RemediationIntegrityError(
                f"invalid remediation backup: {backup_value}"
            )
        original = backup.read_bytes()
        if _digest(original) != change.get("before_sha256"):
            raise RemediationIntegrityError(
                f"remediation backup digest mismatch: {backup_value}"
            )
        prepared.append(
            {
                "logical": logical,
                "path": path,
                "current": path.read_bytes(),
                "original": original,
                "mode": path.stat().st_mode,
            }
        )
    restored: list[dict[str, Any]] = []
    try:
        for item in prepared:
            _atomic_write(item["path"], item["original"], mode=item["mode"])
            restored.append(item)
    except BaseException as error:
        for item in reversed(restored):
            _atomic_write(item["path"], item["current"], mode=item["mode"])
        raise RemediationError(f"rollback failed and was reversed: {error}") from error
    rollback: dict[str, Any] = {
        "schema_version": "1.0.0",
        "transaction_id": receipt["transaction_id"],
        "status": "rolled_back",
        "restored": [item["logical"] for item in prepared],
    }
    return {**rollback, "rollback_digest": _canonical_digest(rollback)}


__all__ = [
    "RemediationError",
    "RemediationIntegrityError",
    "apply_remediation_plan",
    "rollback_remediation",
]
