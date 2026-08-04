"""Create content-bound baselines from canonical default-branch scan runs."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from trustgate.schema import validate_instance


class BaselineError(ValueError):
    """Raised when a baseline cannot be created or consumed safely."""


class BaselineIntegrityError(BaselineError):
    """Raised when baseline content no longer matches its digest."""


class BaselineCompatibilityError(BaselineError):
    """Raised when valid baseline evidence belongs to another scan contract."""


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise BaselineError("generated_at must include a timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _digest(value: Mapping[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "baseline_digest"}
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _branch(ref: object) -> str | None:
    if not isinstance(ref, str) or not ref:
        return None
    prefix = "refs/heads/"
    return ref[len(prefix):] if ref.startswith(prefix) else ref


def create_baseline(
    scan_run: Mapping[str, Any],
    *,
    default_branch: str,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Create a validated fingerprint index from a default-branch scan run."""

    validate_instance("scan-run", scan_run)
    if not default_branch:
        raise BaselineError("default branch is required")
    if _branch(scan_run.get("ref")) != default_branch:
        raise BaselineError(
            f"scan ref {scan_run.get('ref')!r} is not default branch "
            f"{default_branch!r}"
        )
    repository = scan_run.get("repository")
    if not isinstance(repository, str) or not repository:
        raise BaselineError("repository is required for a baseline")
    commit = scan_run.get("commit")
    if not isinstance(commit, str) or not commit:
        raise BaselineError("commit is required for a baseline")

    findings: dict[str, dict[str, Any]] = {}
    for finding in scan_run.get("findings", ()):
        fingerprint = str(finding.get("fingerprint") or "")
        if fingerprint in findings:
            raise BaselineError(f"duplicate fingerprint {fingerprint!r}")
        findings[fingerprint] = deepcopy(finding)

    scanners: dict[str, dict[str, Any]] = {}
    for scanner in scan_run.get("scanners", ()):
        name = str(scanner.get("scanner") or "")
        if name in scanners:
            raise BaselineError(f"duplicate scanner coverage record {name!r}")
        scanners[name] = deepcopy(scanner)

    baseline: dict[str, Any] = {
        "schema_version": "1.0.0",
        "version": 1,
        "repository": repository,
        "default_branch": default_branch,
        "ref": scan_run["ref"],
        "commit": commit,
        "source_run_id": scan_run["run_id"],
        "source_schema_version": scan_run["schema_version"],
        "generated_at": _timestamp(generated_at or datetime.now(timezone.utc)),
        "findings": {key: findings[key] for key in sorted(findings)},
        "scanners": {key: scanners[key] for key in sorted(scanners)},
    }
    baseline["baseline_digest"] = _digest(baseline)
    verify_baseline(baseline)
    return baseline


def verify_baseline(baseline: Mapping[str, Any]) -> None:
    """Validate baseline structure, index consistency, and content integrity."""

    validate_instance("baseline", baseline)
    for fingerprint, finding in baseline["findings"].items():
        if finding.get("fingerprint") != fingerprint:
            raise BaselineIntegrityError(
                f"finding index key {fingerprint!r} does not match its fingerprint"
            )
    for name, scanner in baseline["scanners"].items():
        if scanner.get("scanner") != name:
            raise BaselineIntegrityError(
                f"scanner index key {name!r} does not match its scanner record"
            )
    if baseline.get("baseline_digest") != _digest(baseline):
        raise BaselineIntegrityError("baseline digest does not match its content")


__all__ = [
    "BaselineError",
    "BaselineCompatibilityError",
    "BaselineIntegrityError",
    "create_baseline",
    "verify_baseline",
]
