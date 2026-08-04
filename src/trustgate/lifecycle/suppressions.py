"""Content-bound, scoped finding suppression records."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
import hashlib
import json
from typing import Any

from trustgate.schema import (
    SchemaValidationError,
    SchemaVersionError,
    validate_instance,
)

from .state import FindingState, transition_finding


class SuppressionError(ValueError):
    """Raised when a suppression cannot be created or trusted."""


class SuppressionScopeError(SuppressionError):
    """Raised when a suppression does not match the finding or runtime scope."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: str) -> datetime:
    return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _canonical_digest(value: Mapping[str, Any], *, omit: Sequence[str] = ()) -> str:
    payload = {key: item for key, item in value.items() if key not in omit}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _scope_selector(scope: Mapping[str, Any], name: str) -> list[str]:
    value = scope.get(name, ())
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes))
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        raise SuppressionError(
            f"scope {name} must be an array of non-empty strings"
        )
    return sorted({item.strip() for item in value})


def _exploit_evidence_digest(finding: Mapping[str, Any]) -> str:
    threat = finding.get("threat_intelligence") or {}
    environment = finding.get("environment") or {}
    dynamic = finding.get("dynamic_correlation") or {}
    evidence = {
        "known_exploitation_date": threat.get("known_exploitation_date"),
        "public_exploit_availability": environment.get(
            "public_exploit_availability"
        ),
        "dynamic_status": dynamic.get("status"),
        "dynamic_observations": dynamic.get("matched_observation_ids", []),
    }
    return _canonical_digest(evidence)


def _revalidation_rule(
    finding: Mapping[str, Any],
    policy_digest: str,
) -> dict[str, Any]:
    threat = finding.get("threat_intelligence") or {}
    return {
        "code_region_hash": finding.get("code_region_hash"),
        "reachability": finding["reachability"],
        "kev_status": threat.get("kev_status"),
        "exploit_evidence_digest": _exploit_evidence_digest(finding),
        "policy_digest": policy_digest,
    }


def _verify_suppression(suppression: Mapping[str, Any]) -> dict[str, Any]:
    document = deepcopy(dict(suppression))
    validate_instance("suppression", document)
    expected_digest = _canonical_digest(
        document,
        omit=("suppression_digest",),
    )
    if document["suppression_digest"] != expected_digest:
        raise SuppressionError("suppression digest does not match its content")
    identity_digest = _canonical_digest(
        document,
        omit=("suppression_id", "suppression_digest"),
    )
    if document["suppression_id"] != f"suppression-{identity_digest[-24:]}":
        raise SuppressionError("suppression identifier does not match its content")
    created = _parse_timestamp(document["created_at"])
    approval_time = _parse_timestamp(document["approval"]["timestamp"])
    if approval_time > created:
        raise SuppressionError("suppression approval cannot follow creation")
    expires_at = document["expires_at"]
    if expires_at is not None and _parse_timestamp(expires_at) <= created:
        raise SuppressionError("suppression expiry must follow its creation time")
    return document


def _matches_scope(
    finding: Mapping[str, Any],
    suppression: Mapping[str, Any],
    *,
    repository: str,
    ref: str | None,
    environment: str | None,
) -> bool:
    if finding["fingerprint"] != suppression["finding_fingerprint"]:
        return False
    scope = suppression["scope"]
    if repository != scope["repository"]:
        return False
    if scope["branches"] and (
        ref is None
        or not any(fnmatchcase(ref, pattern) for pattern in scope["branches"])
    ):
        return False
    path = finding.get("file")
    if scope["paths"] and (
        path is None
        or not any(fnmatchcase(str(path), pattern) for pattern in scope["paths"])
    ):
        return False
    if scope["environments"] and environment not in scope["environments"]:
        return False
    return True


def create_suppression(
    finding: Mapping[str, Any],
    *,
    repository: str,
    reason: str,
    author: str,
    created_at: datetime,
    expires_at: datetime | None,
    scope: Mapping[str, Sequence[str]] | None,
    approval: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]],
    policy_digest: str,
    allow_permanent: bool = False,
) -> dict[str, Any]:
    """Create a schema-valid suppression bound to one canonical finding."""

    canonical_finding = deepcopy(dict(finding))
    validate_instance("finding", canonical_finding)
    created = _utc(created_at)
    if expires_at is None and not allow_permanent:
        raise SuppressionError(
            "permanent suppressions require explicit authorization"
        )
    expires = _utc(expires_at) if expires_at is not None else None
    if expires is not None and expires <= created:
        raise SuppressionError("suppression expiry must follow its creation time")
    selectors = dict(scope or {})
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "version": 1,
        "finding_fingerprint": canonical_finding["fingerprint"],
        "reason": reason,
        "author": author,
        "created_at": created.isoformat(),
        "expires_at": expires.isoformat() if expires is not None else None,
        "scope": {
            "repository": repository,
            "branches": _scope_selector(selectors, "branches"),
            "paths": _scope_selector(selectors, "paths"),
            "environments": _scope_selector(selectors, "environments"),
        },
        "approval": deepcopy(dict(approval)),
        "evidence": deepcopy(list(evidence)),
        "revalidation_rule": _revalidation_rule(
            canonical_finding,
            policy_digest,
        ),
    }
    identity_digest = _canonical_digest(document)
    document["suppression_id"] = f"suppression-{identity_digest[-24:]}"
    document["suppression_digest"] = _canonical_digest(
        document,
        omit=("suppression_digest",),
    )
    return _verify_suppression(document)


def apply_suppression(
    finding: Mapping[str, Any],
    suppression: Mapping[str, Any],
    *,
    repository: str,
    ref: str | None = None,
    environment: str | None = None,
    changed_at: datetime | None = None,
) -> dict[str, Any]:
    """Apply a verified suppression only to its exact finding and scope."""

    canonical_finding = deepcopy(dict(finding))
    validate_instance("finding", canonical_finding)
    document = _verify_suppression(suppression)
    if not _matches_scope(
        canonical_finding,
        document,
        repository=repository,
        ref=ref,
        environment=environment,
    ):
        raise SuppressionScopeError(
            "suppression does not match the finding fingerprint and scope"
        )
    recorded_rule = document["revalidation_rule"]
    current_rule = _revalidation_rule(
        canonical_finding,
        recorded_rule["policy_digest"],
    )
    if current_rule != recorded_rule:
        raise SuppressionError(
            "suppression revalidation context changed before application"
        )
    transition_time = _utc(changed_at or datetime.now(timezone.utc))
    if transition_time < _parse_timestamp(document["created_at"]):
        raise SuppressionError(
            "suppression cannot be applied before its creation"
        )
    expires_at = document["expires_at"]
    expiry = _parse_timestamp(expires_at) if expires_at is not None else None
    if expiry is not None and expiry <= transition_time:
        raise SuppressionError("expired suppression cannot be applied")
    evidence = [
        *document["evidence"],
        {
            "kind": "suppression",
            "reference": document["suppression_id"],
            "summary": "Applied content-bound suppression record.",
        },
    ]
    return transition_finding(
        canonical_finding,
        to_state=FindingState.SUPPRESSED,
        actor=document["author"],
        reason=document["reason"],
        evidence=evidence,
        approval=document["approval"],
        expires_at=expiry,
        changed_at=transition_time,
        allow_permanent=expiry is None,
    )


def lint_suppression(
    suppression: Mapping[str, Any],
    *,
    evaluated_at: datetime | None = None,
    warning_window: timedelta = timedelta(days=7),
) -> list[dict[str, str]]:
    """Return actionable issues for one verified suppression record."""

    try:
        document = _verify_suppression(suppression)
    except (SuppressionError, SchemaValidationError, SchemaVersionError) as error:
        return [
            {
                "code": "INVALID_SUPPRESSION",
                "level": "error",
                "message": str(error),
            }
        ]
    if document["expires_at"] is None:
        return [
            {
                "code": "PERMANENT_SUPPRESSION",
                "level": "warning",
                "message": "Suppression has no expiry and requires ongoing review.",
            }
        ]
    evaluation_time = _utc(evaluated_at or datetime.now(timezone.utc))
    expiry = _parse_timestamp(document["expires_at"])
    if expiry <= evaluation_time:
        return [
            {
                "code": "SUPPRESSION_EXPIRED",
                "level": "error",
                "message": f"Suppression expired at {document['expires_at']}.",
            }
        ]
    if evaluation_time < expiry <= evaluation_time + warning_window:
        return [
            {
                "code": "SUPPRESSION_EXPIRING",
                "level": "warning",
                "message": (
                    f"Suppression expires within {warning_window.days} days at "
                    f"{document['expires_at']}."
                ),
            }
        ]
    return []


_REVALIDATION_REASONS = {
    "code_region_hash": "code_changed",
    "reachability": "reachability_changed",
    "kev_status": "kev_status_changed",
    "exploit_evidence_digest": "exploit_evidence_changed",
    "policy_digest": "policy_changed",
}


def revalidate_suppression(
    finding: Mapping[str, Any],
    suppression: Mapping[str, Any],
    *,
    repository: str,
    policy_digest: str,
    ref: str | None = None,
    environment: str | None = None,
    evaluated_at: datetime | None = None,
) -> dict[str, Any]:
    """Reopen a suppressed finding when expiry or recorded risk context changes."""

    canonical_finding = deepcopy(dict(finding))
    validate_instance("finding", canonical_finding)
    document = _verify_suppression(suppression)
    if not _matches_scope(
        canonical_finding,
        document,
        repository=repository,
        ref=ref,
        environment=environment,
    ):
        raise SuppressionScopeError(
            "suppression does not match the finding fingerprint and scope"
        )
    evaluation_time = _utc(evaluated_at or datetime.now(timezone.utc))
    reasons: list[str] = []
    expires_at = document["expires_at"]
    if expires_at is not None and _parse_timestamp(expires_at) <= evaluation_time:
        reasons.append("expired")
    recorded = document["revalidation_rule"]
    current = _revalidation_rule(canonical_finding, policy_digest)
    reasons.extend(
        reason
        for field, reason in _REVALIDATION_REASONS.items()
        if recorded[field] != current[field]
    )
    reopened = bool(reasons) and canonical_finding["status"] == "suppressed"
    result_finding = canonical_finding
    if reopened:
        result_finding = transition_finding(
            canonical_finding,
            to_state=FindingState.OPEN,
            actor="system:trustgate",
            reason="Suppression revalidation returned the finding to evaluation.",
            evidence=[
                {
                    "kind": "suppression-revalidation",
                    "reference": document["suppression_id"],
                    "summary": f"Suppression invalidated: {reason}.",
                }
                for reason in reasons
            ],
            changed_at=evaluation_time,
            automatic=True,
        )
    return {
        "finding": result_finding,
        "active": not reasons and result_finding["status"] == "suppressed",
        "reopened": reopened,
        "reasons": reasons,
        "evaluated_at": evaluation_time.isoformat(),
        "suppression_id": document["suppression_id"],
    }


__all__ = [
    "SuppressionError",
    "SuppressionScopeError",
    "apply_suppression",
    "create_suppression",
    "lint_suppression",
    "revalidate_suppression",
]
