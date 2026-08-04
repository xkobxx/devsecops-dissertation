"""Immutable, auditable state transitions for canonical findings."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from trustgate.schema import validate_instance


class FindingState(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class LifecycleError(ValueError):
    """Raised when a finding state transition is not auditable."""


_APPROVAL_REQUIRED = {
    FindingState.SUPPRESSED,
    FindingState.FALSE_POSITIVE,
    FindingState.ACCEPTED_RISK,
}


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _utc_datetime(value).isoformat()


def _parse_timestamp(value: str) -> datetime:
    return _utc_datetime(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _validate_history(finding: Mapping[str, Any]) -> None:
    history = finding.get("state_history", ())
    if not history:
        return
    previous: Mapping[str, Any] | None = None
    for position, entry in enumerate(history, start=1):
        if entry["sequence"] != position:
            raise LifecycleError("state history sequence is not contiguous")
        if previous is not None:
            if entry["from_state"] != previous["to_state"]:
                raise LifecycleError("state history transitions are not contiguous")
            if _parse_timestamp(entry["timestamp"]) < _parse_timestamp(
                previous["timestamp"]
            ):
                raise LifecycleError("state history timestamps are not chronological")
        state = FindingState(entry["to_state"])
        if state in _APPROVAL_REQUIRED and entry["approval"] is None:
            raise LifecycleError(f"{state.value} state requires approval")
        approval = entry["approval"]
        if approval is not None and _parse_timestamp(
            approval["timestamp"]
        ) > _parse_timestamp(entry["timestamp"]):
            raise LifecycleError("approval timestamp cannot follow the transition")
        expires_at = entry["expires_at"]
        if state is FindingState.OPEN and expires_at is not None:
            raise LifecycleError("open state cannot expire")
        if expires_at is not None and _parse_timestamp(expires_at) <= _parse_timestamp(
            entry["timestamp"]
        ):
            raise LifecycleError("expiry must be after the transition timestamp")
        previous = entry
    if history[-1]["to_state"] != finding["status"]:
        raise LifecycleError("current status does not match state history")


def transition_finding(
    finding: Mapping[str, Any],
    *,
    to_state: FindingState | str,
    actor: str,
    reason: str,
    evidence: Sequence[Mapping[str, Any]] = (),
    changed_at: datetime | None = None,
    approval: Mapping[str, Any] | None = None,
    expires_at: datetime | None = None,
    automatic: bool = False,
    allow_permanent: bool = False,
) -> dict[str, Any]:
    """Return a canonical finding with one immutable history entry appended."""

    current = deepcopy(dict(finding))
    validate_instance("finding", current)
    _validate_history(current)
    try:
        selected_state = FindingState(to_state)
    except ValueError as error:
        raise LifecycleError(f"unsupported finding state {to_state!r}") from error
    if selected_state.value == current["status"]:
        raise LifecycleError(f"finding is already {selected_state.value}")
    if selected_state in _APPROVAL_REQUIRED and approval is None:
        raise LifecycleError(f"{selected_state.value} state requires approval")
    if (
        selected_state is FindingState.SUPPRESSED
        and expires_at is None
        and not allow_permanent
    ):
        raise LifecycleError(
            "permanent suppressions require explicit authorization"
        )
    transition_time = _utc_datetime(changed_at or datetime.now(timezone.utc))
    if selected_state is FindingState.OPEN and expires_at is not None:
        raise LifecycleError("open state cannot expire")
    if expires_at is not None and _utc_datetime(expires_at) <= transition_time:
        raise LifecycleError("expiry must be after the transition timestamp")

    history = list(current.get("state_history", ()))
    entry = {
        "sequence": len(history) + 1,
        "from_state": current["status"],
        "to_state": selected_state.value,
        "actor": actor,
        "timestamp": transition_time.isoformat(),
        "reason": reason,
        "evidence": deepcopy(list(evidence)),
        "approval": deepcopy(dict(approval)) if approval is not None else None,
        "expires_at": _timestamp(expires_at) if expires_at is not None else None,
        "automatic": automatic,
    }
    history.append(entry)
    current["status"] = selected_state.value
    current["state_history"] = history
    validate_instance("finding", current)
    _validate_history(current)
    return current


def reopen_expired_finding(
    finding: Mapping[str, Any],
    *,
    evaluated_at: datetime | None = None,
    actor: str = "system:trustgate",
) -> dict[str, Any]:
    """Automatically reopen a finding when its current state has expired."""

    current = deepcopy(dict(finding))
    validate_instance("finding", current)
    _validate_history(current)
    history = current.get("state_history", ())
    if current["status"] == FindingState.OPEN.value or not history:
        return current
    latest = history[-1]
    expires_at = latest.get("expires_at")
    if expires_at is None:
        return current
    evaluation_time = _utc_datetime(evaluated_at or datetime.now(timezone.utc))
    if _parse_timestamp(str(expires_at)) > evaluation_time:
        return current
    sequence = latest["sequence"]
    return transition_finding(
        current,
        to_state=FindingState.OPEN,
        actor=actor,
        reason=f"The {current['status']} state expired and was automatically reopened.",
        evidence=[
            {
                "kind": "lifecycle-expiry",
                "reference": f"state-history:{sequence}",
                "summary": f"The state expiry {expires_at} was reached.",
            }
        ],
        changed_at=evaluation_time,
        automatic=True,
    )
