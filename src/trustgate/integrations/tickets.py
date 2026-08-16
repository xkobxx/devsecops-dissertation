"""Ticket synchronisation for finding-to-ticket tracking.

Prevents duplicate tickets and safely syncs ticket close → finding state.
Local-first JSON store, same pattern as calibration feedback.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
from typing import Any


class TicketSyncError(ValueError):
    """Raised when ticket synchronisation data is invalid."""


class TicketState:
    """Ticket lifecycle states."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    WONT_FIX = "wont_fix"

    _TERMINAL = frozenset({RESOLVED, CLOSED, WONT_FIX})

    @classmethod
    def is_terminal(cls, state: str) -> bool:
        return state in cls._TERMINAL


def _ticket_key(finding_fingerprint: str, integration_type: str) -> str:
    """Deterministic ticket key to prevent duplicates."""
    return hashlib.sha256(
        f"{finding_fingerprint}:{integration_type}".encode()
    ).hexdigest()[:16]


def assign_finding(
    finding: dict[str, Any],
    *,
    owner: str,
    integration_type: str,
    ticket_id: str | None = None,
) -> dict[str, Any]:
    """Create a ticket assignment record for a finding.

    Uses a deterministic key to prevent duplicate tickets for the
    same finding+integration pair.
    """
    fingerprint = finding.get("fingerprint") or finding.get("finding_id")
    if not fingerprint:
        raise TicketSyncError("finding must have fingerprint or finding_id")
    if not owner:
        raise TicketSyncError("owner is required")

    return {
        "ticket_key": _ticket_key(fingerprint, integration_type),
        "finding_fingerprint": fingerprint,
        "integration_type": integration_type,
        "ticket_id": ticket_id,
        "owner": owner,
        "state": TicketState.OPEN,
        "rule_id": finding.get("rule_id"),
        "severity": finding.get("severity"),
    }


def sync_ticket_close(
    ticket_record: dict[str, Any],
    *,
    new_state: str = TicketState.RESOLVED,
    validated: bool = False,
) -> dict[str, Any]:
    """Update finding state when a ticket is closed.

    Only updates if 'validated' is True (the close was reviewed).
    This prevents accidental finding resolution from bulk ticket closes.
    """
    if new_state not in (TicketState.RESOLVED, TicketState.CLOSED, TicketState.WONT_FIX):
        raise TicketSyncError(
            f"ticket close requires a terminal state, got: {new_state}"
        )

    result = {**ticket_record, "state": new_state}

    if validated:
        result["finding_state_updated"] = True
        result["finding_new_status"] = (
            "suppressed" if new_state == TicketState.WONT_FIX else "resolved"
        )
    else:
        result["finding_state_updated"] = False
        result["finding_new_status"] = None
        result["requires_validation"] = True

    return result


class TicketStore:
    """Local-first ticket tracking store.

    Prevents duplicate tickets for the same finding+integration pair.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> list[dict[str, Any]]:
        if not self._path.is_file():
            return []
        return json.loads(self._path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]

    def _save(self, records: list[dict[str, Any]]) -> None:
        if self._path.is_symlink():
            raise TicketSyncError(
                f"refusing symlinked ticket store: {self._path}"
            )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self._path.parent,
                prefix=f".{self._path.name}.",
                delete=False,
            ) as f:
                json.dump(records, f, indent=2, sort_keys=True)
                f.write("\n")
                tmp = Path(f.name)
            tmp.replace(self._path)
        except BaseException:
            if tmp is not None:
                tmp.unlink(missing_ok=True)
            raise

    def assign(self, record: dict[str, Any]) -> dict[str, Any]:
        """Add a ticket assignment. Deduplicates by ticket_key."""
        records = self._load()
        existing = {r.get("ticket_key") for r in records}
        if record.get("ticket_key") in existing:
            # Return existing — no duplicate ticket
            for r in records:
                if r.get("ticket_key") == record.get("ticket_key"):
                    return r
            return record  # ponytail: defensive fallback
        records.append(record)
        self._save(records)
        return record

    def find_by_fingerprint(
        self,
        fingerprint: str,
    ) -> list[dict[str, Any]]:
        """Find all tickets for a finding fingerprint."""
        return [
            r for r in self._load()
            if r.get("finding_fingerprint") == fingerprint
        ]

    def update_state(
        self,
        ticket_key: str,
        new_state: str,
        *,
        validated: bool = False,
    ) -> dict[str, Any] | None:
        """Update a ticket's state. Returns updated record or None."""
        records = self._load()
        for i, r in enumerate(records):
            if r.get("ticket_key") == ticket_key:
                if TicketState.is_terminal(new_state):
                    records[i] = sync_ticket_close(
                        r, new_state=new_state, validated=validated,
                    )
                else:
                    records[i] = {**r, "state": new_state}
                self._save(records)
                return records[i]
        return None

    def list(self, *, state: str | None = None) -> list[dict[str, Any]]:
        """List tickets, optionally filtered by state."""
        records = self._load()
        if state:
            records = [r for r in records if r.get("state") == state]
        return records
