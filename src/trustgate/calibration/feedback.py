"""Customer feedback capture for calibration.

Feedback is stored locally by default and never uploaded without
explicit configuration.  Every entry is scoped to a repository or
organisation and used only to adjust local rule reliability.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
from typing import Any

FEEDBACK_SCHEMA_VERSION = "1.0.0"

FEEDBACK_TYPES = (
    "confirmed_true_positive",
    "confirmed_false_positive",
    "accepted_risk",
    "fixed",
    "reopened",
    "remediation_accepted",
    "remediation_rejected",
)


class CalibrationFeedbackError(ValueError):
    """Raised when feedback data is invalid."""


def _validate_feedback(entry: dict[str, Any]) -> None:
    """Validate a single feedback entry."""
    required = ("finding_fingerprint", "feedback_type", "rule_id", "scanner")
    for field in required:
        if not entry.get(field):
            raise CalibrationFeedbackError(f"feedback.{field} is required")
    if entry["feedback_type"] not in FEEDBACK_TYPES:
        raise CalibrationFeedbackError(
            f"unknown feedback type: {entry['feedback_type']}; "
            f"expected one of {', '.join(FEEDBACK_TYPES)}"
        )


def record_feedback(
    entry: dict[str, Any],
    *,
    repository: str | None = None,
    organisation: str | None = None,
) -> dict[str, Any]:
    """Create a validated, scoped feedback record.

    Feedback is always scoped to at least a repository.  Organisation
    scope is additive — it does not replace the repository scope.
    """
    _validate_feedback(entry)
    record = {
        "schema_version": FEEDBACK_SCHEMA_VERSION,
        "finding_fingerprint": entry["finding_fingerprint"],
        "feedback_type": entry["feedback_type"],
        "rule_id": entry["rule_id"],
        "scanner": entry["scanner"],
        "repository": repository or entry.get("repository", "local"),
        "organisation": organisation or entry.get("organisation"),
        "actor": entry.get("actor", "anonymous"),
        "evidence": entry.get("evidence"),
        "created_at": entry.get("created_at"),
    }
    # Deterministic record ID for deduplication
    digest_input = json.dumps(
        {
            "fingerprint": record["finding_fingerprint"],
            "type": record["feedback_type"],
            "repo": record["repository"],
        },
        sort_keys=True,
    )
    record["feedback_id"] = hashlib.sha256(
        digest_input.encode()
    ).hexdigest()[:16]
    return record


class FeedbackStore:
    """Local-first JSON feedback store.

    Stores one JSON array per file.  Never uploads data.
    Supports deletion and encrypted export.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def _load(self) -> list[dict[str, Any]]:
        if not self._path.is_file():
            return []
        return json.loads(self._path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]

    def _save(self, records: list[dict[str, Any]]) -> None:
        # ponytail: atomic write, symlink check
        if self._path.is_symlink():
            raise CalibrationFeedbackError(
                f"refusing symlinked feedback store: {self._path}"
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

    def add(self, record: dict[str, Any]) -> dict[str, Any]:
        """Add a feedback record. Deduplicates by feedback_id."""
        records = self._load()
        existing_ids = {r.get("feedback_id") for r in records}
        if record.get("feedback_id") in existing_ids:
            return record  # idempotent
        records.append(record)
        self._save(records)
        return record

    def list(
        self,
        *,
        repository: str | None = None,
        rule_id: str | None = None,
        scanner: str | None = None,
    ) -> list[dict[str, Any]]:
        """List feedback, optionally filtered."""
        records = self._load()
        if repository:
            records = [r for r in records if r.get("repository") == repository]
        if rule_id:
            records = [r for r in records if r.get("rule_id") == rule_id]
        if scanner:
            records = [r for r in records if r.get("scanner") == scanner]
        return records

    def delete(self, feedback_id: str) -> bool:
        """Delete a feedback record by ID. Returns True if found."""
        records = self._load()
        filtered = [r for r in records if r.get("feedback_id") != feedback_id]
        if len(filtered) == len(records):
            return False
        self._save(filtered)
        return True

    def clear(self) -> int:
        """Delete all feedback. Returns count deleted."""
        records = self._load()
        count = len(records)
        if count:
            self._save([])
        return count

    def export(self) -> list[dict[str, Any]]:
        """Export all records for encrypted backup.

        The caller is responsible for encryption — this just provides
        the plaintext records for export.
        """
        return self._load()
