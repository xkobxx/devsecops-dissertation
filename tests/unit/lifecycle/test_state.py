"""Behavior tests for auditable finding-state transitions."""

from __future__ import annotations

from datetime import datetime, timezone
import unittest

from trustgate.lifecycle import (
    FindingState,
    LifecycleError,
    reopen_expired_finding,
    transition_finding,
)
from trustgate.schema import validate_instance

from tests.unit.schemas.test_schema_contracts import valid_finding


def suppressed_finding() -> dict[str, object]:
    return transition_finding(
        valid_finding(),
        to_state=FindingState.SUPPRESSED,
        actor="user:developer@example.test",
        reason="Temporary exception while the dependency is upgraded.",
        evidence=[
            {
                "kind": "ticket",
                "reference": "SEC-43",
                "summary": "Upgrade is scheduled.",
            }
        ],
        approval={
            "actor": "user:security@example.test",
            "timestamp": "2026-08-03T11:59:00Z",
            "reason": "Approved until the upgrade window.",
        },
        changed_at=datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
        expires_at=datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc),
    )


class FindingStateTransitionTests(unittest.TestCase):
    def test_transition_records_complete_history_without_mutating_input(self) -> None:
        finding = valid_finding()

        transitioned = transition_finding(
            finding,
            to_state=FindingState.ACKNOWLEDGED,
            actor="user:security@example.test",
            reason="Security triage started.",
            evidence=[
                {
                    "kind": "ticket",
                    "reference": "SEC-42",
                    "summary": "Assigned for investigation.",
                }
            ],
            changed_at=datetime(2026, 8, 3, 10, 30, tzinfo=timezone.utc),
        )

        self.assertEqual(finding["status"], "open")
        self.assertNotIn("state_history", finding)
        self.assertEqual(transitioned["status"], "acknowledged")
        self.assertEqual(
            transitioned["state_history"],
            [
                {
                    "sequence": 1,
                    "from_state": "open",
                    "to_state": "acknowledged",
                    "actor": "user:security@example.test",
                    "timestamp": "2026-08-03T10:30:00+00:00",
                    "reason": "Security triage started.",
                    "evidence": [
                        {
                            "kind": "ticket",
                            "reference": "SEC-42",
                            "summary": "Assigned for investigation.",
                        }
                    ],
                    "approval": None,
                    "expires_at": None,
                    "automatic": False,
                }
            ],
        )
        validate_instance("finding", transitioned)

    def test_suppression_requires_recorded_approval(self) -> None:
        with self.assertRaisesRegex(
            LifecycleError,
            "suppressed state requires approval",
        ):
            transition_finding(
                valid_finding(),
                to_state=FindingState.SUPPRESSED,
                actor="user:developer@example.test",
                reason="Accepted by the service owner.",
                changed_at=datetime(2026, 8, 3, 11, 0, tzinfo=timezone.utc),
            )

    def test_permanent_suppressed_state_requires_explicit_authorization(self) -> None:
        with self.assertRaisesRegex(
            LifecycleError,
            "permanent suppressions require explicit authorization",
        ):
            transition_finding(
                valid_finding(),
                to_state=FindingState.SUPPRESSED,
                actor="user:developer@example.test",
                reason="No expiry provided.",
                approval={
                    "actor": "user:security@example.test",
                    "timestamp": "2026-08-03T10:59:00Z",
                    "reason": "Reviewed by security.",
                },
                changed_at=datetime(2026, 8, 3, 11, 0, tzinfo=timezone.utc),
            )

    def test_expiry_must_follow_the_transition_timestamp(self) -> None:
        with self.assertRaisesRegex(
            LifecycleError,
            "expiry must be after the transition timestamp",
        ):
            transition_finding(
                valid_finding(),
                to_state=FindingState.SUPPRESSED,
                actor="user:developer@example.test",
                reason="Temporary exception.",
                approval={
                    "actor": "user:security@example.test",
                    "timestamp": "2026-08-03T10:59:00Z",
                    "reason": "Approved for one day.",
                },
                changed_at=datetime(2026, 8, 3, 11, 0, tzinfo=timezone.utc),
                expires_at=datetime(2026, 8, 3, 10, 59, tzinfo=timezone.utc),
            )

    def test_expired_state_reopens_automatically_and_preserves_approval(self) -> None:
        suppressed = suppressed_finding()

        reopened = reopen_expired_finding(
            suppressed,
            evaluated_at=datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(suppressed["status"], "suppressed")
        self.assertEqual(reopened["status"], "open")
        self.assertEqual(
            reopened["state_history"][0]["approval"]["actor"],
            "user:security@example.test",
        )
        self.assertEqual(
            reopened["state_history"][0]["expires_at"],
            "2026-08-04T12:00:00+00:00",
        )
        automatic = reopened["state_history"][1]
        self.assertEqual(automatic["sequence"], 2)
        self.assertEqual(automatic["from_state"], "suppressed")
        self.assertEqual(automatic["to_state"], "open")
        self.assertEqual(automatic["actor"], "system:trustgate")
        self.assertTrue(automatic["automatic"])
        self.assertEqual(
            automatic["evidence"][0]["reference"],
            "state-history:1",
        )
        validate_instance("finding", reopened)

    def test_unexpired_state_is_not_reopened(self) -> None:
        suppressed = suppressed_finding()

        unchanged = reopen_expired_finding(
            suppressed,
            evaluated_at=datetime(2026, 8, 4, 11, 59, tzinfo=timezone.utc),
        )

        self.assertEqual(unchanged, suppressed)
        self.assertIsNot(unchanged, suppressed)

    def test_transition_rejects_history_that_disagrees_with_current_state(self) -> None:
        finding = transition_finding(
            valid_finding(),
            to_state=FindingState.ACKNOWLEDGED,
            actor="user:security@example.test",
            reason="Triage started.",
            changed_at=datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
        )
        finding["status"] = "resolved"

        with self.assertRaisesRegex(
            LifecycleError,
            "current status does not match state history",
        ):
            transition_finding(
                finding,
                to_state=FindingState.OPEN,
                actor="user:security@example.test",
                reason="Reopened after review.",
                changed_at=datetime(2026, 8, 3, 13, 0, tzinfo=timezone.utc),
            )

    def test_transition_rejects_a_timestamp_before_existing_history(self) -> None:
        finding = transition_finding(
            valid_finding(),
            to_state=FindingState.ACKNOWLEDGED,
            actor="user:security@example.test",
            reason="Triage started.",
            changed_at=datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
        )

        with self.assertRaisesRegex(
            LifecycleError,
            "state history timestamps are not chronological",
        ):
            transition_finding(
                finding,
                to_state=FindingState.RESOLVED,
                actor="user:developer@example.test",
                reason="Finding was remediated.",
                changed_at=datetime(2026, 8, 3, 11, 59, tzinfo=timezone.utc),
            )

    def test_transition_requires_an_actual_state_change(self) -> None:
        with self.assertRaisesRegex(LifecycleError, "already open"):
            transition_finding(
                valid_finding(),
                to_state=FindingState.OPEN,
                actor="user:security@example.test",
                reason="No state change.",
                changed_at=datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
            )

    def test_approval_cannot_be_recorded_after_the_transition(self) -> None:
        with self.assertRaisesRegex(
            LifecycleError,
            "approval timestamp cannot follow the transition",
        ):
            transition_finding(
                valid_finding(),
                to_state=FindingState.ACCEPTED_RISK,
                actor="user:developer@example.test",
                reason="Risk accepted for the release.",
                approval={
                    "actor": "user:security@example.test",
                    "timestamp": "2026-08-03T12:01:00Z",
                    "reason": "Approved by security.",
                },
                changed_at=datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
            )

    def test_open_state_cannot_have_an_expiry(self) -> None:
        acknowledged = transition_finding(
            valid_finding(),
            to_state=FindingState.ACKNOWLEDGED,
            actor="user:security@example.test",
            reason="Triage started.",
            changed_at=datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
        )

        with self.assertRaisesRegex(LifecycleError, "open state cannot expire"):
            transition_finding(
                acknowledged,
                to_state=FindingState.OPEN,
                actor="user:security@example.test",
                reason="Returned to the triage queue.",
                changed_at=datetime(2026, 8, 3, 13, 0, tzinfo=timezone.utc),
                expires_at=datetime(2026, 8, 4, 13, 0, tzinfo=timezone.utc),
            )


if __name__ == "__main__":
    unittest.main()
