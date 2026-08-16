"""Tests for ticket synchronisation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from trustgate.integrations.tickets import (
    TicketState,
    TicketStore,
    TicketSyncError,
    assign_finding,
    sync_ticket_close,
)


def _finding(**kwargs: object) -> dict:
    return {
        "fingerprint": "abc123",
        "severity": "high",
        "scanner": "Bandit",
        "rule_id": "B101",
        **kwargs,
    }


class AssignFindingTests(unittest.TestCase):

    def test_creates_ticket_record(self):
        record = assign_finding(
            _finding(), owner="alice", integration_type="jira",
        )
        self.assertEqual(record["owner"], "alice")
        self.assertEqual(record["state"], TicketState.OPEN)
        self.assertIn("ticket_key", record)

    def test_deterministic_key(self):
        r1 = assign_finding(
            _finding(), owner="alice", integration_type="jira",
        )
        r2 = assign_finding(
            _finding(), owner="bob", integration_type="jira",
        )
        # Same finding + integration → same key
        self.assertEqual(r1["ticket_key"], r2["ticket_key"])

    def test_different_integration_different_key(self):
        r1 = assign_finding(
            _finding(), owner="alice", integration_type="jira",
        )
        r2 = assign_finding(
            _finding(), owner="alice", integration_type="linear",
        )
        self.assertNotEqual(r1["ticket_key"], r2["ticket_key"])

    def test_missing_fingerprint_rejected(self):
        with self.assertRaises(TicketSyncError):
            assign_finding({}, owner="alice", integration_type="jira")

    def test_missing_owner_rejected(self):
        with self.assertRaises(TicketSyncError):
            assign_finding(_finding(), owner="", integration_type="jira")

    def test_finding_id_used_as_fallback(self):
        f = {"finding_id": "f-001", "severity": "high"}
        record = assign_finding(f, owner="alice", integration_type="jira")
        self.assertEqual(record["finding_fingerprint"], "f-001")


class SyncTicketCloseTests(unittest.TestCase):

    def test_validated_close_updates_finding(self):
        record = assign_finding(
            _finding(), owner="alice", integration_type="jira",
        )
        result = sync_ticket_close(record, validated=True)
        self.assertTrue(result["finding_state_updated"])
        self.assertEqual(result["finding_new_status"], "resolved")
        self.assertEqual(result["state"], TicketState.RESOLVED)

    def test_unvalidated_close_requires_validation(self):
        record = assign_finding(
            _finding(), owner="alice", integration_type="jira",
        )
        result = sync_ticket_close(record, validated=False)
        self.assertFalse(result["finding_state_updated"])
        self.assertTrue(result["requires_validation"])

    def test_wont_fix_maps_to_suppressed(self):
        record = assign_finding(
            _finding(), owner="alice", integration_type="jira",
        )
        result = sync_ticket_close(
            record, new_state=TicketState.WONT_FIX, validated=True,
        )
        self.assertEqual(result["finding_new_status"], "suppressed")

    def test_non_terminal_state_rejected(self):
        record = assign_finding(
            _finding(), owner="alice", integration_type="jira",
        )
        with self.assertRaises(TicketSyncError):
            sync_ticket_close(record, new_state=TicketState.IN_PROGRESS)


class TicketStoreTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self._path = Path(self._dir.name) / "tickets.json"
        self.store = TicketStore(self._path)

    def tearDown(self):
        self._dir.cleanup()

    def test_assign_stores_record(self):
        record = assign_finding(
            _finding(), owner="alice", integration_type="jira",
        )
        self.store.assign(record)
        tickets = self.store.list()
        self.assertEqual(len(tickets), 1)

    def test_duplicate_assignment_returns_existing(self):
        record = assign_finding(
            _finding(), owner="alice", integration_type="jira",
        )
        self.store.assign(record)
        dup = assign_finding(
            _finding(), owner="bob", integration_type="jira",
        )
        result = self.store.assign(dup)
        # Should return existing, not create duplicate
        tickets = self.store.list()
        self.assertEqual(len(tickets), 1)
        self.assertEqual(result["owner"], "alice")

    def test_find_by_fingerprint(self):
        r1 = assign_finding(
            _finding(), owner="alice", integration_type="jira",
        )
        r2 = assign_finding(
            _finding(), owner="alice", integration_type="linear",
        )
        self.store.assign(r1)
        self.store.assign(r2)
        results = self.store.find_by_fingerprint("abc123")
        self.assertEqual(len(results), 2)

    def test_update_state(self):
        record = assign_finding(
            _finding(), owner="alice", integration_type="jira",
        )
        self.store.assign(record)
        updated = self.store.update_state(
            record["ticket_key"], TicketState.IN_PROGRESS,
        )
        self.assertEqual(updated["state"], TicketState.IN_PROGRESS)

    def test_update_terminal_state_calls_sync(self):
        record = assign_finding(
            _finding(), owner="alice", integration_type="jira",
        )
        self.store.assign(record)
        updated = self.store.update_state(
            record["ticket_key"],
            TicketState.RESOLVED,
            validated=True,
        )
        self.assertTrue(updated["finding_state_updated"])

    def test_filter_by_state(self):
        r1 = assign_finding(
            _finding(), owner="alice", integration_type="jira",
        )
        r2 = assign_finding(
            _finding(fingerprint="xyz"), owner="bob", integration_type="jira",
        )
        self.store.assign(r1)
        self.store.assign(r2)
        self.store.update_state(
            r1["ticket_key"], TicketState.IN_PROGRESS,
        )
        open_tickets = self.store.list(state=TicketState.OPEN)
        self.assertEqual(len(open_tickets), 1)

    def test_update_nonexistent_returns_none(self):
        result = self.store.update_state("bogus", TicketState.OPEN)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
