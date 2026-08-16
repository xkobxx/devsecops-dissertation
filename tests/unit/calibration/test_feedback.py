"""Tests for customer feedback capture."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from trustgate.calibration.feedback import (
    CalibrationFeedbackError,
    FEEDBACK_SCHEMA_VERSION,
    FEEDBACK_TYPES,
    FeedbackStore,
    record_feedback,
)


def _entry(**overrides: object) -> dict:
    base = {
        "finding_fingerprint": "abc123",
        "feedback_type": "confirmed_true_positive",
        "rule_id": "B101",
        "scanner": "Bandit",
    }
    base.update(overrides)
    return base


class RecordFeedbackTests(unittest.TestCase):

    def test_valid_feedback_returns_record(self):
        record = record_feedback(_entry())
        self.assertEqual(record["schema_version"], FEEDBACK_SCHEMA_VERSION)
        self.assertEqual(record["feedback_type"], "confirmed_true_positive")
        self.assertIn("feedback_id", record)

    def test_all_feedback_types_accepted(self):
        for ftype in FEEDBACK_TYPES:
            record = record_feedback(_entry(feedback_type=ftype))
            self.assertEqual(record["feedback_type"], ftype)

    def test_unknown_feedback_type_rejected(self):
        with self.assertRaises(CalibrationFeedbackError):
            record_feedback(_entry(feedback_type="invalid_type"))

    def test_missing_fingerprint_rejected(self):
        with self.assertRaises(CalibrationFeedbackError):
            record_feedback(_entry(finding_fingerprint=""))

    def test_missing_rule_id_rejected(self):
        with self.assertRaises(CalibrationFeedbackError):
            record_feedback(_entry(rule_id=""))

    def test_repository_scope_applied(self):
        record = record_feedback(_entry(), repository="my-repo")
        self.assertEqual(record["repository"], "my-repo")

    def test_organisation_scope_applied(self):
        record = record_feedback(
            _entry(), repository="my-repo", organisation="my-org"
        )
        self.assertEqual(record["organisation"], "my-org")

    def test_default_repository_is_local(self):
        record = record_feedback(_entry())
        self.assertEqual(record["repository"], "local")

    def test_feedback_id_is_deterministic(self):
        r1 = record_feedback(_entry())
        r2 = record_feedback(_entry())
        self.assertEqual(r1["feedback_id"], r2["feedback_id"])

    def test_different_types_produce_different_ids(self):
        r1 = record_feedback(_entry(feedback_type="confirmed_true_positive"))
        r2 = record_feedback(_entry(feedback_type="confirmed_false_positive"))
        self.assertNotEqual(r1["feedback_id"], r2["feedback_id"])


class FeedbackStoreTests(unittest.TestCase):

    def test_add_and_list(self):
        with tempfile.TemporaryDirectory() as d:
            store = FeedbackStore(Path(d) / "feedback.json")
            record = record_feedback(_entry())
            store.add(record)
            results = store.list()
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["feedback_id"], record["feedback_id"])

    def test_deduplication(self):
        with tempfile.TemporaryDirectory() as d:
            store = FeedbackStore(Path(d) / "feedback.json")
            record = record_feedback(_entry())
            store.add(record)
            store.add(record)  # duplicate
            self.assertEqual(len(store.list()), 1)

    def test_filter_by_repository(self):
        with tempfile.TemporaryDirectory() as d:
            store = FeedbackStore(Path(d) / "feedback.json")
            store.add(record_feedback(_entry(), repository="repo-a"))
            store.add(record_feedback(
                _entry(finding_fingerprint="xyz"),
                repository="repo-b",
            ))
            self.assertEqual(len(store.list(repository="repo-a")), 1)

    def test_filter_by_rule_id(self):
        with tempfile.TemporaryDirectory() as d:
            store = FeedbackStore(Path(d) / "feedback.json")
            store.add(record_feedback(_entry(rule_id="B101")))
            store.add(record_feedback(
                _entry(rule_id="B102", finding_fingerprint="other")
            ))
            self.assertEqual(len(store.list(rule_id="B101")), 1)

    def test_delete(self):
        with tempfile.TemporaryDirectory() as d:
            store = FeedbackStore(Path(d) / "feedback.json")
            record = record_feedback(_entry())
            store.add(record)
            self.assertTrue(store.delete(record["feedback_id"]))
            self.assertEqual(len(store.list()), 0)

    def test_delete_nonexistent_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            store = FeedbackStore(Path(d) / "feedback.json")
            self.assertFalse(store.delete("nonexistent"))

    def test_clear(self):
        with tempfile.TemporaryDirectory() as d:
            store = FeedbackStore(Path(d) / "feedback.json")
            store.add(record_feedback(_entry()))
            store.add(record_feedback(
                _entry(finding_fingerprint="other")
            ))
            count = store.clear()
            self.assertEqual(count, 2)
            self.assertEqual(len(store.list()), 0)

    def test_export_returns_all_records(self):
        with tempfile.TemporaryDirectory() as d:
            store = FeedbackStore(Path(d) / "feedback.json")
            store.add(record_feedback(_entry()))
            exported = store.export()
            self.assertEqual(len(exported), 1)

    def test_empty_store_lists_empty(self):
        with tempfile.TemporaryDirectory() as d:
            store = FeedbackStore(Path(d) / "feedback.json")
            self.assertEqual(store.list(), [])

    def test_keeps_feedback_local(self):
        """Feedback is stored in the provided path, not uploaded."""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "feedback.json"
            store = FeedbackStore(path)
            store.add(record_feedback(_entry()))
            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
