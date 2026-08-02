from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from trustgate.threat_intelligence.cache import ThreatCache


NOW = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)


class ThreatCacheTests(unittest.TestCase):
    def test_round_trips_fresh_and_expired_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = ThreatCache(Path(directory))
            cache.put(
                "epss",
                "CVE-2026-1234",
                {"epss": "0.42"},
                fetched_at=NOW,
                ttl=timedelta(hours=1),
            )

            fresh = cache.get("epss", "CVE-2026-1234", now=NOW)
            stale = cache.get(
                "epss",
                "CVE-2026-1234",
                now=NOW + timedelta(hours=2),
            )

            self.assertIsNotNone(fresh)
            self.assertFalse(fresh.stale)
            self.assertEqual(fresh.payload, {"epss": "0.42"})
            self.assertIsNotNone(stale)
            self.assertTrue(stale.stale)

    def test_cache_paths_are_content_addressed_and_reject_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = ThreatCache(root)
            cache.put(
                "../../epss",
                "../CVE-2026-1234",
                {"ok": True},
                fetched_at=NOW,
                ttl=timedelta(hours=1),
            )
            self.assertEqual(len(list(root.glob("*.json"))), 1)

            linked = root / "linked.json"
            linked.symlink_to(root / "missing.json")
            with self.assertRaises(ValueError):
                cache.read_path(linked, now=NOW)

    def test_corrupt_cache_is_reported_instead_of_silently_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = ThreatCache(Path(directory))
            path = cache.path_for("osv", "GHSA-abcd-1234-efgh")
            path.write_text("{not-json", encoding="utf-8")

            with self.assertRaises(ValueError):
                cache.get("osv", "GHSA-abcd-1234-efgh", now=NOW)


if __name__ == "__main__":
    unittest.main()
