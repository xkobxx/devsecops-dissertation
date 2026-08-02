from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from trustgate.threat_intelligence.cache import ThreatCache
from trustgate.threat_intelligence.models import (
    EnrichmentConfig,
    NetworkMode,
    ThreatRecord,
)
from trustgate.threat_intelligence.service import enrich_findings

from tests.unit.schemas.test_schema_contracts import valid_finding


NOW = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)


class StubProvider:
    def __init__(
        self,
        name: str,
        *,
        records: tuple[ThreatRecord, ...] = (),
        error: Exception | None = None,
    ) -> None:
        self.name = name
        self.records = records
        self.error = error
        self.calls = 0

    def fetch(self, query, *, mode, transport):
        self.calls += 1
        if self.error:
            raise self.error
        return self.records


def dependency_finding() -> dict[str, object]:
    finding = valid_finding()
    finding.update(
        {
            "cve": ["CVE-2026-1234"],
            "ghsa": ["GHSA-abcd-1234-efgh"],
            "osv": ["PYSEC-2026-1"],
            "dependency": {
                "name": "demo",
                "version": "1.0.0",
                "ecosystem": "PyPI",
                "purl": "pkg:pypi/demo@1.0.0",
                "direct": True,
            },
        }
    )
    return finding


class ThreatEnrichmentServiceTests(unittest.TestCase):
    def test_merges_fields_and_makes_failures_and_incompleteness_visible(self) -> None:
        osv = StubProvider(
            "osv",
            records=(
                ThreatRecord(
                    source="osv",
                    advisory_ids=("CVE-2026-1234", "PYSEC-2026-1"),
                    fixed_versions=("1.2.0",),
                    published_date="2026-01-01T00:00:00Z",
                    modified_date="2026-01-02T00:00:00Z",
                ),
            ),
        )
        nvd = StubProvider("nvd", error=RuntimeError("rate limited"))
        with tempfile.TemporaryDirectory() as directory:
            enriched = enrich_findings(
                [dependency_finding()],
                config=EnrichmentConfig(
                    cache_dir=Path(directory),
                    network_mode=NetworkMode.METADATA_ONLY,
                ),
                providers=(osv, nvd),
                transport=object(),
                now=NOW,
            )

        threat = enriched[0]["threat_intelligence"]
        self.assertEqual(
            threat["advisory_ids"],
            [
                "CVE-2026-1234",
                "GHSA-abcd-1234-efgh",
                "PYSEC-2026-1",
            ],
        )
        self.assertEqual(threat["fixed_versions"], ["1.2.0"])
        self.assertEqual(threat["network_mode"], "metadata-only")
        self.assertFalse(threat["risk_context_complete"])
        self.assertIn("No threat feed", threat["limitations"][0])
        self.assertEqual(threat["failures"][0]["source"], "nvd")
        self.assertIn("rate limited", threat["failures"][0]["error"])

    def test_original_ids_and_unknown_kev_survive_empty_or_failed_feeds(self) -> None:
        kev = StubProvider("cisa-kev", error=RuntimeError("unavailable"))
        with tempfile.TemporaryDirectory() as directory:
            enriched = enrich_findings(
                [dependency_finding()],
                config=EnrichmentConfig(
                    cache_dir=Path(directory),
                    network_mode=NetworkMode.METADATA_ONLY,
                ),
                providers=(kev,),
                transport=object(),
                now=NOW,
            )

        threat = enriched[0]["threat_intelligence"]
        self.assertEqual(
            threat["advisory_ids"],
            [
                "CVE-2026-1234",
                "GHSA-abcd-1234-efgh",
                "PYSEC-2026-1",
            ],
        )
        self.assertIsNone(threat["kev_status"])
        self.assertIsNone(threat["data_source_timestamp"])

    def test_disabled_mode_uses_stale_cache_without_network(self) -> None:
        provider = StubProvider("epss")
        with tempfile.TemporaryDirectory() as directory:
            cache = ThreatCache(Path(directory))
            cache.put(
                "epss",
                "CVE-2026-1234",
                [
                    ThreatRecord(
                        source="epss",
                        advisory_ids=("CVE-2026-1234",),
                        epss_probability=0.4,
                        epss_percentile=0.9,
                    ).to_dict()
                ],
                fetched_at=NOW - timedelta(days=2),
                ttl=timedelta(hours=24),
            )
            enriched = enrich_findings(
                [dependency_finding()],
                config=EnrichmentConfig(
                    cache_dir=Path(directory),
                    network_mode=NetworkMode.DISABLED,
                ),
                providers=(provider,),
                transport=object(),
                now=NOW,
            )

        threat = enriched[0]["threat_intelligence"]
        self.assertEqual(provider.calls, 0)
        self.assertEqual(threat["epss_probability"], 0.4)
        self.assertTrue(threat["stale"])
        self.assertEqual(threat["sources"][0]["status"], "stale-cache")

    def test_disabled_mode_is_fully_functional_when_cache_is_fresh(self) -> None:
        provider = StubProvider("epss")
        with tempfile.TemporaryDirectory() as directory:
            cache = ThreatCache(Path(directory))
            cache.put(
                "epss",
                "CVE-2026-1234",
                [
                    ThreatRecord(
                        source="epss",
                        advisory_ids=("CVE-2026-1234",),
                        epss_probability=0.4,
                    ).to_dict()
                ],
                fetched_at=NOW,
                ttl=timedelta(hours=24),
            )
            enriched = enrich_findings(
                [dependency_finding()],
                config=EnrichmentConfig(
                    cache_dir=Path(directory),
                    network_mode=NetworkMode.DISABLED,
                ),
                providers=(provider,),
                transport=object(),
                now=NOW,
            )

        self.assertEqual(provider.calls, 0)
        self.assertFalse(enriched[0]["threat_intelligence"]["stale"])
        self.assertEqual(
            enriched[0]["threat_intelligence"]["sources"][0]["status"],
            "fresh-cache",
        )


if __name__ == "__main__":
    unittest.main()
