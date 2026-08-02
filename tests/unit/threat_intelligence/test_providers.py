from __future__ import annotations

import unittest

from trustgate.threat_intelligence.models import NetworkMode, ThreatQuery
from trustgate.threat_intelligence.providers import (
    CisaKevProvider,
    EpssProvider,
    GitHubAdvisoryProvider,
    NvdProvider,
    OsvProvider,
)


class FakeTransport:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, object]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: object | None = None,
    ) -> object:
        self.requests.append(
            {"method": method, "url": url, "headers": headers, "body": body}
        )
        return self.responses.pop(0)


QUERY = ThreatQuery(
    cve_ids=("CVE-2026-1234",),
    ghsa_ids=("GHSA-abcd-1234-efgh",),
    osv_ids=("PYSEC-2026-1",),
    package_name="demo",
    package_version="1.0.0",
    ecosystem="PyPI",
    purl="pkg:pypi/demo@1.0.0",
)


class ProviderTests(unittest.TestCase):
    def test_full_osv_disclosure_list_matches_package_payload(self) -> None:
        self.assertEqual(
            QUERY.identifiers_for("osv", NetworkMode.FULL),
            ("PyPI", "demo", "1.0.0", "pkg:pypi/demo@1.0.0"),
        )

    def test_osv_metadata_only_sends_only_advisory_identifiers(self) -> None:
        transport = FakeTransport(
            [
                {
                    "id": "PYSEC-2026-1",
                    "aliases": ["CVE-2026-1234"],
                    "published": "2026-01-01T00:00:00Z",
                    "modified": "2026-01-02T00:00:00Z",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "1.2.0"},
                                    ]
                                }
                            ]
                        }
                    ],
                }
            ]
        )

        records = OsvProvider().fetch(
            QUERY,
            mode=NetworkMode.METADATA_ONLY,
            transport=transport,
        )

        self.assertEqual(transport.requests[0]["method"], "GET")
        self.assertIn("PYSEC-2026-1", str(transport.requests[0]["url"]))
        self.assertIsNone(transport.requests[0]["body"])
        self.assertEqual(records[0].fixed_versions, ("1.2.0",))
        self.assertIn("CVE-2026-1234", records[0].advisory_ids)

    def test_osv_full_mode_can_send_package_metadata_but_never_finding_code(self) -> None:
        transport = FakeTransport([{"vulns": []}])

        OsvProvider().fetch(QUERY, mode=NetworkMode.FULL, transport=transport)

        body = transport.requests[0]["body"]
        self.assertEqual(
            body,
            {
                "version": "1.0.0",
                "package": {"name": "demo", "ecosystem": "PyPI"},
            },
        )
        self.assertNotIn("file", str(body).lower())
        self.assertNotIn("source", str(body).lower())

    def test_github_advisory_parses_cvss_dates_and_fixed_versions(self) -> None:
        transport = FakeTransport(
            [
                {
                    "ghsa_id": "GHSA-abcd-1234-efgh",
                    "cve_id": "CVE-2026-1234",
                    "identifiers": [
                        {"type": "GHSA", "value": "GHSA-abcd-1234-efgh"},
                        {"type": "CVE", "value": "CVE-2026-1234"},
                    ],
                    "published_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-03T00:00:00Z",
                    "cvss_severities": {
                        "cvss_v4": {
                            "vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N",
                            "score": 9.3,
                        }
                    },
                    "vulnerabilities": [{"first_patched_version": "1.2.0"}],
                }
            ]
        )

        record = GitHubAdvisoryProvider().fetch(
            QUERY,
            mode=NetworkMode.METADATA_ONLY,
            transport=transport,
        )[0]

        self.assertEqual(record.cvss_score, 9.3)
        self.assertTrue(record.cvss_vector.startswith("CVSS:4.0"))
        self.assertEqual(record.fixed_versions, ("1.2.0",))

    def test_nvd_epss_and_kev_normalise_provider_specific_fields(self) -> None:
        nvd_transport = FakeTransport(
            [
                {
                    "timestamp": "2026-01-04T00:00:00.000Z",
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2026-1234",
                                "published": "2026-01-01T00:00:00.000",
                                "lastModified": "2026-01-03T00:00:00.000",
                                "metrics": {
                                    "cvssMetricV31": [
                                        {
                                            "cvssData": {
                                                "baseScore": 9.8,
                                                "vectorString": "CVSS:3.1/AV:N/AC:L",
                                            }
                                        }
                                    ]
                                },
                            }
                        }
                    ],
                }
            ]
        )
        epss_transport = FakeTransport(
            [
                {
                    "data": [
                        {
                            "cve": "CVE-2026-1234",
                            "epss": "0.420000",
                            "percentile": "0.910000",
                            "date": "2026-01-04",
                        }
                    ]
                }
            ]
        )
        kev_transport = FakeTransport(
            [
                {
                    "dateReleased": "2026-01-04T00:00:00Z",
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2026-1234",
                            "dateAdded": "2026-01-02",
                            "knownRansomwareCampaignUse": "Known",
                        }
                    ],
                }
            ]
        )

        nvd = NvdProvider().fetch(
            QUERY, mode=NetworkMode.METADATA_ONLY, transport=nvd_transport
        )[0]
        epss = EpssProvider().fetch(
            QUERY, mode=NetworkMode.METADATA_ONLY, transport=epss_transport
        )[0]
        kev = CisaKevProvider().fetch(
            QUERY, mode=NetworkMode.METADATA_ONLY, transport=kev_transport
        )[0]

        self.assertEqual(nvd.cvss_score, 9.8)
        self.assertEqual(epss.epss_probability, 0.42)
        self.assertEqual(epss.epss_percentile, 0.91)
        self.assertTrue(kev.kev_status)
        self.assertEqual(kev.known_exploitation_date, "2026-01-02")
        self.assertEqual(kev.ransomware_association, "known")

    def test_cisa_dotted_release_date_is_normalised_to_iso_timestamp(self) -> None:
        transport = FakeTransport(
            [
                {
                    "dateReleased": "2026.07.25",
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2026-1234",
                            "dateAdded": "2026-07-24",
                            "knownRansomwareCampaignUse": "Unknown",
                        }
                    ],
                }
            ]
        )

        records = CisaKevProvider().fetch(
            QUERY, mode=NetworkMode.METADATA_ONLY, transport=transport
        )

        self.assertEqual(
            records[0].data_source_timestamp,
            "2026-07-25T00:00:00Z",
        )


if __name__ == "__main__":
    unittest.main()
