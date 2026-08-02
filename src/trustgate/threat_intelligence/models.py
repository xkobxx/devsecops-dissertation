"""Privacy-aware models shared by threat-intelligence providers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any


class NetworkMode(StrEnum):
    """Controls which metadata may leave the local Trust Gate process."""

    DISABLED = "disabled"
    METADATA_ONLY = "metadata-only"
    FULL = "full"


DEFAULT_TTLS = {
    "osv": timedelta(hours=24),
    "github-advisories": timedelta(hours=24),
    "nvd": timedelta(hours=24),
    "epss": timedelta(hours=24),
    "cisa-kev": timedelta(hours=6),
}


@dataclass(frozen=True)
class EnrichmentConfig:
    cache_dir: Path
    network_mode: NetworkMode = NetworkMode.METADATA_ONLY
    timeout_seconds: float = 10.0
    github_token: str | None = None
    nvd_api_key: str | None = None
    ttls: dict[str, timedelta] = field(
        default_factory=lambda: dict(DEFAULT_TTLS)
    )

    def ttl_for(self, source: str) -> timedelta:
        return self.ttls.get(source, timedelta(hours=24))


@dataclass(frozen=True)
class ThreatQuery:
    cve_ids: tuple[str, ...] = ()
    ghsa_ids: tuple[str, ...] = ()
    osv_ids: tuple[str, ...] = ()
    package_name: str | None = None
    package_version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None

    @classmethod
    def from_finding(cls, finding: dict[str, Any]) -> "ThreatQuery":
        dependency = finding.get("dependency")
        dependency = dependency if isinstance(dependency, dict) else {}
        return cls(
            cve_ids=tuple(
                sorted({str(value) for value in finding.get("cve", ())})
            ),
            ghsa_ids=tuple(
                sorted({str(value) for value in finding.get("ghsa", ())})
            ),
            osv_ids=tuple(
                sorted({str(value) for value in finding.get("osv", ())})
            ),
            package_name=_optional_string(dependency.get("name")),
            package_version=_optional_string(dependency.get("version")),
            ecosystem=_optional_string(dependency.get("ecosystem")),
            purl=_optional_string(dependency.get("purl")),
        )

    @property
    def advisory_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(set(self.cve_ids + self.ghsa_ids + self.osv_ids))
        )

    def cache_key_for(self, source: str) -> str:
        if source == "osv" and self.osv_ids:
            return ",".join(self.osv_ids)
        if source == "github-advisories" and self.ghsa_ids:
            return ",".join(self.ghsa_ids)
        if self.cve_ids:
            return ",".join(self.cve_ids)
        if self.advisory_ids:
            return ",".join(self.advisory_ids)
        return "|".join(
            value or ""
            for value in (
                self.ecosystem,
                self.package_name,
                self.package_version,
                self.purl,
            )
        )

    def identifiers_for(self, source: str, mode: NetworkMode) -> tuple[str, ...]:
        if mode is NetworkMode.DISABLED:
            return ()
        if (
            source == "osv"
            and mode is NetworkMode.FULL
            and self.package_name
        ):
            return tuple(
                value
                for value in (
                    self.ecosystem,
                    self.package_name,
                    self.package_version,
                    self.purl,
                )
                if value
            )
        if source == "osv":
            identifiers = self.osv_ids or self.ghsa_ids or self.cve_ids
        elif source == "github-advisories":
            identifiers = self.ghsa_ids or self.cve_ids
        else:
            identifiers = self.cve_ids
        if identifiers:
            return tuple(identifiers)
        return ()


@dataclass(frozen=True)
class ThreatRecord:
    source: str
    advisory_ids: tuple[str, ...] = ()
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss_probability: float | None = None
    epss_percentile: float | None = None
    kev_status: bool | None = None
    known_exploitation_date: str | None = None
    ransomware_association: str | None = None
    fixed_versions: tuple[str, ...] = ()
    published_date: str | None = None
    modified_date: str | None = None
    data_source_timestamp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "advisory_ids": list(self.advisory_ids),
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "epss_probability": self.epss_probability,
            "epss_percentile": self.epss_percentile,
            "kev_status": self.kev_status,
            "known_exploitation_date": self.known_exploitation_date,
            "ransomware_association": self.ransomware_association,
            "fixed_versions": list(self.fixed_versions),
            "published_date": self.published_date,
            "modified_date": self.modified_date,
            "data_source_timestamp": self.data_source_timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ThreatRecord":
        return cls(
            source=str(data["source"]),
            advisory_ids=tuple(str(value) for value in data.get("advisory_ids", ())),
            cvss_score=_optional_float(data.get("cvss_score")),
            cvss_vector=_optional_string(data.get("cvss_vector")),
            epss_probability=_optional_float(data.get("epss_probability")),
            epss_percentile=_optional_float(data.get("epss_percentile")),
            kev_status=(
                data.get("kev_status")
                if isinstance(data.get("kev_status"), bool)
                else None
            ),
            known_exploitation_date=_optional_string(
                data.get("known_exploitation_date")
            ),
            ransomware_association=_optional_string(
                data.get("ransomware_association")
            ),
            fixed_versions=tuple(
                str(value) for value in data.get("fixed_versions", ())
            ),
            published_date=_optional_string(data.get("published_date")),
            modified_date=_optional_string(data.get("modified_date")),
            data_source_timestamp=_optional_string(
                data.get("data_source_timestamp")
            ),
        )


def _optional_string(value: object) -> str | None:
    return str(value) if value not in (None, "") else None


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    return float(value)
