"""Official advisory-feed clients and provider-specific normalization."""

from __future__ import annotations

from collections.abc import Mapping
import json
from typing import Any, Protocol
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

from .models import NetworkMode, ThreatQuery, ThreatRecord


class JsonTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: object | None = None,
    ) -> object: ...


class UrlLibJsonTransport:
    """Small allowlisted JSON transport with bounded responses."""

    ALLOWED_HOSTS = frozenset(
        {
            "api.osv.dev",
            "api.github.com",
            "services.nvd.nist.gov",
            "api.first.org",
            "www.cisa.gov",
        }
    )

    def __init__(self, *, timeout_seconds: float = 10.0) -> None:
        self.timeout_seconds = timeout_seconds

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: object | None = None,
    ) -> object:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in self.ALLOWED_HOSTS:
            raise ValueError(f"threat feed URL is not allowlisted: {url}")
        encoded = (
            json.dumps(body, separators=(",", ":")).encode("utf-8")
            if body is not None
            else None
        )
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "trustgate-threat-intelligence/1.0",
            **(headers or {}),
        }
        if encoded is not None:
            request_headers["Content-Type"] = "application/json"
        request = Request(
            url,
            data=encoded,
            headers=request_headers,
            method=method,
        )
        with urlopen(request, timeout=self.timeout_seconds) as response:
            raw = response.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("threat feed response exceeded 16 MiB")
        return json.loads(raw.decode("utf-8"))


class OsvProvider:
    name = "osv"

    def fetch(
        self,
        query: ThreatQuery,
        *,
        mode: NetworkMode,
        transport: JsonTransport,
    ) -> tuple[ThreatRecord, ...]:
        if mode is NetworkMode.FULL and query.package_name:
            package: dict[str, str] = {"name": query.package_name}
            if query.ecosystem:
                package["ecosystem"] = query.ecosystem
            body: dict[str, object] = {"package": package}
            if query.package_version:
                body["version"] = query.package_version
            response = transport.request(
                "POST", "https://api.osv.dev/v1/query", body=body
            )
            vulnerabilities = _mapping(response).get("vulns", [])
            return tuple(
                _parse_osv(item)
                for item in vulnerabilities
                if isinstance(item, dict)
            )
        identifiers = query.osv_ids or query.ghsa_ids or query.cve_ids
        return tuple(
            _parse_osv(
                transport.request(
                    "GET",
                    f"https://api.osv.dev/v1/vulns/{quote(identifier, safe='')}",
                )
            )
            for identifier in identifiers
        )


class GitHubAdvisoryProvider:
    name = "github-advisories"

    def __init__(self, token: str | None = None) -> None:
        self.token = token

    def fetch(
        self,
        query: ThreatQuery,
        *,
        mode: NetworkMode,
        transport: JsonTransport,
    ) -> tuple[ThreatRecord, ...]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if query.ghsa_ids:
            responses = [
                transport.request(
                    "GET",
                    "https://api.github.com/advisories/"
                    + quote(identifier, safe=""),
                    headers=headers,
                )
                for identifier in query.ghsa_ids
            ]
        else:
            responses = []
            for identifier in query.cve_ids:
                response = transport.request(
                    "GET",
                    "https://api.github.com/advisories?"
                    + urlencode({"cve_id": identifier, "per_page": 100}),
                    headers=headers,
                )
                responses.extend(response if isinstance(response, list) else [])
        return tuple(
            _parse_github(item) for item in responses if isinstance(item, dict)
        )


class NvdProvider:
    name = "nvd"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key

    def fetch(
        self,
        query: ThreatQuery,
        *,
        mode: NetworkMode,
        transport: JsonTransport,
    ) -> tuple[ThreatRecord, ...]:
        headers = {"apiKey": self.api_key} if self.api_key else None
        records = []
        for identifier in query.cve_ids:
            response = _mapping(
                transport.request(
                    "GET",
                    "https://services.nvd.nist.gov/rest/json/cves/2.0?"
                    + urlencode({"cveIds": identifier}),
                    headers=headers,
                )
            )
            timestamp = _iso(response.get("timestamp"))
            for wrapper in response.get("vulnerabilities", []):
                if isinstance(wrapper, dict) and isinstance(wrapper.get("cve"), dict):
                    records.append(_parse_nvd(wrapper["cve"], timestamp))
        return tuple(records)


class EpssProvider:
    name = "epss"

    def fetch(
        self,
        query: ThreatQuery,
        *,
        mode: NetworkMode,
        transport: JsonTransport,
    ) -> tuple[ThreatRecord, ...]:
        if not query.cve_ids:
            return ()
        response = _mapping(
            transport.request(
                "GET",
                "https://api.first.org/data/v1/epss?"
                + urlencode({"cve": ",".join(query.cve_ids)}),
            )
        )
        return tuple(
            ThreatRecord(
                source=self.name,
                advisory_ids=(str(item["cve"]),),
                epss_probability=float(item["epss"]),
                epss_percentile=float(item["percentile"]),
                data_source_timestamp=_date_as_timestamp(item.get("date")),
            )
            for item in response.get("data", [])
            if isinstance(item, dict)
            and item.get("cve")
            and item.get("epss") is not None
            and item.get("percentile") is not None
        )


class CisaKevProvider:
    name = "cisa-kev"
    URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    def fetch(
        self,
        query: ThreatQuery,
        *,
        mode: NetworkMode,
        transport: JsonTransport,
    ) -> tuple[ThreatRecord, ...]:
        if not query.cve_ids:
            return ()
        response = _mapping(transport.request("GET", self.URL))
        wanted = set(query.cve_ids)
        timestamp = _iso(
            response.get("dateReleased") or response.get("date_released")
        )
        records = []
        for item in response.get("vulnerabilities", []):
            if not isinstance(item, dict) or item.get("cveID") not in wanted:
                continue
            ransomware = str(
                item.get("knownRansomwareCampaignUse", "Unknown")
            ).strip().lower()
            records.append(
                ThreatRecord(
                    source=self.name,
                    advisory_ids=(str(item["cveID"]),),
                    kev_status=True,
                    known_exploitation_date=str(item["dateAdded"]),
                    ransomware_association=(
                        "known" if ransomware == "known" else "unknown"
                    ),
                    data_source_timestamp=timestamp,
                )
            )
        return tuple(records)


def default_providers(
    *,
    github_token: str | None = None,
    nvd_api_key: str | None = None,
) -> tuple[object, ...]:
    return (
        OsvProvider(),
        GitHubAdvisoryProvider(github_token),
        NvdProvider(nvd_api_key),
        EpssProvider(),
        CisaKevProvider(),
    )


def _parse_osv(data: object) -> ThreatRecord:
    value = _mapping(data)
    fixed = set()
    for affected in value.get("affected", []):
        if not isinstance(affected, dict):
            continue
        for range_value in affected.get("ranges", []):
            if not isinstance(range_value, dict):
                continue
            for event in range_value.get("events", []):
                if isinstance(event, dict) and event.get("fixed"):
                    fixed.add(str(event["fixed"]))
    vector = None
    for severity in value.get("severity", []):
        if isinstance(severity, dict) and severity.get("score"):
            vector = str(severity["score"])
            break
    identifiers = {
        str(identifier)
        for identifier in (value.get("aliases") or [])
        if identifier
    }
    if value.get("id"):
        identifiers.add(str(value["id"]))
    return ThreatRecord(
        source="osv",
        advisory_ids=tuple(sorted(identifiers)),
        cvss_vector=vector,
        fixed_versions=tuple(sorted(fixed)),
        published_date=_iso(value.get("published")),
        modified_date=_iso(value.get("modified")),
        data_source_timestamp=_iso(value.get("modified")),
    )


def _parse_github(value: Mapping[str, Any]) -> ThreatRecord:
    identifiers = {
        str(item["value"])
        for item in value.get("identifiers", [])
        if isinstance(item, dict) and item.get("value")
    }
    for key in ("ghsa_id", "cve_id"):
        if value.get(key):
            identifiers.add(str(value[key]))
    severities = value.get("cvss_severities")
    severities = severities if isinstance(severities, dict) else {}
    cvss = severities.get("cvss_v4") or severities.get("cvss_v3") or {}
    cvss = cvss if isinstance(cvss, dict) else {}
    fixed = {
        str(item["first_patched_version"])
        for item in value.get("vulnerabilities", [])
        if isinstance(item, dict) and item.get("first_patched_version")
    }
    return ThreatRecord(
        source="github-advisories",
        advisory_ids=tuple(sorted(identifiers)),
        cvss_score=_float_or_none(cvss.get("score")),
        cvss_vector=_string_or_none(cvss.get("vector_string")),
        fixed_versions=tuple(sorted(fixed)),
        published_date=_iso(value.get("published_at")),
        modified_date=_iso(value.get("updated_at")),
        data_source_timestamp=_iso(value.get("updated_at")),
    )


def _parse_nvd(value: Mapping[str, Any], timestamp: str | None) -> ThreatRecord:
    metrics = value.get("metrics")
    metrics = metrics if isinstance(metrics, dict) else {}
    cvss: Mapping[str, Any] = {}
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(name)
        if isinstance(candidates, list) and candidates:
            first = candidates[0]
            if isinstance(first, dict) and isinstance(first.get("cvssData"), dict):
                cvss = first["cvssData"]
                break
    return ThreatRecord(
        source="nvd",
        advisory_ids=(str(value["id"]),) if value.get("id") else (),
        cvss_score=_float_or_none(cvss.get("baseScore")),
        cvss_vector=_string_or_none(cvss.get("vectorString")),
        published_date=_iso(value.get("published")),
        modified_date=_iso(value.get("lastModified")),
        data_source_timestamp=timestamp,
    )


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("threat feed response root must be an object")
    return value


def _iso(value: object) -> str | None:
    if value in (None, ""):
        return None
    text = str(value)
    if "T" not in text:
        text = text.replace(".", "-")
        return f"{text}T00:00:00Z"
    if text.endswith("Z") or "+" in text[10:] or "-" in text[10:]:
        return text
    return f"{text}Z"


def _date_as_timestamp(value: object) -> str | None:
    return _iso(value)


def _float_or_none(value: object) -> float | None:
    return float(value) if value is not None else None


def _string_or_none(value: object) -> str | None:
    return str(value) if value not in (None, "") else None
