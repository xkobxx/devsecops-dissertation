"""Cache-backed orchestration and normalization for advisory enrichment."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Iterable

from .cache import CacheEntry, ThreatCache
from .models import EnrichmentConfig, NetworkMode, ThreatQuery, ThreatRecord
from .providers import JsonTransport, UrlLibJsonTransport, default_providers


LIMITATION = (
    "No threat feed provides complete risk context; enrichment is advisory "
    "evidence and must be combined with local reachability and environment data."
)


def summarise_threat_data(
    findings: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    threat_records = [
        finding["threat_intelligence"]
        for finding in findings
        if isinstance(finding.get("threat_intelligence"), dict)
    ]
    stale_findings = sum(
        1 for record in threat_records if record.get("stale") is True
    )
    failed_sources = sum(
        len(record.get("failures", ())) for record in threat_records
    )
    if not threat_records:
        status = "not-requested"
    elif stale_findings:
        status = "stale"
    elif failed_sources:
        status = "degraded"
    elif all(
        all(
            source.get("status") in {"cache-miss", "failed", "not-applicable"}
            for source in record.get("sources", ())
        )
        for record in threat_records
    ):
        status = "unavailable"
    else:
        status = "fresh"
    return {
        "status": status,
        "enriched_findings": len(threat_records),
        "stale_findings": stale_findings,
        "failed_sources": failed_sources,
    }


def enrich_findings(
    findings: Iterable[dict[str, Any]],
    *,
    config: EnrichmentConfig,
    providers: Iterable[object] | None = None,
    transport: JsonTransport | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Return enriched copies without ever sending finding source evidence."""

    observed = _utc(now or datetime.now(timezone.utc))
    cache = ThreatCache(config.cache_dir)
    selected_providers = tuple(
        providers
        if providers is not None
        else default_providers(
            github_token=config.github_token,
            nvd_api_key=config.nvd_api_key,
        )
    )
    client = transport or UrlLibJsonTransport(
        timeout_seconds=config.timeout_seconds
    )
    enriched = []
    for original in findings:
        finding = deepcopy(original)
        query = ThreatQuery.from_finding(finding)
        records: list[ThreatRecord] = []
        statuses: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []
        for provider in selected_providers:
            source = str(getattr(provider, "name"))
            identifiers = query.identifiers_for(source, config.network_mode)
            applicable_identifiers = query.identifiers_for(
                source, NetworkMode.METADATA_ONLY
            )
            key = query.cache_key_for(source)
            if not key or (
                not applicable_identifiers
                and not (
                    source == "osv"
                    and config.network_mode is NetworkMode.FULL
                    and query.package_name
                )
            ):
                statuses.append(
                    _status(
                        source=source,
                        status="not-applicable",
                        identifiers=(),
                    )
                )
                continue
            try:
                cached = cache.get(source, key, now=observed)
            except ValueError as error:
                cached = None
                failures.append({"source": source, "error": str(error)})
            if config.network_mode is NetworkMode.DISABLED:
                if cached is None:
                    statuses.append(
                        _status(
                            source=source,
                            status="cache-miss",
                            identifiers=(),
                        )
                    )
                    failures.append(
                        {
                            "source": source,
                            "error": "No cached threat data is available offline.",
                        }
                    )
                    continue
                records.extend(_records_from_cache(cached))
                statuses.append(
                    _cache_status(
                        cached,
                        "stale-cache" if cached.stale else "fresh-cache",
                    )
                )
                continue
            if cached is not None and not cached.stale:
                records.extend(_records_from_cache(cached))
                statuses.append(_cache_status(cached, "fresh-cache"))
                continue
            if source == "nvd" and any(
                record.cvss_score is not None and record.cvss_vector
                for record in records
            ):
                statuses.append(
                    _status(
                        source=source,
                        status="not-needed",
                        identifiers=(),
                    )
                )
                continue
            try:
                fetched = tuple(
                    provider.fetch(
                        query,
                        mode=config.network_mode,
                        transport=client,
                    )
                )
                entry = cache.put(
                    source,
                    key,
                    [record.to_dict() for record in fetched],
                    fetched_at=observed,
                    ttl=config.ttl_for(source),
                )
                records.extend(fetched)
                statuses.append(
                    _cache_status(
                        entry,
                        "refreshed",
                        identifiers=identifiers,
                    )
                )
            except Exception as error:
                failures.append(
                    {
                        "source": source,
                        "error": f"{type(error).__name__}: {error}",
                    }
                )
                if cached is not None:
                    records.extend(_records_from_cache(cached))
                    statuses.append(
                        _cache_status(
                            cached,
                            "stale-cache",
                            identifiers=identifiers,
                        )
                    )
                else:
                    statuses.append(
                        _status(
                            source=source,
                            status="failed",
                            identifiers=identifiers,
                        )
                    )
        finding["threat_intelligence"] = _merge(
            records,
            query=query,
            statuses=statuses,
            failures=failures,
            network_mode=config.network_mode,
        )
        enriched.append(finding)
    return enriched


def enrich_scan_run(
    scan_run: dict[str, Any],
    *,
    config: EnrichmentConfig,
    providers: Iterable[object] | None = None,
    transport: JsonTransport | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Enrich and revalidate an existing canonical scan-run document."""

    from trustgate.schema import validate_instance

    validate_instance("scan-run", scan_run)
    enriched = deepcopy(scan_run)
    enriched["findings"] = enrich_findings(
        enriched["findings"],
        config=config,
        providers=providers,
        transport=transport,
        now=now,
    )
    enriched["summary"]["threat_data"] = summarise_threat_data(
        enriched["findings"]
    )
    validate_instance("scan-run", enriched)
    return enriched


def _records_from_cache(entry: CacheEntry) -> tuple[ThreatRecord, ...]:
    if not isinstance(entry.payload, list):
        raise ValueError("cached threat payload must be a list")
    return tuple(
        ThreatRecord.from_dict(value)
        for value in entry.payload
        if isinstance(value, dict)
    )


def _merge(
    records: Iterable[ThreatRecord],
    *,
    query: ThreatQuery,
    statuses: list[dict[str, Any]],
    failures: list[dict[str, str]],
    network_mode: NetworkMode,
) -> dict[str, Any]:
    values = tuple(records)
    cvss_records = [record for record in values if record.cvss_score is not None]
    cvss = max(cvss_records, key=lambda record: record.cvss_score or 0, default=None)
    epss_records = [
        record for record in values if record.epss_probability is not None
    ]
    epss = max(
        epss_records,
        key=lambda record: record.epss_probability or 0,
        default=None,
    )
    kev_records = [record for record in values if record.kev_status]
    kev = kev_records[0] if kev_records else None
    kev_freshly_checked = any(
        status.get("source") == "cisa-kev"
        and status.get("status") in {"fresh-cache", "refreshed"}
        for status in statuses
    )
    timestamps = sorted(
        {
            value
            for record in values
            for value in (record.data_source_timestamp,)
            if value
        }
        | {
            str(status["fetched_at"])
            for status in statuses
            if status.get("fetched_at")
        }
    )
    published = sorted(
        {record.published_date for record in values if record.published_date}
    )
    modified = sorted(
        {record.modified_date for record in values if record.modified_date}
    )
    return {
        "advisory_ids": sorted(
            set(query.advisory_ids)
            | {
                identifier
                for record in values
                for identifier in record.advisory_ids
            }
        ),
        "cvss_score": cvss.cvss_score if cvss else None,
        "cvss_vector": cvss.cvss_vector if cvss else None,
        "epss_probability": (
            epss.epss_probability if epss else None
        ),
        "epss_percentile": epss.epss_percentile if epss else None,
        "kev_status": True if kev else False if kev_freshly_checked else None,
        "known_exploitation_date": (
            kev.known_exploitation_date if kev else None
        ),
        "ransomware_association": (
            kev.ransomware_association if kev else None
        ),
        "fixed_versions": sorted(
            {
                version
                for record in values
                for version in record.fixed_versions
            }
        ),
        "published_date": published[0] if published else None,
        "modified_date": modified[-1] if modified else None,
        "data_source_timestamp": timestamps[-1] if timestamps else None,
        "network_mode": network_mode.value,
        "stale": any(status.get("stale") is True for status in statuses),
        "risk_context_complete": False,
        "limitations": [LIMITATION],
        "sources": statuses,
        "failures": failures,
    }


def _cache_status(
    entry: CacheEntry,
    status: str,
    *,
    identifiers: tuple[str, ...] = (),
) -> dict[str, Any]:
    return _status(
        source=entry.source,
        status=status,
        identifiers=identifiers,
        fetched_at=entry.fetched_at.isoformat(),
        expires_at=entry.expires_at.isoformat(),
        stale=status == "stale-cache",
    )


def _status(
    *,
    source: str,
    status: str,
    identifiers: tuple[str, ...],
    fetched_at: str | None = None,
    expires_at: str | None = None,
    stale: bool = False,
) -> dict[str, Any]:
    return {
        "source": source,
        "status": status,
        "fetched_at": fetched_at,
        "expires_at": expires_at,
        "stale": stale,
        "identifiers_sent": list(identifiers),
    }


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
