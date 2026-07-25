"""Deterministic finding deduplication and correlation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from trustgate.benchmarks.statistics import posterior_precision
from trustgate.fingerprints import normalise_repository_path


_SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}
_SIGNAL_LABELS = {
    "cwe": "CWE",
    "file": "file",
    "symbol": "symbol",
    "source": "source",
    "sink": "sink",
    "code_region": "code region",
    "dependency": "dependency",
    "cve": "CVE",
    "infrastructure_resource": "infrastructure resource",
    "secret_fingerprint": "secret fingerprint",
}


@dataclass(frozen=True, slots=True)
class ScannerContradiction:
    """A scanner or review source that disputes one finding identity."""

    scanner: str
    finding_identity: str
    reason: str

    def __post_init__(self) -> None:
        if not self.scanner.strip():
            raise ValueError("contradicting scanner must not be empty")
        if not self.finding_identity.strip():
            raise ValueError("contradiction finding identity must not be empty")
        if not self.reason.strip():
            raise ValueError("contradiction reason must not be empty")


@dataclass(frozen=True, slots=True)
class CorrelationConfig:
    """Configuration for evidence independence and confidence limits."""

    rule_ancestry: Mapping[str, str] = field(default_factory=dict)
    confidence_level: float = 0.95

    def __post_init__(self) -> None:
        ancestry = dict(self.rule_ancestry)
        if any(
            not str(key).strip() or not str(value).strip()
            for key, value in ancestry.items()
        ):
            raise ValueError("rule ancestry keys and values must not be empty")
        if not 0.0 < self.confidence_level <= 1.0:
            raise ValueError("confidence level must be greater than 0 and at most 1")
        object.__setattr__(
            self,
            "rule_ancestry",
            MappingProxyType(
                {
                    str(key).strip().casefold(): str(value).strip()
                    for key, value in ancestry.items()
                }
            ),
        )


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _unique_objects(values: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for value in values:
        if isinstance(value, dict):
            unique.setdefault(_canonical(value), deepcopy(value))
    return [unique[key] for key in sorted(unique)]


def _location(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "file": finding.get("file"),
        "start_line": finding.get("start_line"),
        "end_line": finding.get("end_line"),
        "symbol": finding.get("symbol"),
    }


def _deduplication_key(finding: dict[str, Any]) -> tuple[str, str]:
    scanner = str(finding.get("scanner") or "unknown").strip().casefold()
    identity = str(
        finding.get("fingerprint")
        or finding.get("finding_id")
        or _canonical(finding)
    )
    return scanner, identity


def _finding_order(finding: dict[str, Any]) -> tuple[Any, ...]:
    raw_reference = finding.get("raw_report_reference")
    raw_path = (
        str(raw_reference.get("path") or "")
        if isinstance(raw_reference, dict)
        else ""
    )
    return (
        *_deduplication_key(finding),
        -_SEVERITY_RANK.get(
            str(finding.get("normalised_severity") or "unknown").lower(),
            0,
        ),
        str(finding.get("file") or ""),
        int(finding.get("start_line") or 0),
        str(finding.get("finding_id") or ""),
        raw_path,
    )


def _merge_exact_group(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    ordered = sorted(findings, key=_finding_order)
    merged = deepcopy(ordered[0])
    merged["occurrence_count"] = sum(
        max(1, int(finding.get("occurrence_count") or 1))
        for finding in ordered
    )
    locations: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    raw_references: list[dict[str, Any]] = []
    source_ids: set[str] = set()
    for finding in ordered:
        existing_locations = finding.get("locations")
        if isinstance(existing_locations, list):
            locations.extend(
                item for item in existing_locations if isinstance(item, dict)
            )
        else:
            locations.append(_location(finding))
        finding_evidence = finding.get("evidence")
        if isinstance(finding_evidence, list):
            evidence.extend(
                item for item in finding_evidence if isinstance(item, dict)
            )
        prior_references = finding.get("raw_evidence_references")
        if isinstance(prior_references, list):
            raw_references.extend(
                item for item in prior_references if isinstance(item, dict)
            )
        raw_reference = finding.get("raw_report_reference")
        if isinstance(raw_reference, dict):
            raw_references.append(raw_reference)
        prior_ids = finding.get("source_finding_ids")
        if isinstance(prior_ids, list):
            source_ids.update(str(item) for item in prior_ids if str(item))
        finding_id = str(finding.get("finding_id") or "")
        if finding_id:
            source_ids.add(finding_id)

    merged["locations"] = _unique_objects(locations)
    merged["evidence"] = _unique_objects(evidence)
    merged["raw_evidence_references"] = _unique_objects(raw_references)
    merged["source_finding_ids"] = sorted(source_ids)
    first_seen = sorted(
        str(finding["first_seen"])
        for finding in ordered
        if finding.get("first_seen")
    )
    last_seen = sorted(
        str(finding["last_seen"])
        for finding in ordered
        if finding.get("last_seen")
    )
    if first_seen:
        merged["first_seen"] = first_seen[0]
    if last_seen:
        merged["last_seen"] = last_seen[-1]
    return merged


def deduplicate_findings(
    findings: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge exact same-scanner repeats without losing occurrences or evidence."""

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            raise TypeError("findings must contain only objects")
        groups.setdefault(_deduplication_key(finding), []).append(finding)
    return [
        _merge_exact_group(groups[key])
        for key in sorted(groups)
    ]


def _string_values(value: Any) -> frozenset[str]:
    values = value if isinstance(value, list) else [value]
    return frozenset(
        str(item).strip().upper()
        for item in values
        if item is not None and str(item).strip()
    )


def _same_text(first: Any, second: Any) -> bool:
    return bool(
        first is not None
        and second is not None
        and str(first).strip()
        and str(first).strip().casefold() == str(second).strip().casefold()
    )


def _dependency_identity(finding: dict[str, Any]) -> tuple[str, str] | None:
    dependency = finding.get("dependency")
    if not isinstance(dependency, dict):
        return None
    name = str(dependency.get("name") or "").strip().casefold()
    ecosystem = str(dependency.get("ecosystem") or "").strip().casefold()
    aliases = {"pip": "pypi", "python": "pypi"}
    ecosystem = aliases.get(ecosystem, ecosystem)
    if not name:
        return None
    return ecosystem, name


def _regions_related(first: dict[str, Any], second: dict[str, Any]) -> bool:
    first_hash = first.get("code_region_hash")
    second_hash = second.get("code_region_hash")
    if _same_text(first_hash, second_hash):
        return True
    first_start = first.get("start_line")
    second_start = second.get("start_line")
    if not isinstance(first_start, int) or not isinstance(second_start, int):
        return False
    first_end = (
        first.get("end_line")
        if isinstance(first.get("end_line"), int)
        else first_start
    )
    second_end = (
        second.get("end_line")
        if isinstance(second.get("end_line"), int)
        else second_start
    )
    return not (
        int(first_end) + 5 < second_start
        or int(second_end) + 5 < first_start
    )


def _correlation_signals(
    first: dict[str, Any],
    second: dict[str, Any],
) -> frozenset[str]:
    if _same_text(first.get("scanner"), second.get("scanner")):
        return frozenset()

    signals: set[str] = set()
    first_file = normalise_repository_path(first.get("file"))
    second_file = normalise_repository_path(second.get("file"))
    if _same_text(first_file, second_file):
        signals.add("file")
    if _string_values(first.get("cwe")) & _string_values(second.get("cwe")):
        signals.add("cwe")
    if _same_text(first.get("symbol"), second.get("symbol")):
        signals.add("symbol")
    if _same_text(first.get("source"), second.get("source")):
        signals.add("source")
    if _same_text(first.get("sink"), second.get("sink")):
        signals.add("sink")
    if "file" in signals and _regions_related(first, second):
        signals.add("code_region")
    if (
        _dependency_identity(first) is not None
        and _dependency_identity(first) == _dependency_identity(second)
    ):
        signals.add("dependency")
    if _string_values(first.get("cve")) & _string_values(second.get("cve")):
        signals.add("cve")
    if _same_text(
        first.get("infrastructure_resource"),
        second.get("infrastructure_resource"),
    ):
        signals.add("infrastructure_resource")
    if _same_text(
        first.get("secret_fingerprint"),
        second.get("secret_fingerprint"),
    ):
        signals.add("secret_fingerprint")

    strong_identity = bool(
        {"infrastructure_resource", "secret_fingerprint"} & signals
        or {"dependency", "cve"}.issubset(signals)
    )
    code_weight = sum(
        {
            "file": 1,
            "cwe": 2,
            "symbol": 2,
            "source": 2,
            "sink": 2,
            "code_region": 2,
        }.get(signal, 0)
        for signal in signals
    )
    has_semantic_anchor = bool(
        {"cwe", "symbol", "source", "sink"} & signals
    )
    if strong_identity or (
        "file" in signals and has_semantic_anchor and code_weight >= 5
    ):
        return frozenset(signals)
    return frozenset()


def _cluster_identity(
    members: list[dict[str, Any]],
    signals: frozenset[str],
) -> dict[str, Any]:
    representative = members[0]
    identity: dict[str, Any] = {
        "signals": sorted(signals),
        "category": str(representative.get("category") or "").casefold(),
    }
    if "file" in signals:
        identity["file"] = normalise_repository_path(representative.get("file"))
    for name in (
        "symbol",
        "source",
        "sink",
        "code_region_hash",
        "infrastructure_resource",
        "secret_fingerprint",
    ):
        if representative.get(name):
            identity[name] = representative[name]
    if "cwe" in signals:
        identity["cwe"] = sorted(
            set.intersection(
                *[
                    set(_string_values(member.get("cwe")))
                    for member in members
                ]
            )
        )
    if "cve" in signals:
        identity["cve"] = sorted(
            set.intersection(
                *[
                    set(_string_values(member.get("cve")))
                    for member in members
                ]
            )
        )
    if "dependency" in signals:
        identity["dependency"] = _dependency_identity(representative)
    return identity


def _all_pair_signals(
    members: list[dict[str, Any]],
) -> frozenset[str]:
    signals: set[str] = set()
    for index, first in enumerate(members):
        for second in members[index + 1 :]:
            signals.update(_correlation_signals(first, second))
    return frozenset(signals)


def _contradictions_for(
    members: list[dict[str, Any]],
    contradictions: tuple[ScannerContradiction, ...],
) -> tuple[ScannerContradiction, ...]:
    identities = {
        str(member.get(field) or "")
        for member in members
        for field in ("finding_id", "fingerprint")
    }
    identities.update(
        str(identity)
        for member in members
        for identity in member.get("source_finding_ids") or []
    )
    return tuple(
        item for item in contradictions if item.finding_identity in identities
    )


def _merge_cluster(
    members: list[dict[str, Any]],
    contradictions: tuple[ScannerContradiction, ...],
    config: CorrelationConfig,
) -> dict[str, Any]:
    merged = _merge_exact_group(members)
    supporting_scanners = sorted(
        {str(member.get("scanner") or "unknown") for member in members}
    )
    signals = _all_pair_signals(members)
    attached_contradictions = _contradictions_for(members, contradictions)
    contradicting_scanners = sorted(
        {item.scanner for item in attached_contradictions}
    )
    if len(members) > 1:
        identity = _cluster_identity(members, signals)
        digest = hashlib.sha256(
            _canonical(identity).encode("utf-8")
        ).hexdigest()
        merged["finding_id"] = f"correlated-{digest[:24]}"
        merged["fingerprint"] = f"correlation-v1:sha256:{digest}"
    labels = [_SIGNAL_LABELS.get(signal, signal) for signal in sorted(signals)]
    if len(supporting_scanners) > 1:
        reason = (
            "Correlated scanner findings by "
            + ", ".join(labels)
            + "."
        )
    else:
        reason = "Single-scanner issue; no independent corroboration."
    if attached_contradictions:
        reason += (
            f" {len(attached_contradictions)} contradiction(s) recorded: "
            + "; ".join(
                f"{item.scanner}: {item.reason}"
                for item in attached_contradictions
            )
        )

    ancestry_sources: dict[str, set[str]] = {}
    for member in members:
        scanner = str(member.get("scanner") or "unknown")
        rule_id = str(member.get("rule_id") or "unknown")
        explicit = member.get("rule_ancestry")
        ancestry = (
            str(explicit)
            if explicit
            else config.rule_ancestry.get(
                f"{scanner}:{rule_id}".casefold(),
                f"scanner:{scanner}",
            )
        )
        ancestry_sources.setdefault(ancestry, set()).add(scanner)
    independent_sources = sorted(ancestry_sources)
    shared_ancestry = [
        {
            "ancestry": ancestry,
            "scanners": sorted(scanners),
        }
        for ancestry, scanners in sorted(ancestry_sources.items())
        if len(scanners) > 1
    ]
    independent_scanner_count = len(independent_sources)
    if len(supporting_scanners) > 1 and independent_scanner_count < 2:
        reason += " Shared rule ancestry prevents independent corroboration."

    human_confirmations = _unique_objects(
        item
        for item in merged.get("evidence") or []
        if item.get("kind") in {"human_confirmation", "manual_validation"}
    )
    dast_confirmations = sorted(
        {
            str(member.get("scanner") or "unknown")
            for member in members
            if str(member.get("category") or "").casefold() == "dast"
            or any(
                isinstance(item, dict)
                and item.get("kind") == "dast_confirmation"
                for item in member.get("evidence") or []
            )
        }
    )
    positive_evidence = independent_scanner_count + bool(human_confirmations)
    posterior = posterior_precision(
        int(positive_evidence),
        len(contradicting_scanners),
        confidence_level=config.confidence_level,
    )
    corroboration = {
        "method": "beta-binomial-independent-evidence",
        "methodology_version": posterior["methodology_version"],
        "independent_scanner_count": independent_scanner_count,
        "independent_sources": independent_sources,
        "shared_rule_ancestry": shared_ancestry,
        "dast_confirmations": dast_confirmations,
        "human_confirmations": human_confirmations,
        "supporting_evidence_count": int(positive_evidence),
        "contradicting_evidence_count": len(contradicting_scanners),
        "estimate": posterior["displayed_estimate"],
        "conservative_bound": posterior["gating_estimate"],
        "confidence_interval": posterior["interval"],
        "explanation": (
            "Independent scanner and human agreement can increase finding-validity "
            "confidence. Shared rule ancestry is counted once. DAST and human "
            "confirmation remain separate; scanner agreement is finding-validity "
            "evidence, not exploitability evidence."
        ),
    }

    merged["supporting_scanners"] = supporting_scanners
    merged["contradicting_scanners"] = contradicting_scanners
    merged["agreement_strength"] = (
        round(
            independent_scanner_count
            / (independent_scanner_count + len(contradicting_scanners)),
            6,
        )
        if independent_scanner_count > 1
        else 0.0
    )
    merged["correlation_reason"] = reason
    merged["correlation_signals"] = sorted(signals)
    merged["corroboration"] = corroboration
    if independent_scanner_count > 1:
        merged["evidence"] = _unique_objects(
            [
                *merged["evidence"],
                {
                    "kind": "corroboration",
                    "summary": (
                        "Independent scanners reported the same issue."
                    ),
                    "reference": merged["fingerprint"],
                    "excerpt": reason,
                },
            ]
        )
    return merged


def correlate_findings(
    findings: Iterable[dict[str, Any]],
    *,
    contradictions: Iterable[ScannerContradiction] = (),
    config: CorrelationConfig | None = None,
) -> list[dict[str, Any]]:
    """Consolidate only findings joined by conservative, explainable signals."""

    deduplicated = deduplicate_findings(findings)
    clusters: list[list[dict[str, Any]]] = []
    for candidate in deduplicated:
        for cluster in clusters:
            if all(
                _correlation_signals(member, candidate)
                for member in cluster
            ):
                cluster.append(candidate)
                break
        else:
            clusters.append([candidate])
    contradiction_tuple = tuple(contradictions)
    resolved_config = config or CorrelationConfig()
    return [
        _merge_cluster(cluster, contradiction_tuple, resolved_config)
        for cluster in clusters
    ]


__all__ = [
    "ScannerContradiction",
    "CorrelationConfig",
    "correlate_findings",
    "deduplicate_findings",
]
