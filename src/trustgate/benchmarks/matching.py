"""Explainable, multi-signal matching between findings and benchmark truth."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any


MATCHING_METHODOLOGY_VERSION = "1.0.0"
_CWE_PATTERN = re.compile(r"CWE-[1-9][0-9]*", re.IGNORECASE)


def _normalise_text(value: Any) -> str | None:
    if value is None:
        return None
    normalised = " ".join(str(value).strip().lower().split())
    return normalised or None


def _normalise_path(value: Any) -> str | None:
    text = _normalise_text(value)
    if text is None:
        return None
    text = text.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    parts = list(PurePosixPath(text).parts)
    fixture_markers = {
        "test_app",
        "test-app",
        "flask_vulnerable",
    }
    for index, part in enumerate(parts):
        if part in fixture_markers and index + 1 < len(parts):
            return "/".join(parts[index + 1 :])
    return "/".join(parts)


def _identifiers(value: Any) -> set[str]:
    values: list[Any]
    if value is None:
        values = []
    elif isinstance(value, list):
        values = value
    else:
        values = [value]
    identifiers: set[str] = set()
    for item in values:
        if isinstance(item, dict):
            identifiers.update(
                str(candidate).upper()
                for candidate in item.values()
                if isinstance(candidate, (str, int))
            )
        elif isinstance(item, (str, int)):
            identifiers.add(str(item).upper())
    return identifiers


def _cwes(record: dict[str, Any]) -> set[str]:
    candidates: list[Any] = []
    for key in ("cwe", "cwes", "identifiers"):
        value = record.get(key)
        candidates.extend(value if isinstance(value, list) else [value])
    return {
        match.group(0).upper()
        for candidate in candidates
        if candidate is not None
        for match in _CWE_PATTERN.finditer(
            json.dumps(candidate) if isinstance(candidate, dict) else str(candidate)
        )
    }


def code_region_hash(source: str) -> str:
    """Hash a code region after removing whitespace-only and comment-only drift."""

    lines: list[str] = []
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        lines.append(" ".join(line.split()))
    payload = "\n".join(lines).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def adjudication_key(finding: dict[str, Any]) -> str:
    """Build a stable key for a manual benchmark adjudication."""

    identity = {
        "scanner": _normalise_text(
            finding.get("scanner", finding.get("tool"))
        ),
        "rule_id": _normalise_text(finding.get("rule_id")),
        "file": _normalise_path(finding.get("file")),
        "line": finding.get("start_line", finding.get("line")),
        "symbol": _normalise_text(finding.get("symbol")),
        "region_hash": _normalise_text(finding.get("code_region_hash")),
    }
    payload = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"finding:sha256:{hashlib.sha256(payload).hexdigest()}"


def _direct_ids(record: dict[str, Any]) -> set[str]:
    values: list[Any] = [
        record.get("vulnerability_id"),
        record.get("benchmark_id"),
        record.get("ground_truth_id"),
    ]
    values.extend(record.get("identifiers") or [])
    return _identifiers(values)


def _scanner_rule_match(
    finding: dict[str, Any],
    truth: dict[str, Any],
) -> bool:
    scanner = _normalise_text(finding.get("scanner", finding.get("tool")))
    rule_id = _normalise_text(finding.get("rule_id"))
    mappings = truth.get("scanner_rules") or {}
    if scanner is None or rule_id is None or not isinstance(mappings, dict):
        return False
    for mapped_scanner, rules in mappings.items():
        if _normalise_text(mapped_scanner) != scanner:
            continue
        candidates = rules if isinstance(rules, list) else [rules]
        return rule_id in {
            candidate
            for candidate in (_normalise_text(item) for item in candidates)
            if candidate is not None
        }
    return False


def _candidate_signals(
    finding: dict[str, Any],
    truth: dict[str, Any],
) -> dict[str, bool]:
    finding_ids = _direct_ids(finding)
    truth_id = str(truth.get("id") or "").upper()
    finding_file = _normalise_path(finding.get("file"))
    truth_file = _normalise_path(truth.get("file"))
    file_match = finding_file is not None and finding_file == truth_file
    finding_symbol = _normalise_text(finding.get("symbol"))
    truth_symbol = _normalise_text(truth.get("symbol"))
    finding_source = _normalise_text(finding.get("source"))
    finding_sink = _normalise_text(finding.get("sink"))
    truth_source = _normalise_text(truth.get("source"))
    truth_sink = _normalise_text(truth.get("sink"))
    finding_hash = _normalise_text(finding.get("code_region_hash"))
    truth_hash = _normalise_text(truth.get("code_region_hash"))
    finding_line = finding.get("start_line", finding.get("line"))
    truth_line = truth.get("line")
    proximity = (
        file_match
        and isinstance(finding_line, int)
        and not isinstance(finding_line, bool)
        and isinstance(truth_line, int)
        and not isinstance(truth_line, bool)
        and abs(finding_line - truth_line) <= 5
    )
    return {
        "vulnerability_id": bool(truth_id and truth_id in finding_ids),
        "scanner_rule": _scanner_rule_match(finding, truth),
        "file": file_match,
        "symbol": bool(
            file_match
            and finding_symbol
            and truth_symbol
            and finding_symbol == truth_symbol
        ),
        "cwe": bool(_cwes(finding) & _cwes(truth)),
        "source_sink": bool(
            file_match
            and finding_source
            and finding_sink
            and truth_source
            and truth_sink
            and finding_source == truth_source
            and finding_sink == truth_sink
        ),
        "code_region_hash": bool(
            file_match
            and finding_hash
            and truth_hash
            and finding_hash == truth_hash
        ),
        "line_proximity": proximity,
    }


def _score(signals: dict[str, bool]) -> int:
    weights = {
        "vulnerability_id": 100,
        "scanner_rule": 60,
        "code_region_hash": 55,
        "source_sink": 45,
        "symbol": 30,
        "cwe": 20,
        "file": 10,
        "line_proximity": 1,
    }
    return sum(weights[name] for name, matched in signals.items() if matched)


def _qualifies(signals: dict[str, bool]) -> bool:
    if signals["vulnerability_id"]:
        return True
    if signals["scanner_rule"] and signals["file"]:
        return True
    if signals["code_region_hash"]:
        return True
    if signals["source_sink"]:
        return True
    return signals["file"] and signals["symbol"] and signals["cwe"]


def _manual_decision(
    finding: dict[str, Any],
    ground_truth: list[dict[str, Any]],
    adjudications: dict[str, dict[str, Any]] | None,
) -> dict[str, Any] | None:
    if not adjudications:
        return None
    key = adjudication_key(finding)
    record = adjudications.get(key)
    if not isinstance(record, dict):
        return None
    status = record.get("status")
    if status not in {"approved", "rejected"}:
        raise ValueError(f"adjudication {key} has unsupported status {status!r}")
    for required in ("reviewer", "reviewed_at", "reason"):
        if not isinstance(record.get(required), str) or not record[required].strip():
            raise ValueError(f"adjudication {key} requires {required}")
    target = record.get("ground_truth_id")
    truth_ids = {str(item.get("id")) for item in ground_truth}
    if status == "approved" and target not in truth_ids:
        raise ValueError(
            f"adjudication {key} references unknown ground truth {target!r}"
        )
    return {
        "finding_key": key,
        "status": "matched" if status == "approved" else "unmatched",
        "ground_truth_id": target if status == "approved" else None,
        "candidate_ids": [target] if status == "approved" else [],
        "ambiguous": False,
        "included_in_metrics": True,
        "matching_reason": [
            {
                "signal": "manual_adjudication",
                "detail": record["reason"],
                "reviewer": record["reviewer"],
                "reviewed_at": record["reviewed_at"],
            }
        ],
        "methodology_version": MATCHING_METHODOLOGY_VERSION,
    }


def match_finding(
    finding: dict[str, Any],
    ground_truth: list[dict[str, Any]],
    *,
    adjudications: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Match one finding without allowing line proximity to decide the result."""

    manual = _manual_decision(finding, ground_truth, adjudications)
    if manual is not None:
        return manual

    candidates: list[tuple[int, str, dict[str, bool]]] = []
    for truth in ground_truth:
        signals = _candidate_signals(finding, truth)
        if _qualifies(signals):
            candidates.append((_score(signals), str(truth.get("id")), signals))
    candidates.sort(key=lambda item: (-item[0], item[1]))
    finding_key = adjudication_key(finding)
    if not candidates:
        return {
            "finding_key": finding_key,
            "status": "unmatched",
            "ground_truth_id": None,
            "candidate_ids": [],
            "ambiguous": False,
            "included_in_metrics": True,
            "matching_reason": [
                {
                    "signal": "no_strong_identity",
                    "detail": (
                        "Line proximity alone is insufficient; no vulnerability ID, "
                        "scanner-rule mapping, file/symbol/CWE, source/sink, or "
                        "code-region hash established identity."
                    ),
                }
            ],
            "methodology_version": MATCHING_METHODOLOGY_VERSION,
        }

    best_score = candidates[0][0]
    close_candidates = [
        candidate
        for candidate in candidates
        if best_score - candidate[0] < 10
    ]
    if len(close_candidates) > 1:
        return {
            "finding_key": finding_key,
            "status": "ambiguous",
            "ground_truth_id": None,
            "candidate_ids": [candidate[1] for candidate in close_candidates],
            "ambiguous": True,
            "included_in_metrics": False,
            "matching_reason": [
                {
                    "signal": "ambiguous_candidates",
                    "detail": (
                        "Multiple ground-truth entries have materially equivalent "
                        "identity evidence; manual adjudication is required."
                    ),
                }
            ],
            "methodology_version": MATCHING_METHODOLOGY_VERSION,
        }

    _, truth_id, signals = candidates[0]
    reasons = [
        {
            "signal": name,
            "detail": (
                "Supporting evidence only; never sufficient by itself."
                if name == "line_proximity"
                else "Identity signal matched."
            ),
        }
        for name, matched in signals.items()
        if matched
    ]
    return {
        "finding_key": finding_key,
        "status": "matched",
        "ground_truth_id": truth_id,
        "candidate_ids": [truth_id],
        "ambiguous": False,
        "included_in_metrics": True,
        "matching_reason": reasons,
        "methodology_version": MATCHING_METHODOLOGY_VERSION,
    }


def match_findings(
    findings: list[dict[str, Any]],
    ground_truth: list[dict[str, Any]],
    *,
    adjudications: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Match a set of findings and expose every decision and exclusion."""

    decisions = [
        match_finding(
            finding,
            ground_truth,
            adjudications=adjudications,
        )
        for finding in findings
    ]
    return {
        "methodology_version": MATCHING_METHODOLOGY_VERSION,
        "decisions": decisions,
        "matched": sum(
            decision["status"] == "matched"
            for decision in decisions
            if decision["included_in_metrics"]
        ),
        "unmatched": sum(
            decision["status"] == "unmatched"
            for decision in decisions
            if decision["included_in_metrics"]
        ),
        "ambiguous_excluded": sum(
            not decision["included_in_metrics"] for decision in decisions
        ),
    }
