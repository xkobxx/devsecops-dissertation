"""Adapter-owned parsers and the compatibility aggregation engine."""

import argparse
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile
from typing import Any
import xml.etree.ElementTree as ElementTree

from trustgate.scanners.models import ParserStatus, ScannerResult, ScannerState
from trustgate.severity import (
    cvss_severity_decision,
    normalise_scanner_severity,
    secret_severity_decision,
    severity_quality_evidence,
)
from trustgate.schema import (
    build_policy_result,
    build_scan_run,
    migrate_finding,
    validate_instance,
    write_validated_json,
)


SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "ERROR": 3,
    "MEDIUM": 2,
    "WARNING": 2,
    "LOW": 1,
    "INFO": 1,
    "UNKNOWN": 0,
}

SCANNER_NAMES = (
    "bandit",
    "brakeman",
    "checkov",
    "codeql-sarif",
    "eslint-security",
    "gitleaks",
    "gosec",
    "grype",
    "hadolint",
    "osv-scanner",
    "pip-audit",
    "semgrep",
    "spotbugs",
    "syft",
    "trivy",
    "trufflehog",
    "zap",
)
DEFAULT_REQUIRED_SCANNERS = frozenset(
    {"bandit", "semgrep", "pip-audit", "trivy", "gitleaks"}
)
REDACTED_VALUE = "[REDACTED]"
SENSITIVE_REPORT_KEY = re.compile(
    r"(?:secret|token|password|passwd|api[_-]?key|private[_-]?key|"
    r"authorization|credential|match|raw(?:v2)?)",
    re.IGNORECASE,
)


class ReportParseError(ValueError):
    """Raised when a scanner report does not match its expected root shape."""


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--target",
        default=".",
        help="Path that was scanned (recorded in findings.json for reference)",
    )
    parser.add_argument(
        "--reports-dir",
        default="reports",
        help="Directory containing raw scanner reports (default: reports)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Canonical scan-run output path "
            "(default: <reports-dir>/findings.json for compatibility)"
        ),
    )
    parser.add_argument(
        "--policy-output",
        default=None,
        help="Policy-result output path (default: beside output as policy-result.json)",
    )
    parser.add_argument(
        "--fail-on",
        default="high",
        choices=["critical", "high", "medium", "low", "none"],
        help='Minimum severity that fails the gate (default: high; "none" disables it)',
    )
    scanner_requirement = parser.add_mutually_exclusive_group()
    scanner_requirement.add_argument(
        "--required-scanner",
        action="append",
        default=None,
        help=(
            "Scanner required for a healthy gate. Repeat as needed; "
            "all configured scanners are required by default."
        ),
    )
    scanner_requirement.add_argument(
        "--optional-scanner",
        action="append",
        default=None,
        help=(
            "Scanner allowed to be absent or unhealthy without blocking. "
            "Repeat as needed."
        ),
    )
    parser.add_argument(
        "--scanner-failure-policy",
        choices=["fail", "warn", "ignore"],
        default="fail",
        help="How required scanner failures affect the gate (default: fail)",
    )
    parser.add_argument(
        "--severity-basis",
        choices=["normalised", "original"],
        default="normalised",
        help=(
            "Evaluate finding thresholds using canonical or scanner-native "
            "severity (default: normalised)"
        ),
    )
    parser.add_argument(
        "--require-execution-metadata",
        action="store_true",
        help="Fail required scanners when authoritative execution metadata is absent.",
    )
    parser.add_argument(
        "--redact-sensitive-content",
        action="store_true",
        help=(
            "Create redacted scanner-report views while retaining restricted "
            "original reports for audit."
        ),
    )
    parser.add_argument(
        "--enrich-threats",
        action="store_true",
        help="Enrich dependency findings with advisory metadata before gating.",
    )
    parser.add_argument(
        "--network-mode",
        choices=["disabled", "metadata-only", "full"],
        default="metadata-only",
        help=(
            "Threat-enrichment privacy mode (default: metadata-only; only used "
            "with --enrich-threats)."
        ),
    )
    parser.add_argument(
        "--threat-cache-dir",
        default=".trustgate/cache/threat-intelligence",
        help="Local threat-data cache (only used with --enrich-threats).",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aggregate per-tool scan reports into one findings feed and gate the build."
    )
    add_arguments(parser)
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _mapping_with_list(
    data: Any,
    key: str,
    scanner: str,
) -> tuple[dict[str, Any], list[Any]]:
    if not isinstance(data, dict):
        raise ReportParseError(f"{scanner} report root must be an object")
    values = data.get(key)
    if not isinstance(values, list):
        raise ReportParseError(f"{scanner} report field {key!r} must be a list")
    return data, values


def _canonical_findings(
    report_path: Path,
    legacy_findings: list[dict[str, Any]],
    *,
    category: str,
    scanner: str,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    audit_path, report_digest = _preserve_raw_report(report_path, scanner)
    redacted_path = (
        _create_redacted_report(report_path, scanner)
        if redact_sensitive_content
        else None
    )
    observed_at = datetime.now(timezone.utc)
    canonical: list[dict[str, Any]] = []
    for legacy in legacy_findings:
        finding_category = str(legacy.pop("_category", category))
        normalisation_records = legacy.pop("_normalisation_records", [])
        severity_override = legacy.pop("_normalised_severity_override", None)
        severity_reason_override = legacy.pop("_severity_reason_override", None)
        if redacted_path is not None:
            legacy.setdefault("evidence", []).append(
                {
                    "kind": "redacted_report",
                    "summary": (
                        "Sensitive scanner-report fields replaced with "
                        f"{REDACTED_VALUE}."
                    ),
                    "reference": str(redacted_path),
                    "excerpt": None,
                }
            )
        scanner_finding_id = legacy.get("scanner_finding_id") or legacy.get("rule_id")
        canonical.append(
            migrate_finding(
                legacy,
                observed_at=observed_at,
                category=finding_category,
                raw_report_reference={
                    "path": str(audit_path),
                    "sha256": report_digest,
                    "scanner_finding_id": (
                        str(scanner_finding_id)
                        if scanner_finding_id is not None
                        else None
                    ),
                },
                normalisation_records=normalisation_records,
                normalised_severity_override=severity_override,
                severity_reason_override=severity_reason_override,
                repository_root=repository_root,
            )
        )
    return canonical


def _write_content_addressed_report(
    *,
    directory: Path,
    scanner: str,
    suffix: str,
    report_bytes: bytes,
) -> tuple[Path, str]:
    report_digest = hashlib.sha256(report_bytes).hexdigest()
    scanner_slug = re.sub(r"[^a-z0-9]+", "-", scanner.lower()).strip("-")
    if directory.is_symlink():
        raise ReportParseError(
            f"report archive directory must not be a symbolic link: {directory}"
        )
    directory.mkdir(parents=True, exist_ok=True)
    archive_path = directory / f"{scanner_slug}-{report_digest}{suffix}"
    if archive_path.is_symlink():
        raise ReportParseError(
            f"archived report must not be a symbolic link: {archive_path}"
        )
    if archive_path.exists():
        if archive_path.read_bytes() != report_bytes:
            raise ReportParseError(
                "content-addressed report does not match its digest: "
                f"{archive_path}"
            )
        return archive_path, report_digest

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=directory,
            prefix=f".{scanner_slug}-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            handle.write(report_bytes)
            handle.flush()
            os.fsync(handle.fileno())
            temporary_path = Path(handle.name)
        os.chmod(temporary_path, 0o444)
        temporary_path.replace(archive_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
    return archive_path, report_digest


def _preserve_raw_report(report_path: Path, scanner: str) -> tuple[Path, str]:
    """Copy scanner output into a content-addressed, append-only audit store."""

    report_bytes = report_path.read_bytes()
    report_digest = hashlib.sha256(report_bytes).hexdigest()
    if report_path.parent.name == "raw" and report_digest in report_path.name:
        return report_path, report_digest
    return _write_content_addressed_report(
        directory=report_path.parent / "raw",
        scanner=scanner,
        suffix=report_path.suffix if report_path.suffix else ".bin",
        report_bytes=report_bytes,
    )


def _redact_report_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): (
                REDACTED_VALUE
                if SENSITIVE_REPORT_KEY.search(str(key))
                else _redact_report_value(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_report_value(item) for item in value]
    return value


def _create_redacted_report(report_path: Path, scanner: str) -> Path:
    suffix = report_path.suffix.lower()
    if suffix == ".xml":
        try:
            root = ElementTree.parse(report_path).getroot()
        except ElementTree.ParseError as error:
            raise ReportParseError(
                f"cannot redact malformed XML report: {error}"
            ) from error
        for element in root.iter():
            if SENSITIVE_REPORT_KEY.search(element.tag):
                element.text = REDACTED_VALUE
            for attribute in tuple(element.attrib):
                if SENSITIVE_REPORT_KEY.search(attribute):
                    element.attrib[attribute] = REDACTED_VALUE
        redacted_bytes = ElementTree.tostring(
            root,
            encoding="utf-8",
            xml_declaration=True,
        )
        published_suffix = ".xml"
    else:
        if suffix in {".jsonl", ".ndjson"}:
            document = []
            with report_path.open(encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    try:
                        document.append(json.loads(line))
                    except json.JSONDecodeError as error:
                        raise ReportParseError(
                            f"cannot redact malformed JSON line {line_number}: "
                            f"{error}"
                        ) from error
        else:
            document = _load_json(report_path)
        redacted_bytes = (
            json.dumps(
                _redact_report_value(document),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        published_suffix = ".json"
    redacted_path, _ = _write_content_addressed_report(
        directory=report_path.parent / "redacted",
        scanner=scanner,
        suffix=published_suffix,
        report_bytes=redacted_bytes,
    )
    return redacted_path


def _normalisation_record(
    canonical_field: str,
    source: str,
    original: Any,
    transformation: str = "copied scanner value without alteration",
) -> dict[str, Any]:
    return {
        "canonical_field": canonical_field,
        "source": source,
        "original": original,
        "transformation": transformation,
    }


def _trivy_cvss(
    value: Any,
    *,
    source_path: str,
    provider: str = "Trivy",
) -> tuple[list[dict[str, Any]], tuple[float, int, str] | None]:
    if not isinstance(value, dict):
        return [], None

    evidence: list[dict[str, Any]] = []
    candidates: list[tuple[float, int, str]] = []
    for source, metrics in value.items():
        if not isinstance(metrics, dict):
            continue
        selected: tuple[float, int] | None = None
        for version in (4, 3, 2):
            raw_score = metrics.get(f"V{version}Score")
            if isinstance(raw_score, bool):
                continue
            try:
                score = float(raw_score)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(score) or not 0 <= score <= 10:
                continue
            selected = (score, version)
            break
        if selected is None:
            continue
        score, version = selected
        source_name = str(source)
        candidates.append((score, version, source_name))
        evidence.append(
            {
                "kind": "cvss",
                "summary": (
                    f"{provider} {source_name} CVSS v{version} base score {score:g}."
                ),
                "reference": f"{source_path}.{source_name}",
                "excerpt": json.dumps(
                    metrics,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            }
        )

    if not candidates:
        return evidence, None
    score, version, source = max(
        candidates,
        key=lambda candidate: (candidate[0], candidate[1], candidate[2]),
    )
    return evidence, (score, version, source)


def _advisory_cvss(
    vulnerability: dict[str, Any],
    *,
    source_path: str,
) -> tuple[list[dict[str, Any]], tuple[float, int, str] | None]:
    structured_key = (
        "CVSS"
        if "CVSS" in vulnerability
        else "cvss"
        if "cvss" in vulnerability
        else None
    )
    structured = (
        vulnerability.get(structured_key)
        if structured_key is not None
        else None
    )
    if isinstance(structured, dict):
        return _trivy_cvss(
            structured,
            source_path=f"{source_path}.{structured_key}",
            provider="pip-audit enriched advisory",
        )

    raw_score = vulnerability.get("cvss_score")
    if isinstance(raw_score, bool):
        return [], None
    try:
        score = float(raw_score)
    except (TypeError, ValueError):
        return [], None
    if not math.isfinite(score) or not 0 <= score <= 10:
        return [], None
    version_value = vulnerability.get("cvss_version", 3)
    try:
        version = int(version_value)
    except (TypeError, ValueError):
        version = 3
    if version not in {2, 3, 4}:
        version = 3
    source = str(vulnerability.get("severity_source") or "advisory")
    evidence = [
        {
            "kind": "cvss",
            "summary": (
                f"pip-audit enriched {source} CVSS v{version} "
                f"base score {score:g}."
            ),
            "reference": f"{source_path}.cvss_score",
            "excerpt": str(raw_score),
        }
    ]
    return evidence, (score, version, source)


def _secret_validation_status(leak: dict[str, Any]) -> bool | None:
    for key in ("Verified", "Validated"):
        if isinstance(leak.get(key), bool):
            return bool(leak[key])
    status = leak.get("VerificationStatus")
    if isinstance(status, str):
        normalised = status.strip().lower()
        if normalised in {"verified", "validated", "confirmed", "true"}:
            return True
        if normalised in {"unverified", "invalid", "false"}:
            return False
    return None


def _advisory_identifiers(
    primary: Any,
    aliases: Any = None,
) -> tuple[list[str], list[str], list[str]]:
    values: list[Any] = [primary]
    if isinstance(aliases, list):
        values.extend(aliases)
    elif aliases is not None:
        values.append(aliases)
    identifiers = list(
        dict.fromkeys(str(value) for value in values if value)
    )
    cve = [identifier for identifier in identifiers if identifier.startswith("CVE-")]
    ghsa = [
        identifier for identifier in identifiers if identifier.startswith("GHSA-")
    ]
    osv = [
        identifier
        for identifier in identifiers
        if not identifier.startswith(("CVE-", "GHSA-"))
    ]
    return cve, ghsa, osv


def _repository_context() -> tuple[str | None, str | None, str | None, str]:
    repository = os.environ.get("GITHUB_REPOSITORY") or None
    ref = os.environ.get("GITHUB_REF") or None
    candidate_commit = os.environ.get("GITHUB_SHA") or ""
    commit = (
        candidate_commit
        if re.fullmatch(r"[0-9a-fA-F]{7,64}", candidate_commit)
        else None
    )
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return repository, ref, commit, "local"
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    trigger = {
        "push": "push",
        "pull_request": "pull_request",
        "pull_request_target": "pull_request",
        "schedule": "schedule",
        "workflow_dispatch": "manual",
        "repository_dispatch": "api",
    }.get(event, "unknown")
    return repository, ref, commit, trigger


def parse_bandit(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    _, results = _mapping_with_list(_load_json(report_path), "results", "Bandit")
    legacy_findings = []
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            continue
        cwe_id = (result.get("issue_cwe") or {}).get("id")
        severity = result.get("issue_severity")
        severity_source = f"$.results[{result_index}].issue_severity"
        severity_decision = normalise_scanner_severity("bandit", severity)
        legacy_findings.append(
            {
                "tool": "Bandit",
                "rule_id": result.get("test_id"),
                "severity": severity,
                "description": result.get("issue_text"),
                "file": result.get("filename"),
                "line": result.get("line_number"),
                "cwe": [f"CWE-{cwe_id}"] if cwe_id else [],
                "evidence": [
                    severity_quality_evidence(
                        severity_decision,
                        reference=severity_source,
                    )
                ],
                "_normalised_severity_override": severity_decision.normalised,
                "_severity_reason_override": severity_decision.reason,
                "_normalisation_records": [
                    _normalisation_record(
                        "rule_id",
                        f"$.results[{result_index}].test_id",
                        result.get("test_id"),
                    ),
                    _normalisation_record(
                        "title",
                        f"$.results[{result_index}].issue_text",
                        result.get("issue_text"),
                        "used scanner description as canonical title",
                    ),
                    _normalisation_record(
                        "description",
                        f"$.results[{result_index}].issue_text",
                        result.get("issue_text"),
                    ),
                    _normalisation_record(
                        "original_severity",
                        severity_source,
                        severity,
                    ),
                    _normalisation_record(
                        "normalised_severity",
                        severity_source,
                        severity,
                        "mapped scanner severity to Trust Gate severity",
                    ),
                    _normalisation_record(
                        "file",
                        f"$.results[{result_index}].filename",
                        result.get("filename"),
                    ),
                    _normalisation_record(
                        "start_line",
                        f"$.results[{result_index}].line_number",
                        result.get("line_number"),
                    ),
                    _normalisation_record(
                        "end_line",
                        f"$.results[{result_index}].line_number",
                        result.get("line_number"),
                    ),
                    *(
                        [
                            _normalisation_record(
                                "cwe",
                                f"$.results[{result_index}].issue_cwe.id",
                                cwe_id,
                                "prefixed numeric CWE identifier",
                            )
                        ]
                        if cwe_id
                        else []
                    ),
                ],
            }
        )
    return _canonical_findings(
        report_path,
        legacy_findings,
        category="sast",
        scanner="bandit",
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_semgrep(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    _, results = _mapping_with_list(_load_json(report_path), "results", "Semgrep")
    legacy_findings = []
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        metadata = (
            extra.get("metadata")
            if isinstance(extra.get("metadata"), dict)
            else {}
        )
        severity = extra.get("severity")
        severity_source = f"$.results[{result_index}].extra.severity"
        severity_decision = normalise_scanner_severity("semgrep", severity)
        legacy_findings.append(
            {
                "tool": "Semgrep",
                "rule_id": result.get("check_id"),
                "severity": severity,
                "description": extra.get("message", ""),
                "file": result.get("path"),
                "start_line": (result.get("start") or {}).get("line"),
                "end_line": (result.get("end") or {}).get("line"),
                "cwe": metadata.get("cwe"),
                "evidence": [
                    severity_quality_evidence(
                        severity_decision,
                        reference=severity_source,
                    )
                ],
                "_normalised_severity_override": severity_decision.normalised,
                "_severity_reason_override": severity_decision.reason,
                "_normalisation_records": [
                    _normalisation_record(
                        "rule_id",
                        f"$.results[{result_index}].check_id",
                        result.get("check_id"),
                    ),
                    _normalisation_record(
                        "title",
                        f"$.results[{result_index}].extra.message",
                        extra.get("message", ""),
                        "used scanner description as canonical title",
                    ),
                    _normalisation_record(
                        "description",
                        f"$.results[{result_index}].extra.message",
                        extra.get("message", ""),
                    ),
                    _normalisation_record(
                        "original_severity",
                        severity_source,
                        severity,
                    ),
                    _normalisation_record(
                        "normalised_severity",
                        severity_source,
                        severity,
                        "mapped scanner severity to Trust Gate severity",
                    ),
                    _normalisation_record(
                        "file",
                        f"$.results[{result_index}].path",
                        result.get("path"),
                    ),
                    _normalisation_record(
                        "start_line",
                        f"$.results[{result_index}].start.line",
                        (result.get("start") or {}).get("line"),
                    ),
                    _normalisation_record(
                        "end_line",
                        f"$.results[{result_index}].end.line",
                        (result.get("end") or {}).get("line"),
                    ),
                    _normalisation_record(
                        "cwe",
                        f"$.results[{result_index}].extra.metadata.cwe",
                        metadata.get("cwe"),
                        "converted scanner identifier value to canonical list",
                    ),
                ],
            }
        )
    return _canonical_findings(
        report_path,
        legacy_findings,
        category="sast",
        scanner="semgrep",
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_pip_audit(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    _, dependencies = _mapping_with_list(
        _load_json(report_path), "dependencies", "pip-audit"
    )
    legacy_findings = []
    for dependency_index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict):
            continue
        for vulnerability_index, vulnerability in enumerate(
            dependency.get("vulns", [])
        ):
            if not isinstance(vulnerability, dict):
                continue
            vulnerability_id = vulnerability.get("id")
            cve, ghsa, osv = _advisory_identifiers(
                vulnerability_id,
                vulnerability.get("aliases"),
            )
            severity = vulnerability.get("severity")
            vulnerability_path = (
                f"$.dependencies[{dependency_index}].vulns[{vulnerability_index}]"
            )
            severity_source = f"{vulnerability_path}.severity"
            scanner_severity_decision = normalise_scanner_severity(
                "pip-audit",
                severity,
            )
            cvss_evidence, cvss_fallback = _advisory_cvss(
                vulnerability,
                source_path=vulnerability_path,
            )
            use_cvss_fallback = (
                cvss_fallback is not None
                and (
                    severity is None
                    or str(severity).strip().upper() == "UNKNOWN"
                )
            )
            severity_decision = (
                cvss_severity_decision(
                    "pip-audit",
                    severity,
                    score=cvss_fallback[0],
                    version=cvss_fallback[1],
                    source=cvss_fallback[2],
                )
                if use_cvss_fallback and cvss_fallback is not None
                else scanner_severity_decision
            )
            legacy_findings.append(
                {
                    "tool": "pip-audit",
                    "rule_id": vulnerability_id,
                    "severity": severity,
                    "description": vulnerability.get("description", ""),
                    "file": dependency.get("name"),
                    "line": None,
                    "cve": cve,
                    "ghsa": ghsa,
                    "osv": osv,
                    "dependency": {
                        "name": dependency.get("name"),
                        "version": dependency.get("version"),
                        "ecosystem": "PyPI",
                        "purl": (
                            f"pkg:pypi/{dependency.get('name')}@"
                            f"{dependency.get('version')}"
                            if dependency.get("name") and dependency.get("version")
                            else None
                        ),
                        "direct": None,
                    },
                    "dependency_scope": "unknown",
                    "evidence": [
                        *cvss_evidence,
                        severity_quality_evidence(
                            severity_decision,
                            reference=(
                                str(cvss_evidence[0]["reference"])
                                if use_cvss_fallback and cvss_evidence
                                else severity_source
                            ),
                        )
                    ],
                    "_normalised_severity_override": severity_decision.normalised,
                    "_severity_reason_override": severity_decision.reason,
                    "_normalisation_records": [
                        _normalisation_record(
                            "rule_id",
                            f"{vulnerability_path}.id",
                            vulnerability_id,
                        ),
                        _normalisation_record(
                            "title",
                            f"{vulnerability_path}.description",
                            vulnerability.get("description", ""),
                            "used scanner description as canonical title",
                        ),
                        _normalisation_record(
                            "description",
                            f"{vulnerability_path}.description",
                            vulnerability.get("description", ""),
                        ),
                        _normalisation_record(
                            "original_severity",
                            severity_source,
                            severity,
                        ),
                        _normalisation_record(
                            "normalised_severity",
                            severity_source,
                            severity,
                            (
                                "mapped missing or scanner severity to "
                                "Trust Gate severity"
                            ),
                        ),
                        _normalisation_record(
                            "file",
                            f"$.dependencies[{dependency_index}].name",
                            dependency.get("name"),
                        ),
                        _normalisation_record(
                            "cve",
                            f"{vulnerability_path}.id",
                            vulnerability_id,
                            "classified advisory identifiers by namespace",
                        ),
                        _normalisation_record(
                            "ghsa",
                            f"{vulnerability_path}.aliases",
                            vulnerability.get("aliases"),
                            "classified advisory aliases by namespace",
                        ),
                        _normalisation_record(
                            "osv",
                            f"{vulnerability_path}.aliases",
                            vulnerability.get("aliases"),
                            "classified advisory aliases by namespace",
                        ),
                        _normalisation_record(
                            "dependency",
                            f"$.dependencies[{dependency_index}]",
                            dependency,
                            "assembled canonical dependency identity",
                        ),
                    ],
                }
            )
    return _canonical_findings(
        report_path,
        legacy_findings,
        category="sca",
        scanner="pip-audit",
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_trivy(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    report = _load_json(report_path)
    if (
        isinstance(report, dict)
        and "Results" not in report
        and report.get("SchemaVersion") == 2
        and isinstance(report.get("Trivy"), dict)
        and isinstance(report["Trivy"].get("Version"), str)
        and isinstance(report.get("ArtifactName"), str)
        and isinstance(report.get("ArtifactType"), str)
    ):
        results: list[Any] = []
    else:
        _, results = _mapping_with_list(report, "Results", "Trivy")
    legacy_findings = []
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            continue
        for vulnerability_index, vulnerability in enumerate(
            result.get("Vulnerabilities", [])
        ):
            if not isinstance(vulnerability, dict):
                continue
            vulnerability_id = vulnerability.get("VulnerabilityID")
            cve, ghsa, osv = _advisory_identifiers(vulnerability_id)
            vulnerability_path = (
                f"$.Results[{result_index}].Vulnerabilities[{vulnerability_index}]"
            )
            severity = vulnerability.get("Severity")
            cvss_evidence, cvss_fallback = _trivy_cvss(
                vulnerability.get("CVSS"),
                source_path=f"{vulnerability_path}.CVSS",
            )
            use_cvss_fallback = (
                cvss_fallback is not None
                and (
                    severity is None
                    or str(severity).strip().upper() == "UNKNOWN"
                )
            )
            scanner_severity_decision = normalise_scanner_severity(
                "trivy",
                severity,
            )
            severity_decision = (
                cvss_severity_decision(
                    "Trivy",
                    severity,
                    score=cvss_fallback[0],
                    version=cvss_fallback[1],
                    source=cvss_fallback[2],
                )
                if use_cvss_fallback and cvss_fallback is not None
                else scanner_severity_decision
            )
            severity_source = f"{vulnerability_path}.Severity"
            legacy_findings.append(
                {
                    "tool": "Trivy",
                    "rule_id": vulnerability_id,
                    "severity": severity,
                    "title": vulnerability.get("Title"),
                    "description": vulnerability.get("Description", ""),
                    "file": result.get("Target", ""),
                    "line": None,
                    "cve": cve,
                    "ghsa": ghsa,
                    "osv": osv,
                    "dependency": {
                        "name": vulnerability.get("PkgName") or result.get("Target"),
                        "version": vulnerability.get("InstalledVersion"),
                        "ecosystem": result.get("Type"),
                        "purl": vulnerability.get("PkgIdentifier", {}).get("PURL"),
                        "direct": None,
                    },
                    "dependency_scope": "unknown",
                    "evidence": [
                        *cvss_evidence,
                        severity_quality_evidence(
                            severity_decision,
                            reference=(
                                f"{vulnerability_path}.CVSS"
                                if use_cvss_fallback
                                else severity_source
                            ),
                        ),
                    ],
                    "_category": "sca",
                    "_normalised_severity_override": severity_decision.normalised,
                    "_severity_reason_override": severity_decision.reason,
                    "_normalisation_records": [
                        _normalisation_record(
                            "rule_id",
                            f"{vulnerability_path}.VulnerabilityID",
                            vulnerability_id,
                        ),
                        _normalisation_record(
                            "title",
                            f"{vulnerability_path}.Title",
                            vulnerability.get("Title"),
                        ),
                        _normalisation_record(
                            "description",
                            f"{vulnerability_path}.Description",
                            vulnerability.get("Description", ""),
                        ),
                        _normalisation_record(
                            "original_severity",
                            severity_source,
                            severity,
                        ),
                        _normalisation_record(
                            "normalised_severity",
                            severity_source,
                            severity,
                            "mapped scanner severity to Trust Gate severity",
                        ),
                        _normalisation_record(
                            "file",
                            f"$.Results[{result_index}].Target",
                            result.get("Target", ""),
                        ),
                        _normalisation_record(
                            "cve",
                            f"{vulnerability_path}.VulnerabilityID",
                            vulnerability_id,
                            "classified advisory identifier by namespace",
                        ),
                        _normalisation_record(
                            "ghsa",
                            f"{vulnerability_path}.VulnerabilityID",
                            vulnerability_id,
                            "classified advisory identifier by namespace",
                        ),
                        _normalisation_record(
                            "osv",
                            f"{vulnerability_path}.VulnerabilityID",
                            vulnerability_id,
                            "classified advisory identifier by namespace",
                        ),
                        _normalisation_record(
                            "dependency",
                            vulnerability_path,
                            vulnerability,
                            "assembled canonical dependency identity",
                        ),
                    ],
                }
            )
        for misconfiguration_index, misconfiguration in enumerate(
            result.get("Misconfigurations", [])
        ):
            if not isinstance(misconfiguration, dict):
                continue
            severity = misconfiguration.get("Severity")
            misconfiguration_path = (
                f"$.Results[{result_index}].Misconfigurations"
                f"[{misconfiguration_index}]"
            )
            severity_source = f"{misconfiguration_path}.Severity"
            severity_decision = normalise_scanner_severity("trivy", severity)
            legacy_findings.append(
                {
                    "tool": "Trivy",
                    "rule_id": misconfiguration.get("ID"),
                    "severity": severity,
                    "title": misconfiguration.get("Title"),
                    "description": misconfiguration.get("Description", ""),
                    "file": result.get("Target", ""),
                    "line": None,
                    "evidence": [
                        severity_quality_evidence(
                            severity_decision,
                            reference=severity_source,
                        )
                    ],
                    "_category": "iac",
                    "_normalised_severity_override": severity_decision.normalised,
                    "_severity_reason_override": severity_decision.reason,
                    "_normalisation_records": [
                        _normalisation_record(
                            "rule_id",
                            f"{misconfiguration_path}.ID",
                            misconfiguration.get("ID"),
                        ),
                        _normalisation_record(
                            "title",
                            f"{misconfiguration_path}.Title",
                            misconfiguration.get("Title"),
                        ),
                        _normalisation_record(
                            "description",
                            f"{misconfiguration_path}.Description",
                            misconfiguration.get("Description", ""),
                        ),
                        _normalisation_record(
                            "original_severity",
                            severity_source,
                            severity,
                        ),
                        _normalisation_record(
                            "normalised_severity",
                            severity_source,
                            severity,
                            "mapped scanner severity to Trust Gate severity",
                        ),
                        _normalisation_record(
                            "file",
                            f"$.Results[{result_index}].Target",
                            result.get("Target", ""),
                        ),
                    ],
                }
            )
    return _canonical_findings(
        report_path,
        legacy_findings,
        category="container",
        scanner="trivy",
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_gitleaks(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    leaks = _load_json(report_path)
    if not isinstance(leaks, list):
        raise ReportParseError("Gitleaks report root must be a list")
    legacy_findings = []
    for leak_index, leak in enumerate(leaks):
        if not isinstance(leak, dict):
            continue
        severity = leak.get("Severity")
        severity_source = f"$[{leak_index}].Severity"
        severity_decision = secret_severity_decision(
            leak.get("RuleID", "secret"),
            severity,
            verified=_secret_validation_status(leak),
        )
        legacy_findings.append(
            {
                "tool": "Gitleaks",
                "rule_id": leak.get("RuleID", "secret"),
                "severity": severity,
                "description": leak.get("Description", "Secret detected"),
                "file": leak.get("File", ""),
                "line": leak.get("StartLine"),
                "scanner_finding_id": leak.get("Fingerprint"),
                "evidence": [
                    severity_quality_evidence(
                        severity_decision,
                        reference=severity_source,
                    )
                ],
                "_normalised_severity_override": severity_decision.normalised,
                "_severity_reason_override": severity_decision.reason,
                "_normalisation_records": [
                    _normalisation_record(
                        "rule_id",
                        f"$[{leak_index}].RuleID",
                        leak.get("RuleID", "secret"),
                    ),
                    _normalisation_record(
                        "title",
                        f"$[{leak_index}].Description",
                        leak.get("Description", "Secret detected"),
                        "used scanner description as canonical title",
                    ),
                    _normalisation_record(
                        "description",
                        f"$[{leak_index}].Description",
                        leak.get("Description", "Secret detected"),
                    ),
                    _normalisation_record(
                        "original_severity",
                        severity_source,
                        severity,
                    ),
                    _normalisation_record(
                        "normalised_severity",
                        severity_source,
                        severity,
                        (
                            "mapped missing or scanner severity to "
                            "Trust Gate severity"
                        ),
                    ),
                    _normalisation_record(
                        "file",
                        f"$[{leak_index}].File",
                        leak.get("File", ""),
                    ),
                    _normalisation_record(
                        "start_line",
                        f"$[{leak_index}].StartLine",
                        leak.get("StartLine"),
                    ),
                    _normalisation_record(
                        "end_line",
                        f"$[{leak_index}].StartLine",
                        leak.get("StartLine"),
                    ),
                ],
            }
        )
    return _canonical_findings(
        report_path,
        legacy_findings,
        category="secrets",
        scanner="gitleaks",
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def _parse_scanner_report(
    *,
    scanner: str,
    report_path: Path,
    metadata_path: Path,
    parser: Any,
    required: bool,
    require_execution_metadata: bool,
    redact_sensitive_content: bool,
    repository_root: str | os.PathLike[str] | None,
) -> tuple[list[dict[str, Any]], ScannerResult]:
    observed_at = datetime.now(timezone.utc)
    report_produced = report_path.is_file()
    execution_result: ScannerResult | None = None
    metadata_error: str | None = None

    if metadata_path.is_file():
        try:
            metadata = _load_json(metadata_path)
            if not isinstance(metadata, dict):
                raise ValueError("execution metadata root must be an object")
            execution_result = ScannerResult.from_dict(metadata)
            if execution_result.scanner != scanner:
                raise ValueError(
                    f"execution metadata is for {execution_result.scanner!r}, "
                    f"expected {scanner!r}"
                )
        except (OSError, KeyError, TypeError, ValueError) as error:
            metadata_error = (
                f"Invalid execution metadata: {type(error).__name__}: {error}"
            )
    elif require_execution_metadata:
        metadata_error = "Required scanner execution metadata was not produced."

    if execution_result is None:
        base_state = (
            ScannerState.FAILED_SCANNER
            if required and metadata_error
            else ScannerState.PARTIAL
            if metadata_error
            else ScannerState.CLEAN
        )
        execution_result = ScannerResult(
            scanner=scanner,
            state=base_state,
            started_at=observed_at,
            ended_at=datetime.now(timezone.utc),
            exit_code=None,
            timed_out=False,
            report_path=str(report_path),
            report_produced=report_produced,
            parser_status=ParserStatus.NOT_RUN,
            error=metadata_error,
            required=required,
        )
    else:
        execution_result = replace(
            execution_result,
            report_path=str(report_path),
            report_produced=report_produced,
            required=required,
        )

    if not report_produced:
        state = ScannerState.FAILED_SCANNER if required else ScannerState.SKIPPED
        errors = [
            error
            for error in (
                execution_result.error,
                "Expected scanner report was not produced.",
            )
            if error
        ]
        return [], replace(
            execution_result,
            state=state,
            parser_status=ParserStatus.NOT_RUN,
            finding_count=0,
            error=" ".join(errors),
        )

    try:
        audit_path, _ = _preserve_raw_report(report_path, scanner)
        published_report_path = (
            _create_redacted_report(report_path, scanner)
            if redact_sensitive_content
            else audit_path
        )
        execution_result = replace(
            execution_result,
            report_path=str(published_report_path),
        )
        findings = parser(
            report_path,
            redact_sensitive_content=redact_sensitive_content,
            repository_root=repository_root,
        )
        validated_findings = []
        for finding in findings:
            finding = dict(finding)
            finding["scanner_version"] = execution_result.version
            validate_instance("finding", finding)
            validated_findings.append(finding)
        findings = validated_findings
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        state = ScannerState.FAILED_SCANNER if required else ScannerState.PARTIAL
        errors = [
            message
            for message in (
                execution_result.error,
                f"{type(error).__name__}: {error}",
            )
            if message
        ]
        return [], replace(
            execution_result,
            state=state,
            report_produced=True,
            parser_status=ParserStatus.FAILED,
            finding_count=0,
            error=" ".join(errors),
        )

    if execution_result.state in {
        ScannerState.FAILED_SCANNER,
        ScannerState.PARTIAL,
    }:
        state = (
            ScannerState.FAILED_SCANNER
            if required
            else ScannerState.PARTIAL
        )
    else:
        state = ScannerState.FINDINGS if findings else execution_result.state
        if state is ScannerState.SKIPPED:
            state = ScannerState.FINDINGS if findings else ScannerState.CLEAN

    return findings, replace(
        execution_result,
        state=state,
        parser_status=ParserStatus.SUCCESS,
        finding_count=len(findings),
    )


def run(args: argparse.Namespace) -> int:
    from trustgate.adapters import AdapterConfig, AdapterContext, RepositoryContext
    from trustgate.adapters.builtin.catalog import builtin_registry

    reports_dir = Path(args.reports_dir)
    output_argument = args.output
    output_path = Path(output_argument) if output_argument else reports_dir / "findings.json"
    output_is_directory = (
        bool(output_argument and output_argument.endswith(os.sep))
        or output_path.exists()
        and output_path.is_dir()
    )
    if output_is_directory:
        output_path /= "findings.json"
    policy_output_path = (
        Path(args.policy_output)
        if args.policy_output
        else output_path.with_name("policy-result.json")
    )
    if output_path.resolve() == policy_output_path.resolve():
        raise ValueError("scan-run output and policy output must be different files")

    registry = builtin_registry(discover_plugins=True)
    requested = set(args.required_scanner or ()) | set(args.optional_scanner or ())
    unknown = requested - set(registry.names())
    if unknown:
        raise ValueError(
            "unknown scanner adapter(s): " + ", ".join(sorted(unknown))
        )
    if args.required_scanner:
        required_scanners = set(args.required_scanner)
    else:
        required_scanners = set(DEFAULT_REQUIRED_SCANNERS) - set(
            args.optional_scanner or ()
        )

    target_path = Path(args.target)
    repository_path = target_path if target_path.is_dir() else Path.cwd()
    repository_context = RepositoryContext.from_path(repository_path)
    scanner_specs = []
    for scanner in registry.names():
        adapter = registry.get(scanner)
        report_filename = getattr(
            adapter,
            "native_report_filename",
            f"{scanner}_report.{adapter.metadata().report_format}",
        )
        report_path = reports_dir / report_filename
        explicitly_selected = scanner in requested
        is_compatibility_default = scanner in DEFAULT_REQUIRED_SCANNERS
        if not (
            report_path.is_file()
            or explicitly_selected
            or is_compatibility_default
        ):
            continue
        context = AdapterContext.create(
            repository=repository_context,
            reports_dir=reports_dir,
            config=AdapterConfig(
                required=scanner in required_scanners,
                options={
                    "redact_sensitive_content": args.redact_sensitive_content
                },
            ),
            metadata=adapter.metadata(),
        )

        def adapter_parser(
            path: Path,
            *,
            redact_sensitive_content: bool = False,
            repository_root: str | os.PathLike[str] | None = None,
            _adapter: Any = adapter,
            _context: Any = context,
        ) -> list[dict[str, Any]]:
            return list(_adapter.parse(Path(path), _context))

        scanner_specs.append(
            (
                scanner,
                report_path,
                reports_dir / f"{scanner}_execution.json",
                adapter_parser,
            )
        )
    findings: list[dict[str, Any]] = []
    scanner_results: list[ScannerResult] = []
    for scanner, report_path, metadata_path, parser in scanner_specs:
        scanner_findings, scanner_result = _parse_scanner_report(
            scanner=scanner,
            report_path=report_path,
            metadata_path=metadata_path,
            parser=parser,
            required=scanner in required_scanners,
            require_execution_metadata=args.require_execution_metadata,
            redact_sensitive_content=args.redact_sensitive_content,
            repository_root=Path.cwd(),
        )
        findings.extend(scanner_findings)
        scanner_results.append(scanner_result)

    repository, ref, commit, trigger = _repository_context()
    scan_run = build_scan_run(
        target=args.target,
        findings=findings,
        scanner_results=scanner_results,
        repository=repository,
        ref=ref,
        commit=commit,
        trigger=trigger,
    )
    if args.enrich_threats:
        from trustgate.threat_intelligence import (
            EnrichmentConfig,
            NetworkMode,
            enrich_scan_run,
        )

        scan_run = enrich_scan_run(
            scan_run,
            config=EnrichmentConfig(
                cache_dir=Path(args.threat_cache_dir),
                network_mode=NetworkMode(args.network_mode),
                github_token=os.environ.get("GITHUB_TOKEN"),
                nvd_api_key=os.environ.get("NVD_API_KEY"),
            ),
        )
    policy_result = build_policy_result(
        scan_run,
        fail_on=args.fail_on,
        scanner_failure_policy=args.scanner_failure_policy,
        severity_basis=args.severity_basis,
    )

    # Both documents are fully validated before either path is published.
    validate_instance("scan-run", scan_run)
    validate_instance("policy-result", policy_result)
    write_validated_json(output_path, scan_run, schema_name="scan-run")
    write_validated_json(
        policy_output_path,
        policy_result,
        schema_name="policy-result",
    )

    print(f"Aggregated {len(findings)} total findings.")
    required_failures = [
        result for result in scanner_results if result.required and not result.healthy
    ]
    optional_failures = [
        result
        for result in scanner_results
        if not result.required and result.state is ScannerState.PARTIAL
    ]
    for result in required_failures + optional_failures:
        print(f"Scanner health: {result.scanner} is {result.state.value}: {result.error}")

    exit_code = int(policy_result["metadata"]["exit_code"])
    if exit_code == 2:
        print(
            "SECURITY GATE FAILED: required scanner failure "
            f"({', '.join(result.scanner for result in required_failures)})."
        )
        return 2
    if required_failures and args.scanner_failure_policy == "warn":
        print("WARNING: continuing despite required scanner failure policy.")

    if args.fail_on == "none" and exit_code == 0:
        print("Security gate disabled (--fail-on none).")
        return 0

    matched_ids = set(policy_result["matched_finding_ids"])
    gating_findings = [
        finding
        for finding in findings
        if finding["finding_id"] in matched_ids
    ]

    if exit_code == 1:
        print(
            "SECURITY GATE FAILED: "
            f"{len(gating_findings)} finding(s) at or above '{args.fail_on}' severity."
        )
        for finding in gating_findings:
            print(
                f"  [{finding['scanner']}] {finding['rule_id']} - "
                f"{finding['description']} "
                f"({finding['file']} line {finding['start_line']})"
            )
        return 1

    print("Security gate passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(parse_args(argv))


__all__ = [
    "SEVERITY_RANK",
    "add_arguments",
    "build_parser",
    "main",
    "parse_args",
    "parse_bandit",
    "parse_gitleaks",
    "parse_pip_audit",
    "parse_semgrep",
    "parse_trivy",
    "run",
]
