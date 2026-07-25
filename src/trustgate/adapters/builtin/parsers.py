"""Native report parsers for built-in Phase 4 adapters."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import re
from typing import Any, Iterable
import xml.etree.ElementTree as ElementTree

from trustgate.severity import (
    normalise_scanner_severity,
    severity_quality_evidence,
)

from .legacy import (
    ReportParseError,
    _advisory_identifiers,
    _canonical_findings,
    _normalisation_record,
)


def _json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _object(value: Any, scanner: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReportParseError(f"{scanner} report root must be an object")
    return value


def _list(value: Any, scanner: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReportParseError(f"{scanner} report root must be a list")
    return value


def _cwe(value: Any) -> list[str]:
    values = value if isinstance(value, list) else [value]
    result: set[str] = set()
    for item in values:
        if item is None:
            continue
        text = str(item).strip()
        match = re.search(r"CWE[-: ]?([1-9][0-9]*)", text, re.IGNORECASE)
        if match is None:
            match = re.fullmatch(r"([1-9][0-9]*)", text)
        if match:
            result.add(f"CWE-{match.group(1)}")
    return sorted(result)


def _legacy_finding(
    *,
    scanner: str,
    category: str,
    rule_id: Any,
    severity: Any,
    title: Any,
    description: Any,
    file: Any,
    start_line: Any = None,
    end_line: Any = None,
    cwe: Any = None,
    cve: Iterable[str] = (),
    ghsa: Iterable[str] = (),
    osv: Iterable[str] = (),
    dependency: dict[str, Any] | None = None,
    scanner_finding_id: Any = None,
    source_reference: str = "$",
) -> dict[str, Any]:
    rule = str(rule_id or f"{scanner}-finding")
    heading = str(title or description or rule)
    detail = str(description or heading)
    severity_decision = normalise_scanner_severity(scanner, severity)
    finding: dict[str, Any] = {
        "tool": scanner,
        "rule_id": rule,
        "severity": severity,
        "title": heading,
        "description": detail,
        "file": str(file or ""),
        "start_line": start_line,
        "end_line": end_line if end_line is not None else start_line,
        "cwe": _cwe(cwe),
        "cve": list(cve),
        "ghsa": list(ghsa),
        "osv": list(osv),
        "scanner_finding_id": (
            str(scanner_finding_id) if scanner_finding_id is not None else None
        ),
        "evidence": [
            severity_quality_evidence(
                severity_decision,
                reference=f"{source_reference}.severity",
            )
        ],
        "_category": category,
        "_normalised_severity_override": severity_decision.normalised,
        "_severity_reason_override": severity_decision.reason,
        "_normalisation_records": [
            _normalisation_record("rule_id", source_reference, rule_id),
            _normalisation_record("title", source_reference, heading),
            _normalisation_record("description", source_reference, detail),
            _normalisation_record(
                "original_severity", source_reference, severity
            ),
            _normalisation_record(
                "normalised_severity",
                source_reference,
                severity,
                "mapped scanner severity to Trust Gate severity",
            ),
            _normalisation_record("file", source_reference, file),
            _normalisation_record("start_line", source_reference, start_line),
            _normalisation_record("end_line", source_reference, end_line),
        ],
    }
    if dependency is not None:
        finding["dependency"] = dependency
        finding["dependency_scope"] = "unknown"
    return finding


def _cvss_label(value: Any) -> Any:
    """Map a SARIF security-severity score while retaining non-numeric labels."""

    try:
        score = float(value)
    except (TypeError, ValueError):
        return value
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def _canonical(
    path: Path,
    scanner: str,
    category: str,
    findings: list[dict[str, Any]],
    *,
    redact_sensitive_content: bool,
    repository_root: str | os.PathLike[str] | None,
) -> list[dict[str, Any]]:
    return _canonical_findings(
        path,
        findings,
        category=category,
        scanner=scanner,
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_zap(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    document = _object(_json(report_path), "OWASP ZAP")
    sites = document.get("site", [])
    if not isinstance(sites, list):
        raise ReportParseError("OWASP ZAP report field 'site' must be a list")
    findings: list[dict[str, Any]] = []
    for site_index, site in enumerate(sites):
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            raise ReportParseError("OWASP ZAP alerts must be a list")
        for alert_index, alert in enumerate(alerts):
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances") or [{}]
            if not isinstance(instances, list):
                raise ReportParseError("OWASP ZAP instances must be a list")
            for instance_index, instance in enumerate(instances):
                if not isinstance(instance, dict):
                    continue
                reference = (
                    f"$.site[{site_index}].alerts[{alert_index}]"
                    f".instances[{instance_index}]"
                )
                findings.append(
                    _legacy_finding(
                        scanner="zap",
                        category="dast",
                        rule_id=alert.get("pluginid") or alert.get("alertRef"),
                        severity=(
                            str(alert.get("riskdesc", "")).split()[0]
                            or alert.get("riskcode")
                        ),
                        title=alert.get("alert") or alert.get("name"),
                        description=alert.get("desc") or alert.get("solution"),
                        file=instance.get("uri") or site.get("@name"),
                        cwe=alert.get("cweid"),
                        scanner_finding_id=(
                            f"{alert.get('pluginid')}:{instance.get('uri')}:"
                            f"{instance.get('method')}"
                        ),
                        source_reference=reference,
                    )
                )
    return _canonical(
        report_path,
        "zap",
        "dast",
        findings,
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_osv_scanner(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    document = _object(_json(report_path), "OSV-Scanner")
    results = document.get("results", [])
    if not isinstance(results, list):
        raise ReportParseError("OSV-Scanner report field 'results' must be a list")
    findings: list[dict[str, Any]] = []
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            continue
        source = result.get("source") if isinstance(result.get("source"), dict) else {}
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            raise ReportParseError("OSV-Scanner packages must be a list")
        for package_index, package_result in enumerate(packages):
            if not isinstance(package_result, dict):
                continue
            package = (
                package_result.get("package")
                if isinstance(package_result.get("package"), dict)
                else {}
            )
            vulnerabilities = package_result.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                raise ReportParseError("OSV-Scanner vulnerabilities must be a list")
            for vulnerability_index, vulnerability in enumerate(vulnerabilities):
                if not isinstance(vulnerability, dict):
                    continue
                identifier = vulnerability.get("id")
                aliases = vulnerability.get("aliases", [])
                cve, ghsa, osv = _advisory_identifiers(identifier, aliases)
                severity = vulnerability.get("database_specific", {})
                if isinstance(severity, dict):
                    severity = severity.get("severity")
                reference = (
                    f"$.results[{result_index}].packages[{package_index}]"
                    f".vulnerabilities[{vulnerability_index}]"
                )
                findings.append(
                    _legacy_finding(
                        scanner="osv-scanner",
                        category="sca",
                        rule_id=identifier,
                        severity=severity,
                        title=vulnerability.get("summary") or identifier,
                        description=(
                            vulnerability.get("details")
                            or vulnerability.get("summary")
                        ),
                        file=source.get("path"),
                        cve=cve,
                        ghsa=ghsa,
                        osv=osv,
                        dependency={
                            "name": package.get("name"),
                            "version": package_result.get("version"),
                            "ecosystem": package.get("ecosystem"),
                            "purl": None,
                            "direct": None,
                        },
                        source_reference=reference,
                    )
                )
    return _canonical(
        report_path,
        "osv-scanner",
        "sca",
        findings,
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_syft(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """Validate a Syft SBOM; packages are evidence inventory, not findings."""

    report_path = Path(path)
    document = _object(_json(report_path), "Syft")
    if not isinstance(document.get("artifacts"), list):
        raise ReportParseError("Syft report field 'artifacts' must be a list")
    return _canonical(
        report_path,
        "syft",
        "sbom",
        [],
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_grype(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    document = _object(_json(report_path), "Grype")
    matches = document.get("matches", [])
    if not isinstance(matches, list):
        raise ReportParseError("Grype report field 'matches' must be a list")
    findings: list[dict[str, Any]] = []
    for index, match in enumerate(matches):
        if not isinstance(match, dict):
            continue
        vulnerability = (
            match.get("vulnerability")
            if isinstance(match.get("vulnerability"), dict)
            else {}
        )
        artifact = (
            match.get("artifact")
            if isinstance(match.get("artifact"), dict)
            else {}
        )
        identifier = vulnerability.get("id")
        cve, ghsa, osv = _advisory_identifiers(
            identifier, vulnerability.get("relatedVulnerabilities")
        )
        locations = artifact.get("locations", [])
        location = locations[0] if isinstance(locations, list) and locations else {}
        findings.append(
            # Raw secret material must never become a canonical identifier.
            _legacy_finding(
                scanner="grype",
                category="sca",
                rule_id=identifier,
                severity=vulnerability.get("severity"),
                title=(
                    vulnerability.get("description")
                    or vulnerability.get("id")
                ),
                description=vulnerability.get("description"),
                file=location.get("path") if isinstance(location, dict) else "",
                cve=cve,
                ghsa=ghsa,
                osv=osv,
                dependency={
                    "name": artifact.get("name"),
                    "version": artifact.get("version"),
                    "ecosystem": artifact.get("type"),
                    "purl": artifact.get("purl"),
                    "direct": None,
                },
                source_reference=f"$.matches[{index}]",
            )
        )
    return _canonical(
        report_path,
        "grype",
        "sca",
        findings,
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_checkov(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    document = _json(report_path)
    reports = document if isinstance(document, list) else [document]
    findings: list[dict[str, Any]] = []
    for report_index, report in enumerate(reports):
        report = _object(report, "Checkov")
        results = report.get("results")
        if not isinstance(results, dict):
            raise ReportParseError("Checkov report field 'results' must be an object")
        failed = results.get("failed_checks", [])
        if not isinstance(failed, list):
            raise ReportParseError("Checkov failed_checks must be a list")
        for index, check in enumerate(failed):
            if not isinstance(check, dict):
                continue
            line_range = check.get("file_line_range") or []
            findings.append(
                _legacy_finding(
                    scanner="checkov",
                    category="iac",
                    rule_id=check.get("check_id"),
                    severity=check.get("severity"),
                    title=check.get("check_name"),
                    description=check.get("guideline") or check.get("check_name"),
                    file=check.get("file_path"),
                    start_line=line_range[0] if line_range else None,
                    end_line=line_range[-1] if line_range else None,
                    source_reference=(
                        f"$[{report_index}].results.failed_checks[{index}]"
                    ),
                )
            )
    return _canonical(
        report_path,
        "checkov",
        "iac",
        findings,
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_hadolint(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    issues = _list(_json(report_path), "Hadolint")
    findings = [
        _legacy_finding(
            scanner="hadolint",
            category="container",
            rule_id=issue.get("code"),
            severity=issue.get("level"),
            title=issue.get("message"),
            description=issue.get("message"),
            file=issue.get("file"),
            start_line=issue.get("line"),
            end_line=issue.get("line"),
            source_reference=f"$[{index}]",
        )
        for index, issue in enumerate(issues)
        if isinstance(issue, dict)
    ]
    return _canonical(
        report_path,
        "hadolint",
        "container",
        findings,
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_gosec(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    document = _object(_json(report_path), "Gosec")
    issues = document.get("Issues", [])
    if not isinstance(issues, list):
        raise ReportParseError("Gosec report field 'Issues' must be a list")
    findings = [
        _legacy_finding(
            scanner="gosec",
            category="sast",
            rule_id=issue.get("rule_id"),
            severity=issue.get("severity"),
            title=issue.get("details"),
            description=issue.get("details"),
            file=issue.get("file"),
            start_line=issue.get("line"),
            end_line=issue.get("line"),
            cwe=(issue.get("cwe") or {}).get("id")
            if isinstance(issue.get("cwe"), dict)
            else issue.get("cwe"),
            source_reference=f"$.Issues[{index}]",
        )
        for index, issue in enumerate(issues)
        if isinstance(issue, dict)
    ]
    return _canonical(
        report_path,
        "gosec",
        "sast",
        findings,
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_brakeman(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    document = _object(_json(report_path), "Brakeman")
    warnings = document.get("warnings", [])
    if not isinstance(warnings, list):
        raise ReportParseError("Brakeman report field 'warnings' must be a list")
    findings = [
        _legacy_finding(
            scanner="brakeman",
            category="sast",
            rule_id=warning.get("warning_code") or warning.get("warning_type"),
            # Brakeman confidence is not vulnerability severity.
            severity=None,
            title=warning.get("warning_type"),
            description=warning.get("message"),
            file=warning.get("file"),
            start_line=warning.get("line"),
            end_line=warning.get("line"),
            cwe=warning.get("cwe_id"),
            scanner_finding_id=warning.get("fingerprint"),
            source_reference=f"$.warnings[{index}]",
        )
        for index, warning in enumerate(warnings)
        if isinstance(warning, dict)
    ]
    return _canonical(
        report_path,
        "brakeman",
        "sast",
        findings,
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_spotbugs(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    try:
        root = ElementTree.parse(report_path).getroot()
    except ElementTree.ParseError as error:
        raise ReportParseError(f"SpotBugs report is malformed XML: {error}") from error
    if root.tag.rsplit("}", 1)[-1] != "BugCollection":
        raise ReportParseError("SpotBugs report root must be BugCollection")
    findings: list[dict[str, Any]] = []
    for index, bug in enumerate(root.findall(".//BugInstance")):
        source = bug.find(".//SourceLine")
        findings.append(
            _legacy_finding(
                scanner="spotbugs",
                category="sast",
                rule_id=bug.get("type"),
                severity=bug.get("priority"),
                title=bug.get("category") or bug.get("type"),
                description=(
                    bug.findtext("LongMessage")
                    or bug.findtext("ShortMessage")
                    or bug.get("type")
                ),
                file=source.get("sourcepath") if source is not None else "",
                start_line=source.get("start") if source is not None else None,
                end_line=source.get("end") if source is not None else None,
                cwe=bug.get("cweid"),
                source_reference=f"$.BugInstance[{index}]",
            )
        )
    return _canonical(
        report_path,
        "spotbugs",
        "sast",
        findings,
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_eslint_security(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    reports = _list(_json(report_path), "ESLint")
    findings: list[dict[str, Any]] = []
    for report_index, report in enumerate(reports):
        if not isinstance(report, dict):
            continue
        messages = report.get("messages", [])
        if not isinstance(messages, list):
            raise ReportParseError("ESLint messages must be a list")
        for message_index, message in enumerate(messages):
            if not isinstance(message, dict) or message.get("severity", 0) == 0:
                continue
            severity = "ERROR" if message.get("severity") == 2 else "WARNING"
            findings.append(
                _legacy_finding(
                    scanner="eslint-security",
                    category="sast",
                    rule_id=message.get("ruleId"),
                    severity=severity,
                    title=message.get("message"),
                    description=message.get("message"),
                    file=report.get("filePath"),
                    start_line=message.get("line"),
                    end_line=message.get("endLine") or message.get("line"),
                    source_reference=(
                        f"$[{report_index}].messages[{message_index}]"
                    ),
                )
            )
    return _canonical(
        report_path,
        "eslint-security",
        "sast",
        findings,
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_trufflehog(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    records: list[dict[str, Any]] = []
    with report_path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ReportParseError(
                    f"TruffleHog line {line_number} is malformed JSON: {error}"
                ) from error
            if not isinstance(record, dict):
                raise ReportParseError(
                    f"TruffleHog line {line_number} must be an object"
                )
            records.append(record)
    findings: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        source = (
            record.get("SourceMetadata")
            if isinstance(record.get("SourceMetadata"), dict)
            else {}
        )
        data = source.get("Data") if isinstance(source.get("Data"), dict) else {}
        filesystem = (
            data.get("Filesystem") if isinstance(data.get("Filesystem"), dict) else {}
        )
        findings.append(
            _legacy_finding(
                scanner="trufflehog",
                category="secrets",
                rule_id=record.get("DetectorName") or record.get("DetectorType"),
                severity="HIGH" if record.get("Verified") else "MEDIUM",
                title=record.get("DetectorName") or "Secret detected",
                description=(
                    "Verified secret detected"
                    if record.get("Verified")
                    else "Unverified secret detected"
                ),
                file=filesystem.get("file"),
                start_line=filesystem.get("line"),
                end_line=filesystem.get("line"),
                scanner_finding_id=(
                    record.get("SourceID")
                    or hashlib.sha256(
                        json.dumps(
                            {
                                "detector": record.get("DetectorName"),
                                "source": source,
                            },
                            sort_keys=True,
                            default=str,
                        ).encode("utf-8")
                    ).hexdigest()
                ),
                source_reference=f"$[{index}]",
            )
        )
    return _canonical(
        report_path,
        "trufflehog",
        "secrets",
        findings,
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


def parse_codeql_sarif(
    path: str | os.PathLike[str],
    *,
    redact_sensitive_content: bool = False,
    repository_root: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    report_path = Path(path)
    document = _object(_json(report_path), "CodeQL SARIF")
    if str(document.get("version")) not in {"2.1.0", "2.1"}:
        raise ReportParseError("CodeQL SARIF version must be 2.1.0")
    runs = document.get("runs", [])
    if not isinstance(runs, list):
        raise ReportParseError("CodeQL SARIF report field 'runs' must be a list")
    findings: list[dict[str, Any]] = []
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            continue
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ReportParseError("CodeQL SARIF results must be a list")
        rules: dict[str, dict[str, Any]] = {}
        driver = (run.get("tool") or {}).get("driver", {})
        if isinstance(driver, dict):
            for rule in driver.get("rules", []):
                if isinstance(rule, dict) and rule.get("id"):
                    rules[str(rule["id"])] = rule
        for result_index, result in enumerate(results):
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId")
            rule = rules.get(str(rule_id), {})
            properties = rule.get("properties", {}) if isinstance(rule, dict) else {}
            locations = result.get("locations", [])
            location = locations[0] if isinstance(locations, list) and locations else {}
            physical = (
                location.get("physicalLocation", {})
                if isinstance(location, dict)
                else {}
            )
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            message = result.get("message", {})
            findings.append(
                _legacy_finding(
                    scanner="codeql-sarif",
                    category="sast",
                    rule_id=rule_id,
                    severity=_cvss_label(
                        properties.get("security-severity")
                        or result.get("level")
                    ),
                    title=rule.get("name") or rule_id,
                    description=(
                        message.get("text")
                        if isinstance(message, dict)
                        else message
                    ),
                    file=artifact.get("uri") if isinstance(artifact, dict) else "",
                    start_line=region.get("startLine") if isinstance(region, dict) else None,
                    end_line=region.get("endLine") if isinstance(region, dict) else None,
                    cwe=properties.get("tags") if isinstance(properties, dict) else None,
                    scanner_finding_id=result.get("partialFingerprints"),
                    source_reference=f"$.runs[{run_index}].results[{result_index}]",
                )
            )
    return _canonical(
        report_path,
        "codeql-sarif",
        "sast",
        findings,
        redact_sensitive_content=redact_sensitive_content,
        repository_root=repository_root,
    )


__all__ = [
    "parse_brakeman",
    "parse_checkov",
    "parse_codeql_sarif",
    "parse_eslint_security",
    "parse_gosec",
    "parse_grype",
    "parse_hadolint",
    "parse_osv_scanner",
    "parse_spotbugs",
    "parse_syft",
    "parse_trufflehog",
    "parse_zap",
]
