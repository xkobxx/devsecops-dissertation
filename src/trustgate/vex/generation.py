"""Deterministic, approval-backed CycloneDX VEX generation."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

from trustgate.schema import SchemaValidationError, validate_instance

VEX_SCHEMA_VERSION = "1.0.0"
ANALYSIS_STATES = frozenset(
    {
        "resolved",
        "resolved_with_pedigree",
        "exploitable",
        "in_triage",
        "false_positive",
        "not_affected",
    }
)
JUSTIFICATIONS = frozenset(
    {
        "code_not_present",
        "code_not_reachable",
        "requires_configuration",
        "requires_dependency",
        "requires_environment",
        "protected_by_compiler",
        "protected_at_runtime",
        "protected_at_perimeter",
        "protected_by_mitigating_control",
    }
)
STATUS_TO_STATES = {
    "affected": frozenset({"exploitable"}),
    "not_affected": frozenset({"not_affected", "false_positive"}),
    "under_investigation": frozenset({"in_triage"}),
    "fixed": frozenset({"resolved", "resolved_with_pedigree"}),
}
STATUS_TO_AFFECTED = {
    "affected": "affected",
    "not_affected": "unaffected",
    "under_investigation": "unknown",
    "fixed": "unaffected",
}
ANALYSIS_FIELDS = frozenset(
    {
        "finding_fingerprint",
        "vulnerability_id",
        "exploitability_status",
        "analysis_state",
        "justification",
        "detail",
        "approval",
    }
)
APPROVAL_FIELDS = frozenset({"actor", "timestamp", "reason"})
VULNERABILITY_ID = re.compile(
    r"^(?:CVE-[0-9]{4}-[0-9]{4,}|GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}|[A-Za-z0-9][A-Za-z0-9._:-]{1,127})$"
)


class VexError(ValueError):
    """Raised when a VEX assertion is unsafe or inconsistent."""


def canonical_digest(value: object) -> str:
    """Return a stable content digest used to bind VEX evidence."""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _timestamp(value: object, *, label: str) -> tuple[str, datetime]:
    if not isinstance(value, str):
        raise VexError(f"{label} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise VexError(f"{label} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise VexError(f"{label} must include a timezone")
    canonical = parsed.isoformat(timespec="seconds").replace("+00:00", "Z")
    return canonical, parsed


def _non_empty(value: object, *, label: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VexError(f"{label} must be a non-empty string")
    result = value.strip()
    if len(result) > maximum or any(ord(character) < 32 for character in result):
        raise VexError(f"{label} contains unsafe text")
    return result


def _source(vulnerability_id: str) -> dict[str, str]:
    if vulnerability_id.startswith("CVE-"):
        return {
            "name": "NVD",
            "url": f"https://nvd.nist.gov/vuln/detail/{vulnerability_id}",
        }
    if vulnerability_id.startswith("GHSA-"):
        return {
            "name": "GitHub Advisories",
            "url": f"https://github.com/advisories/{vulnerability_id}",
        }
    return {
        "name": "OSV",
        "url": f"https://osv.dev/vulnerability/{vulnerability_id}",
    }


def _finding_ids(finding: Mapping[str, Any]) -> set[str]:
    return {
        str(identifier)
        for field in ("cve", "ghsa", "osv")
        for identifier in finding.get(field, [])
    }


def _analysis_record(
    raw: object,
    *,
    findings: Mapping[str, Mapping[str, Any]],
    generated_at: datetime,
    run_id: str,
    scan_run_digest: str,
) -> tuple[dict[str, object], dict[str, object]]:
    if not isinstance(raw, Mapping) or set(raw) != ANALYSIS_FIELDS:
        raise VexError("each VEX analysis must contain exactly the documented fields")
    fingerprint = _non_empty(
        raw["finding_fingerprint"], label="finding_fingerprint", maximum=512
    )
    finding = findings.get(fingerprint)
    if finding is None:
        raise VexError(f"VEX analysis references unknown finding {fingerprint}")
    vulnerability_id = _non_empty(
        raw["vulnerability_id"], label="vulnerability_id", maximum=128
    )
    if not VULNERABILITY_ID.fullmatch(vulnerability_id):
        raise VexError(f"invalid vulnerability identifier {vulnerability_id}")
    if vulnerability_id not in _finding_ids(finding):
        raise VexError(
            f"vulnerability {vulnerability_id} is not recorded on finding {fingerprint}"
        )

    dependency = finding.get("dependency")
    if not isinstance(dependency, Mapping):
        raise VexError(f"finding {fingerprint} has no dependency component")
    name = _non_empty(dependency.get("name"), label="dependency.name", maximum=256)
    version = _non_empty(
        dependency.get("version"), label="dependency.version", maximum=256
    )
    purl = _non_empty(dependency.get("purl"), label="dependency.purl", maximum=1024)
    if not purl.startswith("pkg:"):
        raise VexError(f"finding {fingerprint} dependency has no valid Package URL")

    reachability = finding.get("dependency_reachability")
    if not isinstance(reachability, Mapping):
        raise VexError(f"finding {fingerprint} has no dependency reachability evidence")
    reachability_status = _non_empty(
        reachability.get("status"), label="dependency_reachability.status", maximum=64
    )
    evidence = {
        "reachability": finding.get("reachability"),
        "dependency_reachability": reachability,
        "source_to_sink_analysis": finding.get("source_to_sink_analysis"),
        "dynamic_correlation": finding.get("dynamic_correlation"),
    }

    exploitability_status = _non_empty(
        raw["exploitability_status"], label="exploitability_status", maximum=32
    )
    allowed_states = STATUS_TO_STATES.get(exploitability_status)
    if allowed_states is None:
        raise VexError(f"unsupported exploitability status {exploitability_status}")
    analysis_state = _non_empty(
        raw["analysis_state"], label="analysis_state", maximum=32
    )
    if analysis_state not in ANALYSIS_STATES or analysis_state not in allowed_states:
        raise VexError(
            f"analysis state {analysis_state} is inconsistent with "
            f"exploitability status {exploitability_status}"
        )
    justification = _non_empty(raw["justification"], label="justification", maximum=64)
    if justification not in JUSTIFICATIONS:
        raise VexError(f"unsupported CycloneDX justification {justification}")
    if justification == "code_not_reachable" and (
        reachability_status == "CONFIRMED_REACHABLE"
        or reachability.get("call_path_exists") is True
    ):
        raise VexError(
            "code_not_reachable conflicts with confirmed reachability evidence"
        )
    detail = _non_empty(raw["detail"], label="detail", maximum=8192)

    approval = raw["approval"]
    if not isinstance(approval, Mapping) or set(approval) != APPROVAL_FIELDS:
        raise VexError("each VEX analysis requires a complete approval")
    _non_empty(approval["actor"], label="approval.actor", maximum=256)
    _non_empty(approval["reason"], label="approval.reason", maximum=4096)
    approval_timestamp, approved_at = _timestamp(
        approval["timestamp"], label="approval.timestamp"
    )
    if approved_at > generated_at:
        raise VexError("VEX approval cannot be later than document generation")

    approval_digest = canonical_digest(approval)
    evidence_digest = canonical_digest(evidence)
    decision_digest = canonical_digest(raw)
    vulnerability: dict[str, object] = {
        "bom-ref": "urn:trustgate:vex-analysis:"
        + decision_digest.removeprefix("sha256:"),
        "id": vulnerability_id,
        "source": _source(vulnerability_id),
        "analysis": {
            "state": analysis_state,
            "justification": justification,
            "detail": detail,
            "firstIssued": approval_timestamp,
            "lastUpdated": generated_at.isoformat(timespec="seconds").replace(
                "+00:00", "Z"
            ),
        },
        "affects": [
            {
                "ref": purl,
                "versions": [
                    {
                        "version": version,
                        "status": STATUS_TO_AFFECTED[exploitability_status],
                    }
                ],
            }
        ],
        "properties": [
            {
                "name": "trustgate:vex:exploitability-status",
                "value": exploitability_status,
            },
            {"name": "trustgate:vex:decision-digest", "value": decision_digest},
            {"name": "trustgate:finding:fingerprint", "value": fingerprint},
            {"name": "trustgate:scan-run:id", "value": run_id},
            {"name": "trustgate:scan-run:digest", "value": scan_run_digest},
            {"name": "trustgate:reachability:status", "value": reachability_status},
            {
                "name": "trustgate:reachability:evidence-digest",
                "value": evidence_digest,
            },
            {"name": "trustgate:approval:digest", "value": approval_digest},
        ],
    }
    component: dict[str, object] = {
        "type": "library",
        "bom-ref": purl,
        "name": name,
        "version": version,
        "purl": purl,
    }
    return vulnerability, component


def _vulnerability_sort_key(
    vulnerability: Mapping[str, object],
) -> tuple[str, str]:
    affects = vulnerability["affects"]
    if not isinstance(affects, list) or not affects:
        raise VexError("generated vulnerability has no affected component")
    affected = affects[0]
    if not isinstance(affected, Mapping):
        raise VexError("generated vulnerability has invalid affected component")
    return str(vulnerability["id"]), str(affected["ref"])


def generate_vex(
    scan_run: Mapping[str, Any],
    analysis_document: Mapping[str, Any],
) -> dict[str, object]:
    """Create a deterministic CycloneDX 1.6 VEX from explicit assertions."""

    try:
        validate_instance("scan-run", dict(scan_run))
    except SchemaValidationError as error:
        raise VexError(str(error)) from error
    expected_root_fields = {
        "schema_version",
        "revision",
        "run_id",
        "scan_run_digest",
        "generated_at",
        "analyses",
    }
    if (
        not isinstance(analysis_document, Mapping)
        or set(analysis_document) != expected_root_fields
    ):
        raise VexError("VEX analysis document contains unsupported or missing fields")
    if analysis_document["schema_version"] != VEX_SCHEMA_VERSION:
        raise VexError(f"VEX analysis document must use {VEX_SCHEMA_VERSION}")
    revision = analysis_document["revision"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise VexError("VEX revision must be a positive integer")
    run_id = _non_empty(analysis_document["run_id"], label="run_id", maximum=256)
    if run_id != scan_run["run_id"]:
        raise VexError("VEX analysis run_id does not match the scan run")
    scan_run_digest = canonical_digest(scan_run)
    if analysis_document["scan_run_digest"] != scan_run_digest:
        raise VexError("VEX analysis scan_run_digest does not match the scan run")
    generated_timestamp, generated_at = _timestamp(
        analysis_document["generated_at"], label="generated_at"
    )
    raw_analyses = analysis_document["analyses"]
    if not isinstance(raw_analyses, Sequence) or isinstance(raw_analyses, (str, bytes)):
        raise VexError("VEX analyses must be an array")
    if not raw_analyses:
        raise VexError("VEX analyses must contain at least one approved assertion")

    findings: dict[str, Mapping[str, Any]] = {}
    for finding in scan_run["findings"]:
        fingerprint = str(finding["fingerprint"])
        if fingerprint in findings:
            raise VexError(f"scan run contains duplicate fingerprint {fingerprint}")
        findings[fingerprint] = finding

    vulnerabilities: list[dict[str, object]] = []
    components: dict[str, dict[str, object]] = {}
    decisions: set[tuple[str, str]] = set()
    for raw_analysis in raw_analyses:
        vulnerability, component = _analysis_record(
            raw_analysis,
            findings=findings,
            generated_at=generated_at,
            run_id=run_id,
            scan_run_digest=scan_run_digest,
        )
        decision_key = (
            str(vulnerability["id"]),
            str(component["bom-ref"]),
        )
        if decision_key in decisions:
            raise VexError(
                "VEX analyses contain a duplicate vulnerability/component decision"
            )
        decisions.add(decision_key)
        vulnerabilities.append(vulnerability)
        existing = components.get(str(component["bom-ref"]))
        if existing is not None and existing != component:
            raise VexError("one Package URL resolves to conflicting component metadata")
        components[str(component["bom-ref"])] = component

    vulnerabilities.sort(key=_vulnerability_sort_key)
    repository = scan_run.get("repository") or scan_run["target"]
    root_ref = f"urn:trustgate:scan-run:{run_id}"
    serial = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"https://schemas.trustgate.dev/vex/{scan_run_digest}/{canonical_digest(analysis_document)}",
    )
    metadata_properties = [
        {"name": "trustgate:vex:schema-version", "value": VEX_SCHEMA_VERSION},
        {"name": "trustgate:scan-run:id", "value": run_id},
        {"name": "trustgate:scan-run:digest", "value": scan_run_digest},
    ]
    if scan_run.get("repository") is not None:
        metadata_properties.append(
            {"name": "trustgate:repository", "value": str(scan_run["repository"])}
        )
    if scan_run.get("commit") is not None:
        metadata_properties.append(
            {"name": "trustgate:git:commit", "value": str(scan_run["commit"])}
        )
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": revision,
        "metadata": {
            "timestamp": generated_timestamp,
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": str(repository),
            },
            "properties": metadata_properties,
        },
        "components": [deepcopy(components[purl]) for purl in sorted(components)],
        "vulnerabilities": vulnerabilities,
    }


def write_vex(path: str | Path, document: Mapping[str, Any]) -> Path:
    """Atomically publish a new VEX document without overwriting evidence."""

    output = Path(path)
    if output.exists() or output.is_symlink():
        raise VexError(f"refusing to overwrite VEX artifact: {output}")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=output.parent,
        prefix=f".{output.name}.",
        delete=False,
    ) as temporary:
        json.dump(document, temporary, indent=2, sort_keys=True)
        temporary.write("\n")
        temporary_path = Path(temporary.name)
    temporary_path.replace(output)
    return output


__all__ = [
    "VEX_SCHEMA_VERSION",
    "VexError",
    "canonical_digest",
    "generate_vex",
    "write_vex",
]
