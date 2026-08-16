"""Build and verify content-addressed audit-evidence manifests."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
import hashlib
import json
import mimetypes
from pathlib import Path
from typing import Any

from trustgate.baselines import verify_baseline
from trustgate.schema import (
    SchemaValidationError,
    validate_instance,
    write_validated_json,
)


EVIDENCE_SCHEMA_VERSION = "1.0.0"
CONFIG_FIELDS = frozenset(
    {
        "schema_version",
        "generated_at",
        "workflow_identity",
        "scan_run",
        "scan_configuration",
        "policy_result",
        "baseline",
        "suppressions",
        "approvals",
        "sboms",
        "vex",
        "provenance",
        "attestations",
        "exclusions",
        "manual_requirements",
    }
)
MANUAL_REQUIREMENT_FIELDS = frozenset(
    {"id", "requirement", "owner", "status", "evidence"}
)
MANUAL_STATUSES = frozenset({"required", "complete", "not_applicable"})


class EvidenceError(ValueError):
    """Raised when an evidence set is incomplete, unsafe, or inconsistent."""


class EvidenceIntegrityError(EvidenceError):
    """Raised when a manifest or referenced artifact fails verification."""


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _timestamp(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{label} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError(f"{label} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise EvidenceError(f"{label} must include a timezone")
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _text(value: object, *, label: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{label} must be a non-empty string")
    result = value.strip()
    if len(result) > maximum or any(ord(character) < 32 for character in result):
        raise EvidenceError(f"{label} contains unsafe text")
    return result


def _path_list(value: object, *, label: str, allow_empty: bool) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        qualifier = "a JSON array" if allow_empty else "a non-empty JSON array"
        raise EvidenceError(f"{label} must be {qualifier}")
    paths = [_text(item, label=f"{label} path", maximum=2048) for item in value]
    if len(paths) != len(set(paths)):
        raise EvidenceError(f"{label} must not contain duplicate paths")
    return sorted(paths)


class _ArtifactSet:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise EvidenceError(f"evidence root is not a directory: {self.root}")
        self._records: dict[str, dict[str, object]] = {}

    def resolve(self, relative: object) -> tuple[str, Path]:
        logical = _text(relative, label="artifact path", maximum=2048)
        candidate = Path(logical)
        if candidate.is_absolute():
            raise EvidenceError("artifact paths must remain within evidence root")
        resolved = (self.root / candidate).resolve()
        if not resolved.is_relative_to(self.root):
            raise EvidenceError("artifact paths must remain within evidence root")
        if not resolved.is_file():
            raise EvidenceError(f"evidence artifact does not exist: {logical}")
        normalised = resolved.relative_to(self.root).as_posix()
        return normalised, resolved

    def add(
        self,
        relative: object,
        *,
        kind: str,
        evidence_source: str = "automated",
    ) -> str:
        normalised, resolved = self.resolve(relative)
        content = resolved.read_bytes()
        record: dict[str, object] = {
            "path": normalised,
            "kind": kind,
            "evidence_source": evidence_source,
            "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "media_type": mimetypes.guess_type(normalised)[0]
            or "application/octet-stream",
        }
        existing = self._records.get(normalised)
        if existing is not None and existing != record:
            raise EvidenceError(
                f"artifact {normalised} cannot have conflicting evidence roles"
            )
        self._records[normalised] = record
        return normalised

    def json_object(
        self,
        relative: object,
        *,
        kind: str,
        evidence_source: str = "automated",
    ) -> tuple[str, dict[str, Any]]:
        logical = self.add(relative, kind=kind, evidence_source=evidence_source)
        try:
            value = json.loads((self.root / logical).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise EvidenceError(
                f"invalid JSON evidence artifact {logical}: {error}"
            ) from error
        if not isinstance(value, dict):
            raise EvidenceError(
                f"evidence artifact {logical} must contain a JSON object"
            )
        return logical, value

    def records(self) -> list[dict[str, object]]:
        return [self._records[path] for path in sorted(self._records)]


def _manual_requirements(
    raw: object,
    *,
    artifacts: _ArtifactSet,
) -> list[dict[str, object]]:
    if not isinstance(raw, list):
        raise EvidenceError("manual_requirements must be a JSON array")
    result: list[dict[str, object]] = []
    identifiers: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping) or set(item) != MANUAL_REQUIREMENT_FIELDS:
            raise EvidenceError(
                "each manual requirement must contain exactly id, requirement, "
                "owner, status, and evidence"
            )
        identifier = _text(
            item["id"],
            label=f"manual_requirements[{index}].id",
            maximum=128,
        )
        if identifier in identifiers:
            raise EvidenceError(f"duplicate manual requirement id {identifier}")
        identifiers.add(identifier)
        status = _text(
            item["status"],
            label=f"manual_requirements[{index}].status",
            maximum=32,
        )
        if status not in MANUAL_STATUSES:
            raise EvidenceError(f"unsupported manual requirement status {status}")
        evidence_paths = _path_list(
            item["evidence"],
            label=f"manual_requirements[{index}].evidence",
            allow_empty=status != "complete",
        )
        evidence = [
            artifacts.add(
                path,
                kind="manual-compliance-evidence",
                evidence_source="manual",
            )
            for path in evidence_paths
        ]
        result.append(
            {
                "id": identifier,
                "requirement": _text(
                    item["requirement"],
                    label=f"manual_requirements[{index}].requirement",
                ),
                "owner": _text(
                    item["owner"],
                    label=f"manual_requirements[{index}].owner",
                    maximum=256,
                ),
                "status": status,
                "evidence": evidence,
            }
        )
    return sorted(result, key=lambda item: str(item["id"]))


def _approval_digests(
    suppressions: Sequence[Mapping[str, Any]],
    approvals: Sequence[Mapping[str, Any]],
    vex: Mapping[str, Any],
) -> list[str]:
    digests = {
        _canonical_digest(suppression["approval"])
        for suppression in suppressions
        if isinstance(suppression.get("approval"), Mapping)
    }
    digests.update(_canonical_digest(approval) for approval in approvals)
    for vulnerability in vex.get("vulnerabilities", []):
        if not isinstance(vulnerability, Mapping):
            continue
        for property_ in vulnerability.get("properties", []):
            if (
                isinstance(property_, Mapping)
                and property_.get("name") == "trustgate:approval:digest"
                and isinstance(property_.get("value"), str)
            ):
                digests.add(str(property_["value"]))
    return sorted(digests)


def _data_source_timestamps(scan_run: Mapping[str, Any]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for finding in scan_run["findings"]:
        threat = finding.get("threat_intelligence")
        if not isinstance(threat, Mapping):
            continue
        fingerprint = str(finding["fingerprint"])
        for source in threat.get("sources", []):
            if not isinstance(source, Mapping):
                continue
            timestamp = source.get("fetched_at")
            name = source.get("source")
            if isinstance(timestamp, str) and isinstance(name, str):
                result.append(
                    {
                        "finding_fingerprint": fingerprint,
                        "source": name,
                        "timestamp": _timestamp(
                            timestamp, label="threat data source timestamp"
                        ),
                    }
                )
        aggregate = threat.get("data_source_timestamp")
        if isinstance(aggregate, str):
            result.append(
                {
                    "finding_fingerprint": fingerprint,
                    "source": "aggregate",
                    "timestamp": _timestamp(
                        aggregate, label="aggregate threat data timestamp"
                    ),
                }
            )
    return sorted(
        result,
        key=lambda item: (
            item["finding_fingerprint"],
            item["source"] == "aggregate",
            item["source"],
            item["timestamp"],
        ),
    )


def _verify_vex_binding(vex: Mapping[str, Any], scan_run: Mapping[str, Any]) -> None:
    if vex.get("bomFormat") != "CycloneDX" or not isinstance(
        vex.get("vulnerabilities"), list
    ):
        raise EvidenceError("VEX artifact must be a CycloneDX VEX document")
    expected_run = scan_run["run_id"]
    expected_digest = _canonical_digest(scan_run)
    for vulnerability in vex["vulnerabilities"]:
        properties = {
            item.get("name"): item.get("value")
            for item in vulnerability.get("properties", [])
            if isinstance(item, Mapping)
        }
        if properties.get("trustgate:scan-run:id") != expected_run:
            raise EvidenceError("VEX artifact is not bound to the scan run_id")
        if properties.get("trustgate:scan-run:digest") != expected_digest:
            raise EvidenceError("VEX artifact is not bound to the scan-run content")


def generate_audit_evidence(
    root: str | Path,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    """Generate a deterministic manifest from a complete evidence configuration."""

    if not isinstance(config, Mapping) or set(config) != CONFIG_FIELDS:
        raise EvidenceError(
            "evidence config must contain exactly the documented fields"
        )
    if config.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        raise EvidenceError(
            f"unsupported evidence config version {config.get('schema_version')!r}"
        )
    generated_at = _timestamp(config["generated_at"], label="generated_at")
    workflow_identity = _text(
        config["workflow_identity"], label="workflow_identity", maximum=2048
    )
    artifacts = _ArtifactSet(root)

    scan_path, scan_run = artifacts.json_object(config["scan_run"], kind="scan-run")
    policy_path, policy_result = artifacts.json_object(
        config["policy_result"], kind="policy-result"
    )
    baseline_path, baseline = artifacts.json_object(config["baseline"], kind="baseline")
    scan_configuration = artifacts.add(
        config["scan_configuration"], kind="scan-configuration"
    )
    exclusions_path, exclusions = artifacts.json_object(
        config["exclusions"], kind="scan-exclusions"
    )
    try:
        validate_instance("scan-run", scan_run)
        validate_instance("policy-result", policy_result)
        verify_baseline(baseline)
    except (SchemaValidationError, ValueError) as error:
        raise EvidenceError(f"invalid canonical evidence: {error}") from error

    repository = scan_run.get("repository")
    commit = scan_run.get("commit")
    ref = scan_run.get("ref")
    if not all(isinstance(value, str) and value for value in (repository, commit, ref)):
        raise EvidenceError("scan run requires repository, ref, and commit identity")
    if policy_result["run_id"] != scan_run["run_id"]:
        raise EvidenceError("policy result run_id does not match scan run")
    if baseline["repository"] != repository:
        raise EvidenceError("baseline repository does not match scan run")

    suppression_paths = _path_list(
        config["suppressions"], label="suppressions", allow_empty=True
    )
    suppressions: list[dict[str, Any]] = []
    for path in suppression_paths:
        _, suppression = artifacts.json_object(path, kind="suppression")
        try:
            validate_instance("suppression", suppression)
        except SchemaValidationError as error:
            raise EvidenceError(f"invalid suppression evidence: {error}") from error
        if suppression["scope"]["repository"] != repository:
            raise EvidenceError("suppression repository does not match scan run")
        suppressions.append(suppression)

    approval_paths = _path_list(
        config["approvals"], label="approvals", allow_empty=True
    )
    approvals = [
        artifacts.json_object(path, kind="approval")[1] for path in approval_paths
    ]
    sbom_paths = _path_list(config["sboms"], label="sboms", allow_empty=False)
    sboms: list[tuple[str, dict[str, Any]]] = [
        artifacts.json_object(path, kind="sbom") for path in sbom_paths
    ]
    sbom_formats = {
        "CycloneDX" if document.get("bomFormat") == "CycloneDX" else
        "SPDX" if document.get("spdxVersion") == "SPDX-2.3" else "unknown"
        for _, document in sboms
    }
    if not {"CycloneDX", "SPDX"}.issubset(sbom_formats):
        raise EvidenceError("SBOM evidence must include CycloneDX and SPDX 2.3")

    vex_path, vex = artifacts.json_object(config["vex"], kind="vex")
    _verify_vex_binding(vex, scan_run)
    provenance_paths = [
        artifacts.add(path, kind="provenance")
        for path in _path_list(
            config["provenance"], label="provenance", allow_empty=False
        )
    ]
    attestation_paths = [
        artifacts.add(path, kind="attestation")
        for path in _path_list(
            config["attestations"], label="attestations", allow_empty=False
        )
    ]
    manual = _manual_requirements(config["manual_requirements"], artifacts=artifacts)
    approval_digests = _approval_digests(suppressions, approvals, vex)
    if not approval_digests:
        raise EvidenceError("evidence set must contain at least one approval")

    if isinstance(exclusions, Mapping):
        exclusion_count = len(exclusions)
    elif isinstance(exclusions, list):
        exclusion_count = len(exclusions)
    else:
        raise EvidenceError("exclusions artifact must contain an object or array")

    body: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "generated_at": generated_at,
        "subject": {
            "repository": repository,
            "commit": commit,
            "ref": ref,
            "workflow_identity": workflow_identity,
        },
        "automated_evidence": {
            "scan": {
                "run_id": scan_run["run_id"],
                "status": scan_run["status"],
                "started_at": scan_run["started_at"],
                "ended_at": scan_run["ended_at"],
                "configuration": scan_configuration,
                "scanners": sorted(
                    [
                        {
                            "scanner": scanner["scanner"],
                            "version": scanner["scanner_version"],
                            "state": scanner["state"],
                            "healthy": scanner["healthy"],
                            "required": scanner["required"],
                        }
                        for scanner in scan_run["scanners"]
                    ],
                    key=lambda item: item["scanner"],
                ),
                "findings": {
                    "count": len(scan_run["findings"]),
                    "severity_counts": scan_run["summary"]["severity_counts"],
                    "artifact": scan_path,
                },
                "exclusions": {
                    "count": exclusion_count,
                    "artifact": exclusions_path,
                },
            },
            "policy": {
                "policy_name": policy_result["policy_name"],
                "policy_version": policy_result["policy_version"],
                "evaluated_at": policy_result["evaluated_at"],
                "gate_result": policy_result["outcome"],
                "artifact": policy_path,
            },
            "baseline": {
                "version": baseline["version"],
                "schema_version": baseline["schema_version"],
                "generated_at": baseline["generated_at"],
                "digest": baseline["baseline_digest"],
                "artifact": baseline_path,
            },
            "suppressions": {
                "count": len(suppression_paths),
                "artifacts": suppression_paths,
            },
            "approvals": {
                "count": len(approval_digests),
                "digests": approval_digests,
                "artifacts": approval_paths,
            },
            "supply_chain": {
                "sboms": [path for path, _ in sboms],
                "vex": vex_path,
            },
            "provenance": provenance_paths,
            "attestations": attestation_paths,
            "data_source_timestamps": _data_source_timestamps(scan_run),
        },
        "manual_compliance_requirements": manual,
        "artifacts": artifacts.records(),
        "verification": {
            "digest_algorithm": "sha256",
            "canonicalization": "RFC8785-compatible sorted compact JSON",
            "artifact_scope": "paths relative to the declared evidence root",
        },
    }
    digest = _canonical_digest(body)
    document = {
        **body,
        "evidence_id": "audit-evidence-" + digest.removeprefix("sha256:")[:24],
        "evidence_digest": digest,
    }
    validate_instance("audit-evidence", document)
    return document


def verify_audit_evidence(root: str | Path, document: Mapping[str, Any]) -> None:
    """Verify manifest integrity and every referenced artifact byte-for-byte."""

    try:
        validate_instance("audit-evidence", document)
    except (SchemaValidationError, ValueError) as error:
        raise EvidenceIntegrityError(f"invalid audit manifest: {error}") from error
    payload = {
        key: value
        for key, value in document.items()
        if key not in {"evidence_id", "evidence_digest"}
    }
    expected = _canonical_digest(payload)
    if document.get("evidence_digest") != expected:
        raise EvidenceIntegrityError("audit manifest digest does not match its content")
    expected_id = "audit-evidence-" + expected.removeprefix("sha256:")[:24]
    if document.get("evidence_id") != expected_id:
        raise EvidenceIntegrityError(
            "audit manifest evidence_id does not match its digest"
        )

    artifact_set = _ArtifactSet(root)
    for artifact in document["artifacts"]:
        normalised, resolved = artifact_set.resolve(artifact["path"])
        content = resolved.read_bytes()
        actual_digest = "sha256:" + hashlib.sha256(content).hexdigest()
        if artifact["sha256"] != actual_digest:
            raise EvidenceIntegrityError(f"artifact digest mismatch: {normalised}")
        if artifact["size_bytes"] != len(content):
            raise EvidenceIntegrityError(f"artifact size mismatch: {normalised}")


def write_audit_evidence(path: str | Path, document: Mapping[str, Any]) -> Path:
    """Atomically publish a validated audit-evidence manifest."""

    return write_validated_json(path, document, schema_name="audit-evidence")
