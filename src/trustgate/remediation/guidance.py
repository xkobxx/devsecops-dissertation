"""Evidence-bound guided-remediation reports."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import json
import re
from typing import Any

from trustgate.schema import SchemaValidationError, validate_instance

from .engine import RemediationError
from .guidance_profiles import guidance_profiles
from .rules import supported_rules


REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "revision",
        "generated_at",
        "run_id",
        "scan_run_digest",
        "guidance",
    }
)
MAPPING_FIELDS = frozenset(
    {"finding_fingerprint", "remediation_rule_id", "framework"}
)
_CWE = re.compile(r"^CWE-([1-9][0-9]*)$")
_LIMITATIONS = [
    "Guidance does not modify source code.",
    "Guidance is not proof that a finding is fixed.",
    "Verification must use repository tests and relevant scanners.",
]
_COMMON_VERIFICATION = [
    "Review the proposed pattern against the repository's actual framework "
    "and data flow.",
    "Run the listed unit, integration, and regression tests.",
    "Rerun the scanner rule that produced the original finding.",
    "Confirm the original fingerprint is absent and no new high-risk finding appeared.",
]


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _text(value: object, *, label: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RemediationError(f"{label} must be a non-empty string")
    result = value.strip()
    if len(result) > maximum or any(ord(character) < 32 for character in result):
        raise RemediationError(f"{label} contains unsafe text")
    return result


def _timestamp(value: object) -> str:
    if not isinstance(value, str):
        raise RemediationError("generated_at must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RemediationError(
            "generated_at must be an RFC 3339 timestamp"
        ) from error
    if parsed.tzinfo is None:
        raise RemediationError("generated_at must include a timezone")
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _flow_value(finding: Mapping[str, Any], field: str) -> tuple[str, str]:
    value = finding.get(field)
    if isinstance(value, str) and value.strip():
        return value.strip(), f"finding.{field}"
    return "unknown", "not_available"


def _cwe_references(values: set[str]) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    for value in sorted(values, key=lambda item: int(item.removeprefix("CWE-"))):
        match = _CWE.fullmatch(value)
        if match is None:
            raise RemediationError(f"unsupported CWE reference {value}")
        references.append(
            {
                "id": value,
                "url": (
                    "https://cwe.mitre.org/data/definitions/"
                    f"{match.group(1)}.html"
                ),
            }
        )
    return references


def generate_guidance(
    scan_run: Mapping[str, Any],
    request: Mapping[str, Any],
) -> dict[str, Any]:
    """Generate deterministic guidance without modifying repository source."""

    try:
        validate_instance("scan-run", scan_run)
    except SchemaValidationError as error:
        raise RemediationError(f"invalid canonical scan run: {error}") from error
    if not isinstance(request, Mapping) or set(request) != REQUEST_FIELDS:
        raise RemediationError(
            "guidance request must contain exactly the documented fields"
        )
    if request.get("schema_version") != "1.0.0":
        raise RemediationError("unsupported guidance request schema version")
    revision = request["revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise RemediationError("guidance revision must be a positive integer")
    generated_at = _timestamp(request["generated_at"])
    if request.get("run_id") != scan_run["run_id"]:
        raise RemediationError("guidance request run_id does not match scan run")
    scan_digest = _canonical_digest(scan_run)
    if request.get("scan_run_digest") != scan_digest:
        raise RemediationError(
            "guidance request is not bound to current scan-run content"
        )
    mappings = request["guidance"]
    if not isinstance(mappings, list) or not mappings:
        raise RemediationError("guidance request requires at least one mapping")

    rules = {rule["rule_id"]: rule for rule in supported_rules()}
    profiles = guidance_profiles()
    if set(rules) != set(profiles):
        raise RemediationError("guided-remediation profiles are incomplete")
    findings = {
        str(finding["fingerprint"]): finding for finding in scan_run["findings"]
    }
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for mapping in mappings:
        if not isinstance(mapping, Mapping) or set(mapping) != MAPPING_FIELDS:
            raise RemediationError(
                "each guidance mapping must contain exactly the documented fields"
            )
        fingerprint = _text(
            mapping["finding_fingerprint"],
            label="finding_fingerprint",
            maximum=512,
        )
        if fingerprint in seen:
            raise RemediationError(f"duplicate guidance mapping {fingerprint}")
        seen.add(fingerprint)
        finding = findings.get(fingerprint)
        if finding is None:
            raise RemediationError(
                f"guidance mapping references unknown finding {fingerprint}"
            )
        rule_id = _text(
            mapping["remediation_rule_id"],
            label="remediation_rule_id",
            maximum=128,
        )
        rule = rules.get(rule_id)
        profile = profiles.get(rule_id)
        if rule is None or profile is None:
            raise RemediationError(f"unsupported remediation rule {rule_id}")
        framework = _text(mapping["framework"], label="framework", maximum=128)
        if framework != rule["framework"]:
            raise RemediationError(
                f"rule {rule_id} requires framework {rule['framework']}"
            )
        finding_cwe = {
            str(value) for value in finding.get("cwe", []) if isinstance(value, str)
        }
        applicable_cwe = finding_cwe.intersection(profile["applicable_cwe"])
        if not applicable_cwe:
            raise RemediationError(
                f"rule {rule_id} is not applicable to finding CWE evidence"
            )
        source, source_evidence = _flow_value(finding, "source")
        sink, sink_evidence = _flow_value(finding, "sink")
        entries.append(
            {
                "finding_id": finding["finding_id"],
                "finding_fingerprint": fingerprint,
                "scanner": finding["scanner"],
                "scanner_rule_id": finding["rule_id"],
                "remediation_rule_id": rule_id,
                "framework": framework,
                "status": "guidance_only",
                "why_vulnerable": profile["why_vulnerable"],
                "exploit_scenario": profile["exploit_scenario"],
                "relevant_flow": {
                    "source": source,
                    "source_evidence": source_evidence,
                    "sink": sink,
                    "sink_evidence": sink_evidence,
                },
                "secure_coding_pattern": profile["secure_coding_pattern"],
                "framework_specific_example": profile[
                    "framework_specific_example"
                ],
                "cwe_references": _cwe_references(applicable_cwe),
                "testing_guidance": list(profile["testing_guidance"]),
                "regression_risks": list(profile["regression_risks"]),
                "verification_instructions": list(_COMMON_VERIFICATION),
            }
        )

    body: dict[str, Any] = {
        "schema_version": "1.0.0",
        "revision": revision,
        "generated_at": generated_at,
        "run_id": scan_run["run_id"],
        "scan_run_digest": scan_digest,
        "repository": scan_run["repository"],
        "commit": scan_run["commit"],
        "entries": sorted(
            entries,
            key=lambda entry: (
                entry["finding_fingerprint"],
                entry["remediation_rule_id"],
            ),
        ),
        "limitations": list(_LIMITATIONS),
    }
    digest = _canonical_digest(body)
    document = {
        **body,
        "guidance_id": "guidance-" + digest.removeprefix("sha256:")[:24],
        "guidance_digest": digest,
    }
    validate_instance("remediation-guidance", document)
    return document


__all__ = ["generate_guidance"]
