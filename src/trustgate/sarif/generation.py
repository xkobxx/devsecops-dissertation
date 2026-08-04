"""Deterministic SARIF 2.1.0 output from canonical Trust Gate findings."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
from typing import Any
from urllib.parse import quote

from jsonschema import Draft202012Validator

from trustgate import __version__
from trustgate.schema import validate_instance


SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
    "errata01/os/schemas/sarif-schema-2.1.0.json"
)


class SarifValidationError(ValueError):
    """Raised when generated SARIF does not satisfy Trust Gate's strict profile."""


_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "unknown": "note",
}
_SECURITY_SEVERITIES = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
    "unknown": "0.0",
}
_SEVERITY_RANK = {
    "unknown": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


_PROFILE: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["$schema", "version", "runs"],
    "properties": {
        "$schema": {"const": SARIF_SCHEMA_URI},
        "version": {"const": "2.1.0"},
        "runs": {
            "type": "array",
            "minItems": 1,
            "items": {"$ref": "#/$defs/run"},
        },
    },
    "$defs": {
        "message": {
            "type": "object",
            "additionalProperties": False,
            "required": ["text"],
            "properties": {"text": {"type": "string", "minLength": 1}},
        },
        "rule": {
            "type": "object",
            "additionalProperties": True,
            "required": [
                "id",
                "name",
                "shortDescription",
                "fullDescription",
                "defaultConfiguration",
                "properties",
            ],
            "properties": {
                "id": {"type": "string", "minLength": 1},
                "name": {"type": "string", "minLength": 1},
                "shortDescription": {"$ref": "#/$defs/message"},
                "fullDescription": {"$ref": "#/$defs/message"},
                "defaultConfiguration": {
                    "type": "object",
                    "required": ["level"],
                    "properties": {
                        "level": {"enum": ["error", "warning", "note"]},
                    },
                },
                "properties": {
                    "type": "object",
                    "required": [
                        "security-severity",
                        "tags",
                        "trustgate/originalSeverity",
                    ],
                    "properties": {
                        "security-severity": {
                            "enum": sorted(set(_SECURITY_SEVERITIES.values())),
                        },
                        "tags": {
                            "type": "array",
                            "minItems": 2,
                            "uniqueItems": True,
                            "items": {"type": "string", "minLength": 1},
                        },
                        "trustgate/originalSeverity": {
                            "type": "string",
                            "minLength": 1,
                        },
                    },
                },
            },
        },
        "driver": {
            "type": "object",
            "additionalProperties": True,
            "required": [
                "name",
                "informationUri",
                "version",
                "semanticVersion",
                "rules",
            ],
            "properties": {
                "name": {"const": "Trust Gate"},
                "informationUri": {"type": "string", "minLength": 1},
                "version": {"type": "string", "minLength": 1},
                "semanticVersion": {"type": "string", "minLength": 1},
                "rules": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/rule"},
                },
            },
        },
        "result": {
            "type": "object",
            "additionalProperties": True,
            "required": [
                "ruleId",
                "ruleIndex",
                "message",
                "level",
                "fingerprints",
                "partialFingerprints",
            ],
            "properties": {
                "ruleId": {"type": "string", "minLength": 1},
                "ruleIndex": {"type": "integer", "minimum": 0},
                "message": {"$ref": "#/$defs/message"},
                "level": {"enum": ["error", "warning", "note"]},
                "fingerprints": {
                    "type": "object",
                    "minProperties": 1,
                    "additionalProperties": {"type": "string", "minLength": 1},
                },
                "partialFingerprints": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["trustgateStableContext/v2"],
                    "properties": {
                        "trustgateStableContext/v2": {
                            "type": "string",
                            "pattern": "^[0-9a-f]{64}$",
                        },
                    },
                },
                "locations": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 1,
                    "items": {"$ref": "#/$defs/location"},
                },
            },
        },
        "location": {
            "type": "object",
            "required": ["physicalLocation"],
            "properties": {
                "physicalLocation": {
                    "type": "object",
                    "required": ["artifactLocation"],
                    "properties": {
                        "artifactLocation": {
                            "type": "object",
                            "required": ["uri", "uriBaseId"],
                            "properties": {
                                "uri": {"type": "string", "minLength": 1},
                                "uriBaseId": {"const": "%SRCROOT%"},
                            },
                        },
                        "region": {
                            "type": "object",
                            "required": ["startLine"],
                            "properties": {
                                "startLine": {"type": "integer", "minimum": 1},
                                "endLine": {"type": "integer", "minimum": 1},
                            },
                        },
                    },
                },
            },
        },
        "run": {
            "type": "object",
            "additionalProperties": True,
            "required": [
                "automationDetails",
                "columnKind",
                "properties",
                "tool",
                "results",
            ],
            "properties": {
                "automationDetails": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {"id": {"type": "string", "minLength": 1}},
                },
                "columnKind": {"const": "utf16CodeUnits"},
                "properties": {
                    "type": "object",
                    "required": [
                        "trustgate/commit",
                        "trustgate/ref",
                        "trustgate/repository",
                        "trustgate/runId",
                        "trustgate/trigger",
                    ],
                },
                "tool": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["driver"],
                    "properties": {"driver": {"$ref": "#/$defs/driver"}},
                },
                "results": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/result"},
                },
            },
        },
    },
}


def _rule_id(finding: Mapping[str, Any]) -> str:
    return f"{finding['scanner']}/{finding['rule_id']}"


def _rule(finding: Mapping[str, Any]) -> dict[str, Any]:
    severity = str(finding["normalised_severity"])
    remediation = finding.get("remediation")
    help_sections: list[str] = []
    references: list[str] = []
    if isinstance(remediation, Mapping):
        for field in ("summary", "guidance"):
            value = remediation.get(field)
            if isinstance(value, str) and value:
                help_sections.append(value)
        raw_references = remediation.get("references")
        if isinstance(raw_references, list):
            references = [
                value for value in raw_references if isinstance(value, str) and value
            ]
    if references:
        help_sections.append("References:\n" + "\n".join(references))
    tags = {
        f"category/{finding['category']}",
        f"scanner/{finding['scanner']}",
        *(
            value
            for value in finding.get("cwe", [])
            if isinstance(value, str) and value
        ),
    }
    properties: dict[str, Any] = {
        "security-severity": _SECURITY_SEVERITIES[severity],
        "tags": sorted(tags),
        "trustgate/originalSeverity": str(finding["original_severity"]),
    }
    rule_version = finding.get("rule_version")
    if isinstance(rule_version, str) and rule_version:
        properties["trustgate/ruleVersion"] = rule_version
    rule: dict[str, Any] = {
        "id": _rule_id(finding),
        "name": str(finding["rule_id"]),
        "shortDescription": {"text": str(finding["title"])},
        "fullDescription": {"text": str(finding["description"])},
        "defaultConfiguration": {"level": _LEVELS[severity]},
        "properties": properties,
    }
    if help_sections:
        rule["help"] = {"text": "\n\n".join(help_sections)}
    if references:
        rule["helpUri"] = references[0]
    return rule


def _locations(finding: Mapping[str, Any]) -> list[dict[str, Any]]:
    path = finding.get("file")
    if not isinstance(path, str) or not path:
        return []
    physical: dict[str, Any] = {
        "artifactLocation": {
            "uri": quote(path.replace("\\", "/"), safe="/-._~"),
            "uriBaseId": "%SRCROOT%",
        }
    }
    start_line = finding.get("start_line")
    end_line = finding.get("end_line")
    if isinstance(start_line, int):
        region = {"startLine": start_line}
        if isinstance(end_line, int):
            region["endLine"] = end_line
        physical["region"] = region
    location: dict[str, Any] = {"physicalLocation": physical}
    symbol = finding.get("symbol")
    if isinstance(symbol, str) and symbol:
        location["logicalLocations"] = [
            {"fullyQualifiedName": symbol, "kind": "function"}
        ]
    return [location]


def _result(finding: Mapping[str, Any], rule_index: int) -> dict[str, Any]:
    fingerprint = str(finding["fingerprint"])
    fingerprint_version = fingerprint.split(":", 1)[0]
    stable_context = {
        "dependency": finding.get("dependency"),
        "file": finding.get("file"),
        "infrastructure_resource": finding.get("infrastructure_resource"),
        "rule_id": finding["rule_id"],
        "scanner": finding["scanner"],
        "secret_fingerprint": finding.get("secret_fingerprint"),
        "sink": finding.get("sink"),
        "source": finding.get("source"),
        "symbol": finding.get("symbol"),
    }
    partial_fingerprint = sha256(
        json.dumps(
            stable_context,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    result: dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "ruleIndex": rule_index,
        "message": {"text": str(finding["title"])},
        "level": _LEVELS[str(finding["normalised_severity"])],
        "fingerprints": {
            f"trustgateFindingFingerprint/{fingerprint_version}": fingerprint,
        },
        "partialFingerprints": {
            "trustgateStableContext/v2": partial_fingerprint,
        },
    }
    locations = _locations(finding)
    if locations:
        result["locations"] = locations
    return result


def validate_sarif(document: Mapping[str, Any]) -> None:
    """Validate one SARIF document against the emitted SARIF 2.1.0 profile."""

    errors = sorted(
        Draft202012Validator(_PROFILE).iter_errors(dict(document)),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        details = []
        for error in errors:
            path = "$" + "".join(
                f"[{part}]" if isinstance(part, int) else f".{part}"
                for part in error.absolute_path
            )
            details.append(f"{path}: {error.message}")
        raise SarifValidationError("SARIF validation failed: " + "; ".join(details))


def write_sarif(output: str | Path, document: Mapping[str, Any]) -> Path:
    """Validate and atomically publish one SARIF document."""

    validate_sarif(document)
    output_path = Path(output)
    if output_path.is_symlink():
        raise OSError(f"refusing to replace symlinked output: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            delete=False,
        ) as temporary:
            json.dump(document, temporary, indent=2, sort_keys=True)
            temporary.write("\n")
            temporary_path = Path(temporary.name)
        temporary_path.replace(output_path)
    except BaseException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise
    return output_path


def generate_sarif(scan_run: Mapping[str, Any]) -> dict[str, Any]:
    """Map a canonical scan run to deterministic SARIF 2.1.0."""

    source = deepcopy(dict(scan_run))
    validate_instance("scan-run", source)
    findings = sorted(source["findings"], key=lambda item: item["fingerprint"])
    rule_findings: dict[str, Mapping[str, Any]] = {}
    for finding in findings:
        rule_id = _rule_id(finding)
        previous = rule_findings.get(rule_id)
        if previous is None or _SEVERITY_RANK[str(finding["normalised_severity"])] > (
            _SEVERITY_RANK[str(previous["normalised_severity"])]
        ):
            rule_findings[rule_id] = finding
    rule_ids = sorted(rule_findings)
    rules = [_rule(rule_findings[rule_id]) for rule_id in rule_ids]
    rule_indexes = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    results = [
        _result(finding, rule_indexes[_rule_id(finding)])
        for finding in findings
    ]
    document = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "automationDetails": {"id": source["run_id"]},
                "columnKind": "utf16CodeUnits",
                "properties": {
                    "trustgate/commit": source["commit"],
                    "trustgate/ref": source["ref"],
                    "trustgate/repository": source["repository"],
                    "trustgate/runId": source["run_id"],
                    "trustgate/trigger": source["trigger"],
                },
                "tool": {
                    "driver": {
                        "name": "Trust Gate",
                        "informationUri": "https://github.com/xkobxx/devsecops-dissertation",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    validate_sarif(document)
    return document
