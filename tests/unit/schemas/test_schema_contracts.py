"""Contract tests for Trust Gate's canonical JSON Schemas."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIRECTORY = PROJECT_ROOT / "schemas"
SCHEMA_VERSION = "1.0.0"
SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"

FINDING_FIELDS = {
    "schema_version",
    "finding_id",
    "fingerprint",
    "scanner",
    "scanner_version",
    "rule_id",
    "rule_version",
    "category",
    "cwe",
    "cve",
    "ghsa",
    "osv",
    "title",
    "description",
    "original_severity",
    "normalised_severity",
    "severity_reason",
    "confidence",
    "confidence_method",
    "confidence_sample_size",
    "confidence_interval",
    "file",
    "start_line",
    "end_line",
    "symbol",
    "source",
    "sink",
    "data_flow",
    "dependency",
    "dependency_scope",
    "reachability",
    "environment",
    "introduced_commit",
    "first_seen",
    "last_seen",
    "status",
    "evidence",
    "remediation",
    "raw_report_reference",
}

OPTIONAL_CONFIDENCE_FIELDS = {
    "scanner_rule_reliability",
    "finding_validity_confidence",
    "reachability_confidence",
    "exploitability_confidence",
    "remediation_confidence",
    "overall_decision_confidence",
}

OPTIONAL_CORRELATION_FIELDS = {
    "occurrence_count",
    "locations",
    "raw_evidence_references",
    "source_finding_ids",
    "supporting_scanners",
    "contradicting_scanners",
    "agreement_strength",
    "correlation_reason",
    "correlation_signals",
    "corroboration",
    "code_region_hash",
    "infrastructure_resource",
    "secret_fingerprint",
    "rule_ancestry",
}

OPTIONAL_THREAT_INTELLIGENCE_FIELDS = {
    "threat_intelligence",
}


def load_schema(name: str) -> dict[str, object]:
    with (SCHEMA_DIRECTORY / name).open(encoding="utf-8") as handle:
        return json.load(handle)


FINDING_SCHEMA = load_schema("finding.schema.json")
SCAN_RUN_SCHEMA = load_schema("scan-run.schema.json")
POLICY_RESULT_SCHEMA = load_schema("policy-result.schema.json")

REGISTRY = Registry().with_resources(
    [
        (
            schema["$id"],
            Resource.from_contents(schema),
        )
        for schema in (FINDING_SCHEMA, SCAN_RUN_SCHEMA, POLICY_RESULT_SCHEMA)
    ]
)


def validator(schema: dict[str, object]) -> Draft202012Validator:
    return Draft202012Validator(
        schema,
        registry=REGISTRY,
        format_checker=FormatChecker(),
    )


def valid_finding() -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "finding_id": "finding-001",
        "fingerprint": "v1:sha256:0123456789abcdef",
        "scanner": "semgrep",
        "scanner_version": "1.125.0",
        "rule_id": "python.lang.security.audit.sqli",
        "rule_version": None,
        "category": "sast",
        "cwe": ["CWE-89"],
        "cve": [],
        "ghsa": [],
        "osv": [],
        "title": "Potential SQL injection",
        "description": "Untrusted input reaches a SQL query.",
        "original_severity": "ERROR",
        "normalised_severity": "high",
        "severity_reason": "Semgrep ERROR maps to Trust Gate high.",
        "confidence": None,
        "confidence_method": None,
        "confidence_sample_size": None,
        "confidence_interval": None,
        "file": "src/app.py",
        "start_line": 42,
        "end_line": 42,
        "symbol": "search",
        "source": "request.args['q']",
        "sink": "cursor.execute",
        "data_flow": [],
        "dependency": None,
        "dependency_scope": None,
        "reachability": "reachable",
        "environment": {
            "language": "python",
            "ci": True,
        },
        "introduced_commit": None,
        "first_seen": "2026-07-25T12:00:00Z",
        "last_seen": "2026-07-25T12:00:00Z",
        "status": "open",
        "evidence": [],
        "remediation": {
            "summary": "Use parameterised SQL.",
            "guidance": None,
            "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        },
        "raw_report_reference": {
            "path": "reports/semgrep.json",
            "sha256": "0" * 64,
            "scanner_finding_id": None,
        },
    }


def zero_severity_counts() -> dict[str, int]:
    return {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }


def zero_scanner_state_counts() -> dict[str, int]:
    return {
        "CLEAN": 0,
        "FINDINGS": 0,
        "FAILED_SCANNER": 0,
        "PARTIAL": 0,
        "SKIPPED": 0,
    }


class SchemaContractTests(unittest.TestCase):
    def test_schemas_use_draft_2020_12_and_have_unique_versioned_ids(self) -> None:
        schemas = (FINDING_SCHEMA, SCAN_RUN_SCHEMA, POLICY_RESULT_SCHEMA)

        for schema in schemas:
            with self.subTest(title=schema["title"]):
                self.assertEqual(schema["$schema"], SCHEMA_DIALECT)
                self.assertIn(f"/v{SCHEMA_VERSION}/", schema["$id"])
                self.assertEqual(
                    schema["properties"]["schema_version"]["const"],
                    SCHEMA_VERSION,
                )
                self.assertIn("schema_version", schema["required"])
                self.assertFalse(schema["additionalProperties"])
                Draft202012Validator.check_schema(schema)

        self.assertEqual(len({schema["$id"] for schema in schemas}), len(schemas))

    def test_finding_schema_contains_every_roadmap_field(self) -> None:
        self.assertEqual(
            set(FINDING_SCHEMA["properties"]),
            (
                FINDING_FIELDS
                | OPTIONAL_CONFIDENCE_FIELDS
                | OPTIONAL_CORRELATION_FIELDS
                | OPTIONAL_THREAT_INTELLIGENCE_FIELDS
            ),
        )
        self.assertEqual(set(FINDING_SCHEMA["required"]), FINDING_FIELDS)

    def test_complete_finding_validates(self) -> None:
        errors = list(validator(FINDING_SCHEMA).iter_errors(valid_finding()))

        self.assertEqual(errors, [])

    def test_each_finding_field_is_required(self) -> None:
        instance = valid_finding()
        finding_validator = validator(FINDING_SCHEMA)

        for field in sorted(FINDING_FIELDS):
            incomplete = deepcopy(instance)
            del incomplete[field]
            with self.subTest(field=field):
                self.assertTrue(
                    any(
                        error.validator == "required"
                        for error in finding_validator.iter_errors(incomplete)
                    )
                )

    def test_finding_rejects_unknown_fields(self) -> None:
        instance = valid_finding()
        instance["unexpected"] = "not part of the contract"

        self.assertTrue(validator(FINDING_SCHEMA).is_valid(instance) is False)

    def test_separate_confidence_components_validate(self) -> None:
        instance = valid_finding()
        component = {
            "estimate": 0.75,
            "conservative_bound": 0.5,
            "sample_size": 20,
            "method": "example",
            "methodology_version": "1.0.0",
            "evidence": ["labelled benchmark"],
            "explanation": "Example component.",
            "maturity": "Directional",
            "decision_tier": "Directional",
        }
        for field in OPTIONAL_CONFIDENCE_FIELDS:
            instance[field] = deepcopy(component)

        self.assertEqual(
            list(validator(FINDING_SCHEMA).iter_errors(instance)),
            [],
        )

    def test_correlation_provenance_and_agreement_fields_validate(self) -> None:
        from trustgate.correlation import correlate_findings

        first = valid_finding()
        second = deepcopy(first)
        second.update(
            {
                "scanner": "bandit",
                "rule_id": "B608",
                "finding_id": "finding-bandit",
                "fingerprint": "v2:sha256:" + "b" * 64,
                "start_line": 44,
                "end_line": 44,
                "raw_report_reference": {
                    "path": "reports/bandit.json",
                    "sha256": "b" * 64,
                    "scanner_finding_id": "B608:44",
                },
            }
        )

        correlated = correlate_findings([first, second])[0]

        self.assertEqual(
            list(validator(FINDING_SCHEMA).iter_errors(correlated)),
            [],
        )
        self.assertTrue(
            OPTIONAL_CORRELATION_FIELDS.issubset(FINDING_SCHEMA["properties"])
        )

    def test_threat_intelligence_fields_validate_with_visible_freshness(self) -> None:
        instance = valid_finding()
        instance["threat_intelligence"] = {
            "advisory_ids": ["CVE-2026-1234", "GHSA-abcd-1234-efgh"],
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L",
            "epss_probability": 0.42,
            "epss_percentile": 0.91,
            "kev_status": True,
            "known_exploitation_date": "2026-01-02",
            "ransomware_association": "known",
            "fixed_versions": ["1.2.0"],
            "published_date": "2026-01-01T00:00:00Z",
            "modified_date": "2026-01-03T00:00:00Z",
            "data_source_timestamp": "2026-01-04T00:00:00Z",
            "network_mode": "metadata-only",
            "stale": True,
            "risk_context_complete": False,
            "limitations": ["No threat feed provides complete risk context."],
            "sources": [
                {
                    "source": "epss",
                    "status": "stale-cache",
                    "fetched_at": "2026-01-04T00:00:00Z",
                    "expires_at": "2026-01-05T00:00:00Z",
                    "stale": True,
                    "identifiers_sent": [],
                }
            ],
            "failures": [
                {"source": "nvd", "error": "RuntimeError: rate limited"}
            ],
        }

        self.assertEqual(
            list(validator(FINDING_SCHEMA).iter_errors(instance)),
            [],
        )

    def test_scan_run_validates_and_resolves_finding_reference(self) -> None:
        scanner_counts = zero_scanner_state_counts()
        scanner_counts["FINDINGS"] = 1
        instance = {
            "schema_version": SCHEMA_VERSION,
            "run_id": "run-001",
            "status": "complete",
            "started_at": "2026-07-25T12:00:00Z",
            "ended_at": "2026-07-25T12:00:02Z",
            "duration_seconds": 2.0,
            "target": ".",
            "repository": "example/trustgate-demo",
            "ref": "refs/heads/main",
            "commit": "0123456789abcdef0123456789abcdef01234567",
            "trigger": "push",
            "scanners": [
                {
                    "scanner": "semgrep",
                    "scanner_version": "1.125.0",
                    "state": "FINDINGS",
                    "healthy": True,
                    "required": True,
                    "started_at": "2026-07-25T12:00:00Z",
                    "ended_at": "2026-07-25T12:00:02Z",
                    "duration_seconds": 2.0,
                    "exit_code": 1,
                    "timed_out": False,
                    "report_path": "reports/semgrep.json",
                    "report_produced": True,
                    "parser_status": "SUCCESS",
                    "stdout_path": "reports/logs/semgrep.stdout.log",
                    "stderr_path": "reports/logs/semgrep.stderr.log",
                    "finding_count": 1,
                    "error": None,
                }
            ],
            "findings": [valid_finding()],
            "summary": {
                "total_findings": 1,
                "required_scanners": 1,
                "healthy_scanners": 1,
                "severity_counts": {
                    **zero_severity_counts(),
                    "high": 1,
                },
                "scanner_state_counts": scanner_counts,
            },
            "errors": [],
        }

        self.assertEqual(list(validator(SCAN_RUN_SCHEMA).iter_errors(instance)), [])

    def test_scan_run_rejects_a_legacy_finding(self) -> None:
        instance = {
            "schema_version": SCHEMA_VERSION,
            "run_id": "run-001",
            "status": "complete",
            "started_at": "2026-07-25T12:00:00Z",
            "ended_at": "2026-07-25T12:00:02Z",
            "duration_seconds": 2.0,
            "target": ".",
            "repository": None,
            "ref": None,
            "commit": None,
            "trigger": "local",
            "scanners": [],
            "findings": [
                {
                    "tool": "Bandit",
                    "rule_id": "B608",
                    "severity": "MEDIUM",
                }
            ],
            "summary": {
                "total_findings": 1,
                "required_scanners": 0,
                "healthy_scanners": 0,
                "severity_counts": zero_severity_counts(),
                "scanner_state_counts": zero_scanner_state_counts(),
            },
            "errors": [],
        }

        errors = list(validator(SCAN_RUN_SCHEMA).iter_errors(instance))

        self.assertTrue(errors)
        self.assertTrue(any("schema_version" in error.message for error in errors))

    def test_policy_result_validates(self) -> None:
        instance = {
            "schema_version": SCHEMA_VERSION,
            "policy_result_id": "policy-result-001",
            "run_id": "run-001",
            "policy_name": "default",
            "policy_version": "1.0.0",
            "evaluated_at": "2026-07-25T12:00:03Z",
            "outcome": "fail",
            "reason": "One high-severity finding met the configured threshold.",
            "fail_on": "high",
            "scanner_failure_policy": "fail",
            "matched_finding_ids": ["finding-001"],
            "finding_counts": {
                **zero_severity_counts(),
                "high": 1,
            },
            "scanner_state_counts": {
                **zero_scanner_state_counts(),
                "FINDINGS": 1,
            },
            "waivers": [],
            "metadata": {
                "engine": "trustgate",
            },
        }

        self.assertEqual(
            list(validator(POLICY_RESULT_SCHEMA).iter_errors(instance)),
            [],
        )

    def test_policy_result_rejects_an_unknown_outcome(self) -> None:
        invalid = {
            "schema_version": SCHEMA_VERSION,
            "policy_result_id": "policy-result-001",
            "run_id": "run-001",
            "policy_name": "default",
            "policy_version": "1.0.0",
            "evaluated_at": "2026-07-25T12:00:03Z",
            "outcome": "maybe",
            "reason": "Unsupported outcome.",
            "fail_on": "high",
            "scanner_failure_policy": "fail",
            "matched_finding_ids": [],
            "finding_counts": zero_severity_counts(),
            "scanner_state_counts": zero_scanner_state_counts(),
            "waivers": [],
            "metadata": {},
        }

        errors = list(validator(POLICY_RESULT_SCHEMA).iter_errors(invalid))

        self.assertTrue(any(error.validator == "enum" for error in errors))


if __name__ == "__main__":
    unittest.main()
