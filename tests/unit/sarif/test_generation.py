"""Behavior tests for canonical finding to SARIF 2.1.0 mapping."""

from __future__ import annotations

from copy import deepcopy
import unittest

from trustgate.sarif import generate_sarif, validate_sarif

from tests.unit.baselines.test_comparison import scan
from tests.unit.schemas.test_schema_contracts import valid_finding


def scan_run(*findings: dict[str, object]) -> dict[str, object]:
    return scan(
        list(findings),
        ref="refs/pull/42/merge",
        trigger="pull_request",
        commit="b" * 40,
    )


class SarifGenerationTests(unittest.TestCase):
    def test_canonical_finding_maps_to_deterministic_sarif_result_and_rule(self) -> None:
        finding = valid_finding()
        source = scan_run(finding)
        original = deepcopy(source)

        sarif = generate_sarif(source)

        self.assertEqual(source, original)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(
            sarif["$schema"],
            (
                "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
                "errata01/os/schemas/sarif-schema-2.1.0.json"
            ),
        )
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Trust Gate")
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        rule = run["tool"]["driver"]["rules"][0]
        result = run["results"][0]
        self.assertEqual(rule["id"], "semgrep/python.lang.security.audit.sqli")
        self.assertEqual(result["ruleId"], rule["id"])
        self.assertEqual(result["ruleIndex"], 0)
        self.assertEqual(result["message"]["text"], finding["title"])
        validate_sarif(sarif)
        self.assertEqual(generate_sarif(source), sarif)

    def test_normalised_severity_maps_to_sarif_and_github_security_levels(self) -> None:
        cases = {
            "critical": ("error", "9.5"),
            "high": ("error", "8.0"),
            "medium": ("warning", "5.5"),
            "low": ("note", "3.0"),
            "info": ("note", "1.0"),
            "unknown": ("note", "0.0"),
        }

        for severity, (level, security_severity) in cases.items():
            with self.subTest(severity=severity):
                finding = valid_finding()
                finding["normalised_severity"] = severity
                sarif = generate_sarif(scan_run(finding))
                rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
                result = sarif["runs"][0]["results"][0]

                self.assertEqual(result["level"], level)
                self.assertEqual(rule["defaultConfiguration"]["level"], level)
                self.assertEqual(
                    rule["properties"]["security-severity"],
                    security_severity,
                )

    def test_result_includes_precise_repository_relative_location(self) -> None:
        finding = valid_finding()
        finding.update(
            {
                "file": "src/app file.py",
                "start_line": 42,
                "end_line": 44,
                "symbol": "search",
            }
        )

        result = generate_sarif(scan_run(finding))["runs"][0]["results"][0]

        self.assertEqual(
            result["locations"],
            [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "src/app%20file.py",
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": 42, "endLine": 44},
                    },
                    "logicalLocations": [
                        {"fullyQualifiedName": "search", "kind": "function"}
                    ],
                }
            ],
        )

    def test_rule_includes_security_metadata_and_remediation_help(self) -> None:
        finding = valid_finding()
        finding["remediation"]["guidance"] = "Bind each value separately."

        rule = generate_sarif(scan_run(finding))["runs"][0]["tool"]["driver"][
            "rules"
        ][0]

        self.assertEqual(
            rule["fullDescription"],
            {"text": "Untrusted input reaches a SQL query."},
        )
        self.assertEqual(
            rule["help"]["text"],
            (
                "Use parameterised SQL.\n\nBind each value separately.\n\n"
                "References:\nhttps://cwe.mitre.org/data/definitions/89.html"
            ),
        )
        self.assertEqual(
            rule["helpUri"],
            "https://cwe.mitre.org/data/definitions/89.html",
        )
        self.assertEqual(
            rule["properties"]["tags"],
            ["CWE-89", "category/sast", "scanner/semgrep"],
        )
        self.assertEqual(rule["properties"]["trustgate/originalSeverity"], "ERROR")

    def test_results_include_full_and_line_stable_partial_fingerprints(self) -> None:
        finding = valid_finding()
        moved = deepcopy(finding)
        moved["start_line"] = 142
        moved["end_line"] = 144

        first = generate_sarif(scan_run(finding))["runs"][0]["results"][0]
        second = generate_sarif(scan_run(moved))["runs"][0]["results"][0]

        self.assertEqual(
            first["fingerprints"],
            {"trustgateFindingFingerprint/v1": finding["fingerprint"]},
        )
        self.assertRegex(
            first["partialFingerprints"]["trustgateStableContext/v2"],
            r"^[0-9a-f]{64}$",
        )
        self.assertEqual(first["partialFingerprints"], second["partialFingerprints"])

    def test_run_includes_repository_and_source_revision_metadata(self) -> None:
        source = scan_run(valid_finding())

        run = generate_sarif(source)["runs"][0]

        self.assertEqual(run["automationDetails"], {"id": source["run_id"]})
        self.assertEqual(run["columnKind"], "utf16CodeUnits")
        self.assertEqual(
            run["properties"],
            {
                "trustgate/commit": "b" * 40,
                "trustgate/ref": "refs/pull/42/merge",
                "trustgate/repository": "example/trustgate",
                "trustgate/runId": source["run_id"],
                "trustgate/trigger": "pull_request",
            },
        )

    def test_validation_reports_the_invalid_document_path(self) -> None:
        sarif = generate_sarif(scan_run(valid_finding()))
        del sarif["runs"][0]["results"][0]["message"]

        with self.assertRaisesRegex(
            ValueError,
            r"\$\.runs\[0\]\.results\[0\].*message",
        ):
            validate_sarif(sarif)

        sarif = generate_sarif(scan_run(valid_finding()))
        sarif["runs"][0]["results"][0]["level"] = "severe"
        with self.assertRaisesRegex(
            ValueError,
            r"\$\.runs\[0\]\.results\[0\]\.level",
        ):
            validate_sarif(sarif)

    def test_shared_rule_uses_highest_default_but_preserves_result_levels(self) -> None:
        lower = valid_finding()
        lower["normalised_severity"] = "low"
        higher = deepcopy(lower)
        higher["finding_id"] = "finding-002"
        higher["fingerprint"] = "v1:sha256:fedcba9876543210"
        higher["normalised_severity"] = "critical"

        run = generate_sarif(scan_run(lower, higher))["runs"][0]

        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        self.assertEqual(
            run["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"],
            "error",
        )
        self.assertEqual(
            sorted(result["level"] for result in run["results"]),
            ["error", "note"],
        )

    def test_repository_level_finding_does_not_invent_a_location(self) -> None:
        finding = valid_finding()
        finding.update(
            {
                "file": None,
                "start_line": None,
                "end_line": None,
                "symbol": None,
            }
        )

        result = generate_sarif(scan_run(finding))["runs"][0]["results"][0]

        self.assertNotIn("locations", result)


if __name__ == "__main__":
    unittest.main()
