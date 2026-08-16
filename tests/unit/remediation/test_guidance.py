from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import unittest

from tests.unit.schemas.test_documents import scanner_result
from tests.unit.schemas.test_schema_contracts import valid_finding
from trustgate.remediation import RemediationError, generate_guidance
from trustgate.scanners.models import ScannerState
from trustgate.schema import build_scan_run, validate_instance


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def sql_scan_run() -> dict[str, object]:
    return build_scan_run(
        target=".",
        findings=[valid_finding()],
        scanner_results=[scanner_result(ScannerState.FINDINGS)],
        repository="example/service",
        ref="refs/heads/main",
        commit="a" * 40,
        trigger="push",
    )


def guidance_request(scan_run: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "revision": 2,
        "generated_at": "2026-08-04T16:00:00Z",
        "run_id": scan_run["run_id"],
        "scan_run_digest": _digest(scan_run),
        "guidance": [
            {
                "finding_fingerprint": "v1:sha256:0123456789abcdef",
                "remediation_rule_id": "TG-PY-SQL-001",
                "framework": "python-sqlite3",
            }
        ],
    }


class GuidedRemediationTests(unittest.TestCase):
    def test_generates_complete_deterministic_guidance_for_finding(self) -> None:
        scan_run = sql_scan_run()
        request = guidance_request(scan_run)

        first = generate_guidance(scan_run, request)
        second = generate_guidance(scan_run, request)

        self.assertEqual(first, second)
        validate_instance("remediation-guidance", first)
        self.assertRegex(first["guidance_id"], r"^guidance-[0-9a-f]{24}$")
        self.assertRegex(first["guidance_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(first["revision"], 2)
        self.assertEqual(first["repository"], "example/service")
        self.assertEqual(first["commit"], "a" * 40)
        self.assertEqual(
            first["limitations"],
            [
                "Guidance does not modify source code.",
                "Guidance is not proof that a finding is fixed.",
                "Verification must use repository tests and relevant scanners.",
            ],
        )
        entry = first["entries"][0]
        self.assertEqual(entry["status"], "guidance_only")
        self.assertEqual(entry["finding_id"], "finding-001")
        self.assertEqual(entry["scanner_rule_id"], "python.lang.security.audit.sqli")
        self.assertEqual(entry["remediation_rule_id"], "TG-PY-SQL-001")
        self.assertEqual(entry["framework"], "python-sqlite3")
        self.assertIn("untrusted", entry["why_vulnerable"].lower())
        self.assertIn("query", entry["exploit_scenario"].lower())
        self.assertEqual(
            entry["relevant_flow"],
            {
                "source": "request.args['q']",
                "source_evidence": "finding.source",
                "sink": "cursor.execute",
                "sink_evidence": "finding.sink",
            },
        )
        self.assertIn("placeholder", entry["secure_coding_pattern"].lower())
        self.assertIn("cursor.execute", entry["framework_specific_example"])
        self.assertEqual(
            entry["cwe_references"],
            [
                {
                    "id": "CWE-89",
                    "url": "https://cwe.mitre.org/data/definitions/89.html",
                }
            ],
        )
        self.assertTrue(entry["testing_guidance"])
        self.assertTrue(entry["regression_risks"])
        self.assertIn(
            "Rerun the scanner rule that produced the original finding.",
            entry["verification_instructions"],
        )

    def test_missing_flow_is_reported_as_unknown_not_invented(self) -> None:
        scan_run = sql_scan_run()
        scan_run["findings"][0]["source"] = None
        scan_run["findings"][0]["sink"] = None
        request = guidance_request(scan_run)
        request["scan_run_digest"] = _digest(scan_run)

        report = generate_guidance(scan_run, request)

        self.assertEqual(
            report["entries"][0]["relevant_flow"],
            {
                "source": "unknown",
                "source_evidence": "not_available",
                "sink": "unknown",
                "sink_evidence": "not_available",
            },
        )

    def test_rejects_stale_scan_binding_and_framework_mismatch(self) -> None:
        scan_run = sql_scan_run()
        stale = guidance_request(scan_run)
        stale["scan_run_digest"] = "sha256:" + "0" * 64

        with self.assertRaisesRegex(RemediationError, "scan-run content"):
            generate_guidance(scan_run, stale)

        mismatch = guidance_request(scan_run)
        mismatch["guidance"][0]["framework"] = "python-pyyaml"
        with self.assertRaisesRegex(RemediationError, "requires framework"):
            generate_guidance(scan_run, mismatch)

    def test_rejects_unknown_finding_and_inapplicable_cwe(self) -> None:
        scan_run = sql_scan_run()
        unknown = guidance_request(scan_run)
        unknown["guidance"][0]["finding_fingerprint"] = "v1:sha256:missing"

        with self.assertRaisesRegex(RemediationError, "unknown finding"):
            generate_guidance(scan_run, unknown)

        unrelated_scan = deepcopy(scan_run)
        unrelated_scan["findings"][0]["cwe"] = ["CWE-79"]
        inapplicable = guidance_request(unrelated_scan)
        with self.assertRaisesRegex(RemediationError, "not applicable"):
            generate_guidance(unrelated_scan, inapplicable)


if __name__ == "__main__":
    unittest.main()
