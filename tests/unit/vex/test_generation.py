from __future__ import annotations

import hashlib
import json
import unittest

import trustgate.vex as vex_module
from tests.unit.schemas.test_documents import scanner_result
from tests.unit.schemas.test_schema_contracts import valid_finding
from trustgate.scanners.models import ScannerState
from trustgate.schema import build_scan_run


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def dependency_scan_run() -> dict[str, object]:
    finding = valid_finding()
    finding.update(
        {
            "finding_id": "finding-cve-2026-1234",
            "fingerprint": "v2:sha256:" + "a" * 64,
            "category": "dependency",
            "cve": ["CVE-2026-1234"],
            "file": "requirements/runtime.lock",
            "dependency": {
                "name": "demo",
                "version": "1.2.3",
                "ecosystem": "PyPI",
                "purl": "pkg:pypi/demo@1.2.3",
                "direct": False,
            },
            "dependency_scope": "runtime",
            "reachability": "unreachable",
            "dependency_reachability": {
                "status": "NO_PATH_FOUND",
                "package_installed": True,
                "dependency_relationship": "transitive",
                "imported": False,
                "vulnerable_symbol_called": False,
                "dependency_scope": "runtime",
                "included_in_deployed_artifact": True,
                "call_path_exists": False,
                "analysis_incomplete": False,
                "dynamic_behaviour_unknown": True,
                "analysed_call_path": [],
                "analysed_files": ["src/app.py"],
                "limitations": [
                    "No static path is not proof that exploitation is impossible."
                ],
                "explanation": "No supported import or call path was found.",
            },
        }
    )
    return build_scan_run(
        target=".",
        findings=[finding],
        scanner_results=[scanner_result(ScannerState.FINDINGS)],
        repository="example/service",
        ref="refs/heads/main",
        commit="1" * 40,
        trigger="push",
    )


def analysis_document(scan_run: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "revision": 3,
        "run_id": scan_run["run_id"],
        "scan_run_digest": _digest(scan_run),
        "generated_at": "2026-08-04T12:00:00Z",
        "analyses": [
            {
                "finding_fingerprint": "v2:sha256:" + "a" * 64,
                "vulnerability_id": "CVE-2026-1234",
                "exploitability_status": "not_affected",
                "analysis_state": "not_affected",
                "justification": "code_not_reachable",
                "detail": (
                    "A reviewed local analysis found no supported call path; "
                    "the recorded limitations still apply."
                ),
                "approval": {
                    "actor": "user:security@example.test",
                    "timestamp": "2026-08-04T11:55:00Z",
                    "reason": "Reachability evidence and limitations reviewed.",
                },
            }
        ],
    }


class VexGenerationTests(unittest.TestCase):
    def test_generates_deterministic_approved_cyclonedx_vex(self) -> None:
        scan_run = dependency_scan_run()
        analyses = analysis_document(scan_run)
        generate_vex = vex_module.generate_vex

        first = generate_vex(scan_run, analyses)
        second = generate_vex(scan_run, analyses)

        self.assertEqual(first, second)
        self.assertEqual(first["bomFormat"], "CycloneDX")
        self.assertEqual(first["specVersion"], "1.6")
        self.assertEqual(first["version"], 3)
        self.assertEqual(
            first["components"],
            [
                {
                    "type": "library",
                    "bom-ref": "pkg:pypi/demo@1.2.3",
                    "name": "demo",
                    "version": "1.2.3",
                    "purl": "pkg:pypi/demo@1.2.3",
                }
            ],
        )
        vulnerability = first["vulnerabilities"][0]
        self.assertEqual(vulnerability["id"], "CVE-2026-1234")
        self.assertEqual(vulnerability["analysis"]["state"], "not_affected")
        self.assertEqual(
            vulnerability["analysis"]["justification"], "code_not_reachable"
        )
        self.assertEqual(
            vulnerability["affects"],
            [
                {
                    "ref": "pkg:pypi/demo@1.2.3",
                    "versions": [{"version": "1.2.3", "status": "unaffected"}],
                }
            ],
        )
        properties = {
            property_["name"]: property_["value"]
            for property_ in vulnerability["properties"]
        }
        self.assertEqual(
            properties["trustgate:vex:exploitability-status"], "not_affected"
        )
        self.assertEqual(properties["trustgate:reachability:status"], "NO_PATH_FOUND")
        self.assertRegex(
            properties["trustgate:reachability:evidence-digest"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertRegex(
            properties["trustgate:approval:digest"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertNotIn("security@example.test", json.dumps(first))

    def test_rejects_code_not_reachable_when_evidence_confirms_a_path(self) -> None:
        scan_run = dependency_scan_run()
        finding = scan_run["findings"][0]
        finding["reachability"] = "reachable"
        finding["dependency_reachability"].update(
            {
                "status": "CONFIRMED_REACHABLE",
                "imported": True,
                "vulnerable_symbol_called": True,
                "call_path_exists": True,
            }
        )
        analyses = analysis_document(scan_run)

        with self.assertRaisesRegex(
            vex_module.VexError,
            "code_not_reachable conflicts with confirmed reachability evidence",
        ):
            vex_module.generate_vex(scan_run, analyses)

    def test_rejects_an_analysis_bound_to_stale_scan_content(self) -> None:
        scan_run = dependency_scan_run()
        analyses = analysis_document(scan_run)
        scan_run["findings"][0]["last_seen"] = "2026-08-04T12:01:00Z"

        with self.assertRaisesRegex(
            vex_module.VexError, "scan_run_digest does not match"
        ):
            vex_module.generate_vex(scan_run, analyses)

    def test_rejects_a_decision_without_a_complete_approval(self) -> None:
        scan_run = dependency_scan_run()
        analyses = analysis_document(scan_run)
        del analyses["analyses"][0]["approval"]["reason"]

        with self.assertRaisesRegex(vex_module.VexError, "complete approval"):
            vex_module.generate_vex(scan_run, analyses)

    def test_rejects_a_decision_without_reachability_evidence(self) -> None:
        scan_run = dependency_scan_run()
        del scan_run["findings"][0]["dependency_reachability"]
        analyses = analysis_document(scan_run)

        with self.assertRaisesRegex(
            vex_module.VexError, "no dependency reachability evidence"
        ):
            vex_module.generate_vex(scan_run, analyses)


if __name__ == "__main__":
    unittest.main()
