from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.unit.lifecycle.test_suppressions import valid_suppression
from tests.unit.vex.test_generation import (
    analysis_document,
    dependency_scan_run,
)
from trustgate.baselines import create_baseline
from trustgate.evidence import (
    EvidenceError,
    EvidenceIntegrityError,
    generate_audit_evidence,
    verify_audit_evidence,
)
from trustgate.schema import build_policy_result, validate_instance
from trustgate.vex import generate_vex


GENERATED_AT = datetime(2026, 8, 4, 13, 0, tzinfo=timezone.utc)


def _write(root: Path, relative: str, value: object) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def evidence_fixture(root: Path) -> dict[str, object]:
    scan_run = dependency_scan_run()
    scan_run["findings"][0]["threat_intelligence"] = {
        "advisory_ids": ["CVE-2026-1234"],
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L",
        "epss_probability": 0.42,
        "epss_percentile": 0.91,
        "kev_status": False,
        "known_exploitation_date": None,
        "ransomware_association": None,
        "fixed_versions": ["1.2.4"],
        "published_date": "2026-08-01T00:00:00Z",
        "modified_date": "2026-08-03T00:00:00Z",
        "data_source_timestamp": "2026-08-04T11:30:00Z",
        "network_mode": "metadata-only",
        "stale": False,
        "risk_context_complete": False,
        "limitations": ["Threat intelligence is incomplete risk context."],
        "sources": [
            {
                "source": "osv",
                "status": "fresh-cache",
                "fetched_at": "2026-08-04T11:30:00Z",
                "expires_at": "2026-08-05T11:30:00Z",
                "stale": False,
                "identifiers_sent": [],
            }
        ],
        "failures": [],
    }
    policy_result = build_policy_result(
        scan_run,
        fail_on="high",
        scanner_failure_policy="fail",
        evaluated_at=GENERATED_AT,
    )
    baseline_source = deepcopy(scan_run)
    baseline_source["ref"] = "refs/heads/main"
    baseline = create_baseline(
        baseline_source,
        default_branch="main",
        generated_at=GENERATED_AT,
    )
    vex = generate_vex(scan_run, analysis_document(scan_run))

    _write(root, "reports/scan-run.json", scan_run)
    _write(
        root,
        "reports/scan-configuration.json",
        {"required_scanners": ["semgrep"], "fail_on": "high"},
    )
    _write(root, "reports/policy-result.json", policy_result)
    _write(root, "reports/baseline.json", baseline)
    _write(root, "reports/suppressions/approved.json", valid_suppression())
    _write(
        root,
        "reports/approvals/vex-review.json",
        {
            "actor": "user:security@example.test",
            "timestamp": "2026-08-04T12:45:00Z",
            "reason": "VEX and reachability evidence reviewed.",
        },
    )
    _write(
        root,
        "release/trustgate.cdx.json",
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1},
    )
    _write(
        root,
        "release/trustgate.spdx.json",
        {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"},
    )
    _write(root, "release/trustgate.vex.cdx.json", vex)
    _write(root, "release/provenance.json", {"predicateType": "slsa"})
    _write(root, "release/attestation.json", {"verificationMaterial": {}})
    _write(
        root,
        "reports/exclusions.json",
        {"tests/fixtures/**": "benchmark corpus", "vendor/**": "vendored"},
    )
    _write(
        root,
        "compliance/change-approval.json",
        {"ticket": "CAB-42", "approved": True},
    )
    return {
        "schema_version": "1.0.0",
        "generated_at": "2026-08-04T13:00:00Z",
        "workflow_identity": (
            "https://github.com/example/service/.github/workflows/"
            "security.yml@refs/heads/main"
        ),
        "scan_run": "reports/scan-run.json",
        "scan_configuration": "reports/scan-configuration.json",
        "policy_result": "reports/policy-result.json",
        "baseline": "reports/baseline.json",
        "suppressions": ["reports/suppressions/approved.json"],
        "approvals": ["reports/approvals/vex-review.json"],
        "sboms": [
            "release/trustgate.cdx.json",
            "release/trustgate.spdx.json",
        ],
        "vex": "release/trustgate.vex.cdx.json",
        "provenance": ["release/provenance.json"],
        "attestations": ["release/attestation.json"],
        "exclusions": "reports/exclusions.json",
        "manual_requirements": [
            {
                "id": "change-approval",
                "requirement": "Confirm production change-board approval.",
                "owner": "release-management",
                "status": "complete",
                "evidence": ["compliance/change-approval.json"],
            }
        ],
    }


class AuditEvidenceGenerationTests(unittest.TestCase):
    def test_generates_complete_deterministic_and_verifiable_manifest(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = evidence_fixture(root)

            first = generate_audit_evidence(root, config)
            second = generate_audit_evidence(root, config)

            self.assertEqual(first, second)
            validate_instance("audit-evidence", first)
            self.assertRegex(first["evidence_id"], r"^audit-evidence-[0-9a-f]{24}$")
            self.assertRegex(first["evidence_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(
                first["subject"],
                {
                    "repository": "example/service",
                    "commit": "1" * 40,
                    "ref": "refs/heads/main",
                    "workflow_identity": config["workflow_identity"],
                },
            )
            automated = first["automated_evidence"]
            self.assertEqual(
                automated["scan"]["scanners"],
                [
                    {
                        "scanner": "semgrep",
                        "version": "1.125.0",
                        "state": "FINDINGS",
                        "healthy": True,
                        "required": True,
                    }
                ],
            )
            self.assertEqual(automated["scan"]["findings"]["count"], 1)
            self.assertEqual(automated["scan"]["exclusions"]["count"], 2)
            self.assertEqual(automated["policy"]["gate_result"], "fail")
            self.assertEqual(automated["baseline"]["version"], 1)
            self.assertEqual(automated["suppressions"]["count"], 1)
            self.assertGreaterEqual(automated["approvals"]["count"], 2)
            self.assertEqual(len(automated["supply_chain"]["sboms"]), 2)
            self.assertEqual(len(automated["provenance"]), 1)
            self.assertEqual(len(automated["attestations"]), 1)
            self.assertEqual(
                automated["data_source_timestamps"],
                [
                    {
                        "finding_fingerprint": "v2:sha256:" + "a" * 64,
                        "source": "osv",
                        "timestamp": "2026-08-04T11:30:00Z",
                    },
                    {
                        "finding_fingerprint": "v2:sha256:" + "a" * 64,
                        "source": "aggregate",
                        "timestamp": "2026-08-04T11:30:00Z",
                    },
                ],
            )
            self.assertEqual(
                first["manual_compliance_requirements"][0]["status"],
                "complete",
            )
            self.assertEqual(
                {artifact["evidence_source"] for artifact in first["artifacts"]},
                {"automated", "manual"},
            )
            verify_audit_evidence(root, first)

    def test_verification_detects_artifact_and_manifest_tampering(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = generate_audit_evidence(root, evidence_fixture(root))
            (root / "reports/scan-run.json").write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(EvidenceIntegrityError, "scan-run.json"):
                verify_audit_evidence(root, manifest)

            manifest["subject"]["repository"] = "attacker/repository"
            with self.assertRaisesRegex(EvidenceIntegrityError, "manifest digest"):
                verify_audit_evidence(root, manifest)

    def test_rejects_path_escape_and_inconsistent_run_identity(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = evidence_fixture(root)
            config["scan_configuration"] = "../outside.json"

            with self.assertRaisesRegex(EvidenceError, "within evidence root"):
                generate_audit_evidence(root, config)

            config = evidence_fixture(root)
            policy = json.loads(
                (root / "reports/policy-result.json").read_text(encoding="utf-8")
            )
            policy["run_id"] = "run-unrelated"
            _write(root, "reports/policy-result.json", policy)

            with self.assertRaisesRegex(EvidenceError, "policy result run_id"):
                generate_audit_evidence(root, config)


if __name__ == "__main__":
    unittest.main()
