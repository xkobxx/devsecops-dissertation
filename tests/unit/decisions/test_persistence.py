from __future__ import annotations

import copy
import unittest

from trustgate.decisions.service import evaluate_scan_run
from trustgate.schema import validate_instance

from tests.unit.schemas.test_schema_contracts import valid_finding


def scan_run() -> dict[str, object]:
    finding = valid_finding()
    finding["confidence"] = 0.95
    return {
        "schema_version": "1.0.0",
        "run_id": "run-decision-test",
        "status": "complete",
        "started_at": "2026-08-02T12:00:00Z",
        "ended_at": "2026-08-02T12:00:01Z",
        "duration_seconds": 1.0,
        "target": ".",
        "repository": "example/trustgate",
        "ref": "refs/heads/main",
        "commit": "abcdef1234567",
        "trigger": "local",
        "scanners": [],
        "findings": [finding],
        "summary": {
            "total_findings": 1,
            "required_scanners": 0,
            "healthy_scanners": 0,
            "severity_counts": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0,
                "unknown": 0,
            },
            "scanner_state_counts": {
                "CLEAN": 0,
                "FINDINGS": 0,
                "FAILED_SCANNER": 0,
                "PARTIAL": 0,
                "SKIPPED": 0,
            },
        },
        "errors": [],
    }


def runtime_context() -> dict[str, object]:
    return {
        "runtime_environment": "production",
        "internet_exposure": True,
        "authentication_requirements": False,
        "data_sensitivity": "restricted",
        "asset_criticality": "critical",
        "existing_controls": ["waf"],
        "public_exploit_availability": False,
        "cisa_kev": True,
        "epss": 0.9,
        "fix_availability": True,
        "new_existing_status": "new",
    }


class DecisionPersistenceTests(unittest.TestCase):
    def test_scan_run_persists_validated_decisions_and_summary(self) -> None:
        source = scan_run()

        evaluated = evaluate_scan_run(
            source,
            runtime_context=runtime_context(),
        )

        self.assertNotEqual(id(evaluated), id(source))
        self.assertNotIn("contextual_decision", source["findings"][0])
        decision = evaluated["findings"][0]["contextual_decision"]
        validate_instance("decision", decision)
        validate_instance("scan-run", evaluated)
        self.assertEqual(decision["outcome"], "BLOCK_IMMEDIATELY")
        self.assertEqual(
            evaluated["summary"]["decision_analysis"]["outcome_counts"]["BLOCK_IMMEDIATELY"],
            1,
        )
        self.assertEqual(
            evaluated["summary"]["decision_analysis"]["policy_version"],
            "1.0.0",
        )

    def test_per_finding_runtime_context_overrides_shared_context(self) -> None:
        source = scan_run()
        shared = runtime_context()
        shared["runtime_environment"] = "staging"

        evaluated = evaluate_scan_run(
            copy.deepcopy(source),
            runtime_context=shared,
            finding_contexts={
                "finding-001": {"runtime_environment": "production"}
            },
        )

        decision = evaluated["findings"][0]["contextual_decision"]
        self.assertEqual(
            decision["context"]["components"]["runtime_environment"]["value"],
            "production",
        )


if __name__ == "__main__":
    unittest.main()
