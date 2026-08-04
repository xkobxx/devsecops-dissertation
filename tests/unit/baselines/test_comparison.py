from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import unittest

from trustgate.baselines import BaselineError, compare_to_baseline, create_baseline
from trustgate.lifecycle import FindingState, transition_finding
from trustgate.scanners.models import ScannerState
from trustgate.schema import validate_instance
from trustgate.schema.documents import build_scan_run

from tests.unit.baselines.test_creation import GENERATED_AT
from tests.unit.schemas.test_documents import scanner_result
from tests.unit.schemas.test_schema_contracts import valid_finding


COMPARED_AT = datetime(2026, 8, 4, 14, 0, tzinfo=timezone.utc)


def finding(
    name: str,
    *,
    severity: str = "high",
    reachability: str = "unknown",
) -> dict[str, object]:
    value = valid_finding()
    value.update(
        {
            "finding_id": f"finding-{name}",
            "fingerprint": f"v2:sha256:{name:0<64}"[:74],
            "normalised_severity": severity,
            "reachability": reachability,
        }
    )
    return value


def scan(
    findings: list[dict[str, object]],
    *,
    ref: str,
    trigger: str,
    commit: str,
) -> dict[str, object]:
    return build_scan_run(
        target=".",
        findings=findings,
        scanner_results=[scanner_result(ScannerState.FINDINGS)],
        repository="example/trustgate",
        ref=ref,
        commit=commit,
        trigger=trigger,
    )


def changed_runs() -> tuple[dict[str, object], dict[str, object]]:
    stable = finding("stable")
    removed = finding("removed", severity="low")
    worsened = finding("worsened", severity="medium")
    reachable = finding("reachable", reachability="unreachable")
    exploited = finding("exploited")
    exploited["dependency"] = {
        "name": "example-lib",
        "version": "1.0.0",
        "ecosystem": "PyPI",
        "purl": "pkg:pypi/example-lib@1.0.0",
        "direct": False,
    }
    exploited["environment"]["public_exploit_availability"] = False
    suppressed = transition_finding(
        finding("suppressed", severity="medium"),
        to_state=FindingState.SUPPRESSED,
        actor="user:developer@example.test",
        reason="Temporary exception.",
        approval={
            "actor": "user:security@example.test",
            "timestamp": "2026-08-01T11:59:00Z",
            "reason": "Approved for two days.",
        },
        changed_at=datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc),
        expires_at=datetime(2026, 8, 3, 0, 0, tzinfo=timezone.utc),
    )

    baseline_scan = scan(
        [stable, removed, worsened, reachable, exploited, suppressed],
        ref="refs/heads/main",
        trigger="push",
        commit="a" * 40,
    )

    current_stable = deepcopy(stable)
    current_worsened = deepcopy(worsened)
    current_worsened["normalised_severity"] = "critical"
    current_reachable = deepcopy(reachable)
    current_reachable["reachability"] = "reachable"
    current_exploited = deepcopy(exploited)
    current_exploited["environment"]["public_exploit_availability"] = True
    current_suppressed = deepcopy(suppressed)
    introduced = finding("introduced", severity="critical")
    current_scan = scan(
        [
            current_stable,
            current_worsened,
            current_reachable,
            current_exploited,
            current_suppressed,
            introduced,
        ],
        ref="refs/pull/42/merge",
        trigger="pull_request",
        commit="b" * 40,
    )
    return baseline_scan, current_scan


class BaselineComparisonTests(unittest.TestCase):
    def test_comparison_classifies_every_finding_transition(self) -> None:
        baseline_scan, current_scan = changed_runs()
        baseline = create_baseline(
            baseline_scan,
            default_branch="main",
            generated_at=GENERATED_AT,
        )
        original = deepcopy(current_scan)

        difference = compare_to_baseline(
            baseline,
            current_scan,
            compared_at=COMPARED_AT,
        )

        validate_instance("baseline-diff", difference)
        self.assertEqual(current_scan, original)
        self.assertEqual(difference["new_findings"], [finding("introduced")["fingerprint"]])
        self.assertEqual(difference["removed_findings"], [finding("removed")["fingerprint"]])
        self.assertEqual(
            difference["worsened_findings"],
            [finding("worsened")["fingerprint"]],
        )
        self.assertEqual(
            difference["newly_reachable_findings"],
            [finding("reachable")["fingerprint"]],
        )
        self.assertEqual(
            difference["newly_exploited_dependencies"],
            [finding("exploited")["fingerprint"]],
        )
        self.assertEqual(
            difference["expired_suppressions"],
            [finding("suppressed")["fingerprint"]],
        )
        self.assertEqual(difference["summary"]["new_findings"], 1)
        self.assertEqual(difference["summary"]["removed_findings"], 1)
        self.assertEqual(difference["baseline_age_seconds"], 172800.0)
        self.assertRegex(
            difference["comparison_digest"],
            r"^sha256:[0-9a-f]{64}$",
        )

    def test_comparison_is_deterministic_for_identical_inputs(self) -> None:
        baseline_scan, current_scan = changed_runs()
        baseline = create_baseline(
            baseline_scan,
            default_branch="main",
            generated_at=GENERATED_AT,
        )

        first = compare_to_baseline(baseline, current_scan, compared_at=COMPARED_AT)
        second = compare_to_baseline(baseline, current_scan, compared_at=COMPARED_AT)

        self.assertEqual(first, second)

    def test_comparison_rejects_wrong_repository_and_non_pull_request(self) -> None:
        baseline_scan, current_scan = changed_runs()
        baseline = create_baseline(
            baseline_scan,
            default_branch="main",
            generated_at=GENERATED_AT,
        )
        wrong_repository = deepcopy(current_scan)
        wrong_repository["repository"] = "example/other"
        wrong_trigger = deepcopy(current_scan)
        wrong_trigger["trigger"] = "push"

        with self.assertRaisesRegex(BaselineError, "repository"):
            compare_to_baseline(baseline, wrong_repository)
        with self.assertRaisesRegex(BaselineError, "pull-request"):
            compare_to_baseline(baseline, wrong_trigger)


if __name__ == "__main__":
    unittest.main()
