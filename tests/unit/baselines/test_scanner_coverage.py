from __future__ import annotations

from copy import deepcopy
import unittest

from trustgate.baselines import compare_to_baseline, create_baseline

from tests.unit.baselines.test_comparison import COMPARED_AT, changed_runs
from tests.unit.baselines.test_creation import GENERATED_AT
from tests.unit.schemas.test_schema_contracts import zero_scanner_state_counts


class ScannerCoverageComparisonTests(unittest.TestCase):
    def baseline_and_current(self) -> tuple[dict[str, object], dict[str, object]]:
        baseline_scan, current_scan = changed_runs()
        baseline = create_baseline(
            baseline_scan,
            default_branch="main",
            generated_at=GENERATED_AT,
        )
        return baseline, current_scan

    def test_missing_previously_healthy_scanner_is_a_coverage_regression(self) -> None:
        baseline, current = self.baseline_and_current()
        current["scanners"] = []
        current["summary"]["required_scanners"] = 0
        current["summary"]["healthy_scanners"] = 0
        current["summary"]["scanner_state_counts"] = zero_scanner_state_counts()

        difference = compare_to_baseline(
            baseline,
            current,
            compared_at=COMPARED_AT,
        )

        self.assertEqual(
            difference["scanner_coverage_regressions"],
            [
                {
                    "scanner": "semgrep",
                    "baseline_state": "FINDINGS",
                    "current_state": None,
                    "reason": "previously healthy scanner is missing",
                }
            ],
        )
        self.assertEqual(
            difference["summary"]["scanner_coverage_regressions"],
            1,
        )

    def test_unhealthy_scanner_is_a_coverage_regression(self) -> None:
        baseline, current = self.baseline_and_current()
        current = deepcopy(current)
        scanner = current["scanners"][0]
        scanner.update(
            {
                "state": "FAILED_SCANNER",
                "healthy": False,
                "exit_code": 2,
                "parser_status": "FAILED",
                "error": "scanner failed",
            }
        )
        current["summary"]["healthy_scanners"] = 0
        states = zero_scanner_state_counts()
        states["FAILED_SCANNER"] = 1
        current["summary"]["scanner_state_counts"] = states

        difference = compare_to_baseline(
            baseline,
            current,
            compared_at=COMPARED_AT,
        )

        self.assertEqual(
            difference["scanner_coverage_regressions"][0]["scanner"],
            "semgrep",
        )
        self.assertEqual(
            difference["scanner_coverage_regressions"][0]["current_state"],
            "FAILED_SCANNER",
        )
        self.assertIn(
            "unhealthy",
            difference["scanner_coverage_regressions"][0]["reason"],
        )


if __name__ == "__main__":
    unittest.main()
