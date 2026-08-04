from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import unittest

from trustgate.baselines import (
    BaselineError,
    BaselineIntegrityError,
    create_baseline,
    verify_baseline,
)
from trustgate.scanners.models import ScannerState
from trustgate.schema import validate_instance
from trustgate.schema.documents import build_scan_run

from tests.unit.schemas.test_documents import scanner_result
from tests.unit.schemas.test_schema_contracts import valid_finding


GENERATED_AT = datetime(2026, 8, 2, 14, 0, tzinfo=timezone.utc)


def default_branch_scan() -> dict[str, object]:
    return build_scan_run(
        target=".",
        findings=[valid_finding()],
        scanner_results=[scanner_result(ScannerState.FINDINGS)],
        repository="example/trustgate",
        ref="refs/heads/main",
        commit="a" * 40,
        trigger="push",
    )


class BaselineCreationTests(unittest.TestCase):
    def test_default_branch_scan_becomes_immutable_fingerprint_index(self) -> None:
        source = default_branch_scan()
        original = deepcopy(source)

        baseline = create_baseline(
            source,
            default_branch="main",
            generated_at=GENERATED_AT,
        )

        validate_instance("baseline", baseline)
        self.assertEqual(source, original)
        self.assertEqual(baseline["repository"], "example/trustgate")
        self.assertEqual(baseline["default_branch"], "main")
        self.assertEqual(baseline["ref"], "refs/heads/main")
        self.assertEqual(baseline["commit"], "a" * 40)
        self.assertEqual(
            set(baseline["findings"]),
            {"v1:sha256:0123456789abcdef"},
        )
        self.assertEqual(
            baseline["findings"]["v1:sha256:0123456789abcdef"]["finding_id"],
            "finding-001",
        )
        self.assertEqual(set(baseline["scanners"]), {"semgrep"})
        self.assertRegex(baseline["baseline_digest"], r"^sha256:[0-9a-f]{64}$")
        verify_baseline(baseline)

    def test_generation_rejects_non_default_branch_and_missing_identity(self) -> None:
        feature = default_branch_scan()
        feature["ref"] = "refs/heads/feature/risk"
        missing_repository = default_branch_scan()
        missing_repository["repository"] = None

        with self.assertRaisesRegex(BaselineError, "default branch"):
            create_baseline(feature, default_branch="main")
        with self.assertRaisesRegex(BaselineError, "repository"):
            create_baseline(missing_repository, default_branch="main")

    def test_duplicate_fingerprints_are_rejected(self) -> None:
        scan_run = default_branch_scan()
        duplicate = deepcopy(scan_run["findings"][0])
        duplicate["finding_id"] = "finding-duplicate"
        scan_run["findings"].append(duplicate)
        scan_run["summary"]["total_findings"] = 2
        scan_run["summary"]["severity_counts"]["high"] = 2

        with self.assertRaisesRegex(BaselineError, "duplicate fingerprint"):
            create_baseline(scan_run, default_branch="main")

    def test_tampering_breaks_baseline_integrity(self) -> None:
        baseline = create_baseline(
            default_branch_scan(),
            default_branch="main",
            generated_at=GENERATED_AT,
        )
        baseline["findings"]["v1:sha256:0123456789abcdef"][
            "normalised_severity"
        ] = "low"

        with self.assertRaisesRegex(BaselineIntegrityError, "digest"):
            verify_baseline(baseline)


if __name__ == "__main__":
    unittest.main()
