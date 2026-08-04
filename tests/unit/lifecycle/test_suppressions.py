"""Behavior tests for scoped, auditable finding suppressions."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import unittest

from trustgate.lifecycle import (
    SuppressionError,
    SuppressionScopeError,
    apply_suppression,
    create_suppression,
    lint_suppression,
    revalidate_suppression,
)
from trustgate.schema import validate_instance

from tests.unit.schemas.test_schema_contracts import valid_finding


CREATED_AT = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)
EXPIRES_AT = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
POLICY_DIGEST = "sha256:" + "a" * 64


def valid_suppression(
    finding: dict[str, object] | None = None,
    *,
    expires_at: datetime | None = EXPIRES_AT,
    allow_permanent: bool = False,
) -> dict[str, object]:
    return create_suppression(
        finding or valid_finding(),
        repository="example/service",
        reason="Compensating control is deployed during the upgrade window.",
        author="user:developer@example.test",
        created_at=CREATED_AT,
        expires_at=expires_at,
        scope={
            "branches": ["main", "release/*"],
            "paths": ["src/**"],
            "environments": ["production"],
        },
        approval={
            "actor": "user:security@example.test",
            "timestamp": "2026-08-03T11:59:00Z",
            "reason": "Approved for seven days.",
        },
        evidence=[
            {
                "kind": "ticket",
                "reference": "SEC-44",
                "summary": "Upgrade and rollback plan reviewed.",
            }
        ],
        policy_digest=POLICY_DIGEST,
        allow_permanent=allow_permanent,
    )


def suppress_finding(
    finding: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    suppression = valid_suppression(finding)
    suppressed = apply_suppression(
        finding,
        suppression,
        repository="example/service",
        ref="main",
        environment="production",
        changed_at=CREATED_AT,
    )
    return suppression, suppressed


def threat_intelligence(kev_status: bool | None) -> dict[str, object]:
    return {
        "advisory_ids": [],
        "cvss_score": None,
        "cvss_vector": None,
        "epss_probability": None,
        "epss_percentile": None,
        "kev_status": kev_status,
        "known_exploitation_date": None,
        "ransomware_association": None,
        "fixed_versions": [],
        "published_date": None,
        "modified_date": None,
        "data_source_timestamp": None,
        "network_mode": "disabled",
        "stale": False,
        "risk_context_complete": False,
        "limitations": ["Threat intelligence is not complete risk context."],
        "sources": [],
        "failures": [],
    }


class SuppressionCreationTests(unittest.TestCase):
    def test_create_records_complete_content_bound_suppression(self) -> None:
        finding = valid_finding()

        suppression = create_suppression(
            finding,
            repository="example/service",
            reason="Compensating control is deployed during the upgrade window.",
            author="user:developer@example.test",
            created_at=CREATED_AT,
            expires_at=EXPIRES_AT,
            scope={
                "branches": ["main", "release/*"],
                "paths": ["src/**"],
                "environments": ["production"],
            },
            approval={
                "actor": "user:security@example.test",
                "timestamp": "2026-08-03T11:59:00Z",
                "reason": "Approved for seven days.",
            },
            evidence=[
                {
                    "kind": "ticket",
                    "reference": "SEC-44",
                    "summary": "Upgrade and rollback plan reviewed.",
                }
            ],
            policy_digest=POLICY_DIGEST,
        )

        self.assertNotIn("suppression", finding)
        self.assertEqual(suppression["finding_fingerprint"], finding["fingerprint"])
        self.assertEqual(suppression["author"], "user:developer@example.test")
        self.assertEqual(suppression["created_at"], "2026-08-03T12:00:00+00:00")
        self.assertEqual(suppression["expires_at"], "2026-08-10T12:00:00+00:00")
        self.assertEqual(suppression["scope"]["repository"], "example/service")
        self.assertEqual(suppression["revalidation_rule"]["reachability"], "reachable")
        self.assertEqual(suppression["revalidation_rule"]["policy_digest"], POLICY_DIGEST)
        self.assertTrue(suppression["suppression_id"].startswith("suppression-"))
        self.assertTrue(suppression["suppression_digest"].startswith("sha256:"))
        validate_instance("suppression", suppression)

    def test_permanent_suppression_is_rejected_by_default(self) -> None:
        with self.assertRaisesRegex(
            SuppressionError,
            "permanent suppressions require explicit authorization",
        ):
            create_suppression(
                valid_finding(),
                repository="example/service",
                reason="No expiry was provided.",
                author="user:developer@example.test",
                created_at=CREATED_AT,
                expires_at=None,
                scope={},
                approval={
                    "actor": "user:security@example.test",
                    "timestamp": "2026-08-03T11:59:00Z",
                    "reason": "Reviewed by security.",
                },
                evidence=[
                    {
                        "kind": "ticket",
                        "reference": "SEC-45",
                        "summary": "Exception request.",
                    }
                ],
                policy_digest=POLICY_DIGEST,
            )

    def test_approval_must_precede_suppression_creation(self) -> None:
        with self.assertRaisesRegex(
            SuppressionError,
            "approval cannot follow creation",
        ):
            create_suppression(
                valid_finding(),
                repository="example/service",
                reason="Approval was recorded too late.",
                author="user:developer@example.test",
                created_at=CREATED_AT,
                expires_at=EXPIRES_AT,
                scope={},
                approval={
                    "actor": "user:security@example.test",
                    "timestamp": "2026-08-03T12:01:00Z",
                    "reason": "Late approval.",
                },
                evidence=[
                    {
                        "kind": "ticket",
                        "reference": "SEC-46",
                        "summary": "Approval ordering test.",
                    }
                ],
                policy_digest=POLICY_DIGEST,
            )

    def test_scope_selectors_must_be_explicit_arrays(self) -> None:
        with self.assertRaisesRegex(
            SuppressionError,
            "scope branches must be an array of non-empty strings",
        ):
            create_suppression(
                valid_finding(),
                repository="example/service",
                reason="Invalid scope.",
                author="user:developer@example.test",
                created_at=CREATED_AT,
                expires_at=EXPIRES_AT,
                scope={"branches": "main"},
                approval={
                    "actor": "user:security@example.test",
                    "timestamp": "2026-08-03T11:59:00Z",
                    "reason": "Reviewed by security.",
                },
                evidence=[
                    {
                        "kind": "ticket",
                        "reference": "SEC-48",
                        "summary": "Scope validation test.",
                    }
                ],
                policy_digest=POLICY_DIGEST,
            )


class SuppressionApplicationTests(unittest.TestCase):
    def test_apply_exact_scope_appends_auditable_suppressed_state(self) -> None:
        finding = valid_finding()
        suppression = valid_suppression(finding)

        suppressed = apply_suppression(
            finding,
            suppression,
            repository="example/service",
            ref="main",
            environment="production",
            changed_at=CREATED_AT,
        )

        self.assertEqual(finding["status"], "open")
        self.assertEqual(suppressed["status"], "suppressed")
        transition = suppressed["state_history"][-1]
        self.assertEqual(transition["actor"], suppression["author"])
        self.assertEqual(transition["approval"], suppression["approval"])
        self.assertEqual(transition["expires_at"], suppression["expires_at"])
        self.assertEqual(
            transition["evidence"][-1],
            {
                "kind": "suppression",
                "reference": suppression["suppression_id"],
                "summary": "Applied content-bound suppression record.",
            },
        )
        validate_instance("finding", suppressed)

    def test_stale_suppression_cannot_apply_after_finding_context_changes(self) -> None:
        finding = valid_finding()
        finding["code_region_hash"] = "region-before"
        suppression = valid_suppression(finding)
        changed = deepcopy(finding)
        changed["code_region_hash"] = "region-after"

        with self.assertRaisesRegex(
            SuppressionError,
            "revalidation context changed before application",
        ):
            apply_suppression(
                changed,
                suppression,
                repository="example/service",
                ref="main",
                environment="production",
                changed_at=CREATED_AT,
            )

    def test_suppression_cannot_apply_before_its_creation(self) -> None:
        finding = valid_finding()
        suppression = valid_suppression(finding)

        with self.assertRaisesRegex(
            SuppressionError,
            "cannot be applied before its creation",
        ):
            apply_suppression(
                finding,
                suppression,
                repository="example/service",
                ref="main",
                environment="production",
                changed_at=datetime(2026, 8, 3, 11, 59, tzinfo=timezone.utc),
            )

    def test_suppression_cannot_apply_to_an_unrelated_finding_or_scope(self) -> None:
        finding = valid_finding()
        other = deepcopy(finding)
        other["fingerprint"] = "v2:sha256:" + "b" * 64
        unrelated = valid_suppression(other)

        cases = (
            (unrelated, "example/service", "main", "production"),
            (valid_suppression(finding), "other/service", "main", "production"),
            (valid_suppression(finding), "example/service", "feature/x", "production"),
            (valid_suppression(finding), "example/service", "main", "staging"),
        )
        for suppression, repository, ref, environment in cases:
            with self.subTest(
                repository=repository,
                ref=ref,
                environment=environment,
            ), self.assertRaisesRegex(
                SuppressionScopeError,
                "does not match",
            ):
                apply_suppression(
                    finding,
                    suppression,
                    repository=repository,
                    ref=ref,
                    environment=environment,
                    changed_at=CREATED_AT,
                )

        self.assertEqual(finding["status"], "open")


class SuppressionLintTests(unittest.TestCase):
    def test_lint_warns_about_explicitly_authorized_permanent_suppression(self) -> None:
        suppression = valid_suppression(
            expires_at=None,
            allow_permanent=True,
        )

        issues = lint_suppression(suppression, evaluated_at=CREATED_AT)

        self.assertEqual(
            issues,
            [
                {
                    "code": "PERMANENT_SUPPRESSION",
                    "level": "warning",
                    "message": "Suppression has no expiry and requires ongoing review.",
                }
            ],
        )


class SuppressionRevalidationTests(unittest.TestCase):
    def test_expired_suppression_reopens_finding_for_evaluation(self) -> None:
        finding = valid_finding()
        suppression = valid_suppression(finding)
        suppressed = apply_suppression(
            finding,
            suppression,
            repository="example/service",
            ref="main",
            environment="production",
            changed_at=CREATED_AT,
        )

        result = revalidate_suppression(
            suppressed,
            suppression,
            repository="example/service",
            ref="main",
            environment="production",
            policy_digest=POLICY_DIGEST,
            evaluated_at=EXPIRES_AT,
        )

        self.assertEqual(suppressed["status"], "suppressed")
        self.assertFalse(result["active"])
        self.assertTrue(result["reopened"])
        self.assertEqual(result["reasons"], ["expired"])
        reopened = result["finding"]
        self.assertEqual(reopened["status"], "open")
        transition = reopened["state_history"][-1]
        self.assertTrue(transition["automatic"])
        self.assertEqual(transition["from_state"], "suppressed")
        self.assertEqual(transition["to_state"], "open")
        self.assertEqual(
            transition["evidence"],
            [
                {
                    "kind": "suppression-revalidation",
                    "reference": suppression["suppression_id"],
                    "summary": "Suppression invalidated: expired.",
                }
            ],
        )

    def test_meaningful_code_change_reopens_suppressed_finding(self) -> None:
        finding = valid_finding()
        finding["code_region_hash"] = "region-before"
        suppression, suppressed = suppress_finding(finding)
        suppressed["code_region_hash"] = "region-after"

        result = revalidate_suppression(
            suppressed,
            suppression,
            repository="example/service",
            ref="main",
            environment="production",
            policy_digest=POLICY_DIGEST,
            evaluated_at=datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(result["reasons"], ["code_changed"])
        self.assertTrue(result["reopened"])
        self.assertEqual(result["finding"]["status"], "open")

    def test_reachability_change_reopens_suppressed_finding(self) -> None:
        finding = valid_finding()
        suppression, suppressed = suppress_finding(finding)
        suppressed["reachability"] = "unreachable"

        result = revalidate_suppression(
            suppressed,
            suppression,
            repository="example/service",
            ref="main",
            environment="production",
            policy_digest=POLICY_DIGEST,
            evaluated_at=datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(result["reasons"], ["reachability_changed"])
        self.assertTrue(result["reopened"])

    def test_kev_status_change_reopens_suppressed_finding(self) -> None:
        finding = valid_finding()
        finding["threat_intelligence"] = threat_intelligence(False)
        suppression, suppressed = suppress_finding(finding)
        suppressed["threat_intelligence"] = threat_intelligence(True)

        result = revalidate_suppression(
            suppressed,
            suppression,
            repository="example/service",
            ref="main",
            environment="production",
            policy_digest=POLICY_DIGEST,
            evaluated_at=datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(result["reasons"], ["kev_status_changed"])
        self.assertTrue(result["reopened"])

    def test_exploit_evidence_change_reopens_suppressed_finding(self) -> None:
        finding = valid_finding()
        finding["environment"]["public_exploit_availability"] = False
        suppression, suppressed = suppress_finding(finding)
        suppressed["environment"]["public_exploit_availability"] = True

        result = revalidate_suppression(
            suppressed,
            suppression,
            repository="example/service",
            ref="main",
            environment="production",
            policy_digest=POLICY_DIGEST,
            evaluated_at=datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(result["reasons"], ["exploit_evidence_changed"])
        self.assertTrue(result["reopened"])

    def test_policy_change_reopens_suppressed_finding(self) -> None:
        finding = valid_finding()
        suppression, suppressed = suppress_finding(finding)

        result = revalidate_suppression(
            suppressed,
            suppression,
            repository="example/service",
            ref="main",
            environment="production",
            policy_digest="sha256:" + "b" * 64,
            evaluated_at=datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(result["reasons"], ["policy_changed"])
        self.assertTrue(result["reopened"])

    def test_unchanged_unexpired_suppression_remains_active(self) -> None:
        finding = valid_finding()
        suppression, suppressed = suppress_finding(finding)

        result = revalidate_suppression(
            suppressed,
            suppression,
            repository="example/service",
            ref="main",
            environment="production",
            policy_digest=POLICY_DIGEST,
            evaluated_at=datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc),
        )

        self.assertTrue(result["active"])
        self.assertFalse(result["reopened"])
        self.assertEqual(result["reasons"], [])
        self.assertEqual(result["finding"], suppressed)
        self.assertIsNot(result["finding"], suppressed)

    def test_lint_warns_when_suppression_is_nearing_expiry(self) -> None:
        issues = lint_suppression(
            valid_suppression(),
            evaluated_at=datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(
            issues,
            [
                {
                    "code": "SUPPRESSION_EXPIRING",
                    "level": "warning",
                    "message": (
                        "Suppression expires within 7 days at "
                        "2026-08-10T12:00:00+00:00."
                    ),
                }
            ],
        )

    def test_lint_reports_expired_suppression_as_error(self) -> None:
        issues = lint_suppression(
            valid_suppression(),
            evaluated_at=EXPIRES_AT,
        )

        self.assertEqual(
            issues,
            [
                {
                    "code": "SUPPRESSION_EXPIRED",
                    "level": "error",
                    "message": (
                        "Suppression expired at 2026-08-10T12:00:00+00:00."
                    ),
                }
            ],
        )

    def test_lint_reports_tampered_suppression_without_trusting_it(self) -> None:
        suppression = valid_suppression()
        suppression["reason"] = "Tampered after approval."

        issues = lint_suppression(suppression, evaluated_at=CREATED_AT)

        self.assertEqual(
            issues,
            [
                {
                    "code": "INVALID_SUPPRESSION",
                    "level": "error",
                    "message": "suppression digest does not match its content",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
