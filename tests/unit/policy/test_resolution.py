from __future__ import annotations

import unittest

from trustgate.policy.models import PolicyDocument
from trustgate.policy.resolution import PolicyResolutionError, resolve_policy


def rule(name: str, action: str, severity: str) -> dict[str, object]:
    return {
        "name": name,
        "action": action,
        "when": {"severity": severity},
    }


def base_document() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "version": 1,
        "policy_id": "organisation-base",
        "policy_version": "1.2.0",
        "default_action": "investigate",
        "policies": [rule("base-high", "fix_within_sla", "high")],
    }


def child_document() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "version": 1,
        "policy_id": "service-policy",
        "policy_version": "2.0.0",
        "extends": [
            {
                "path": "base.policy.yml",
                "policy_id": "organisation-base",
                "policy_version": "1.2.0",
            }
        ],
        "organisation_defaults": {
            "default_action": "monitor",
            "policies": [rule("org-low", "monitor", "low")],
        },
        "repository_overrides": [
            {
                "repositories": ["example/critical-*"],
                "default_action": "block",
                "policies": [
                    rule("critical-repository", "block", "critical")
                ],
            }
        ],
        "policies": [rule("service-medium", "fix_before_release", "medium")],
    }


class PolicyResolutionTests(unittest.TestCase):
    def test_inheritance_defaults_and_repository_overrides_have_clear_precedence(self) -> None:
        parent = PolicyDocument.from_dict(base_document())
        child = PolicyDocument.from_dict(child_document())

        effective = resolve_policy(
            child,
            inherited={(parent.policy_id, parent.policy_version): parent},
            repository="example/critical-api",
        )

        self.assertEqual(
            [policy.name for policy in effective.policies],
            [
                "critical-repository",
                "service-medium",
                "org-low",
                "base-high",
            ],
        )
        self.assertEqual(effective.default_action.value, "block")
        self.assertEqual(effective.policy_id, "service-policy")
        self.assertEqual(effective.policy_version, "2.0.0")
        self.assertEqual(effective.extends, ())
        self.assertEqual(effective.repository_overrides, ())

    def test_nonmatching_repository_uses_organisation_default(self) -> None:
        parent = PolicyDocument.from_dict(base_document())
        effective = resolve_policy(
            PolicyDocument.from_dict(child_document()),
            inherited={(parent.policy_id, parent.policy_version): parent},
            repository="example/ordinary-service",
        )

        self.assertEqual(effective.default_action.value, "monitor")
        self.assertNotIn(
            "critical-repository",
            [policy.name for policy in effective.policies],
        )

    def test_inheritance_requires_exact_policy_identity_and_version(self) -> None:
        child = PolicyDocument.from_dict(child_document())
        wrong_parent = PolicyDocument.from_dict(
            {**base_document(), "policy_version": "1.3.0"}
        )

        with self.assertRaisesRegex(PolicyResolutionError, "organisation-base@1.2.0"):
            resolve_policy(
                child,
                inherited={
                    (wrong_parent.policy_id, wrong_parent.policy_version): wrong_parent
                },
                repository="example/service",
            )


if __name__ == "__main__":
    unittest.main()
