from __future__ import annotations

import importlib.util
import unittest

import trustgate.remediation as remediation


class RemediationContractTests(unittest.TestCase):
    def test_remediation_package_is_available(self) -> None:
        self.assertIsNotNone(importlib.util.find_spec("trustgate.remediation"))

    def test_supported_rules_publish_complete_safety_contracts(self) -> None:
        rules = remediation.supported_rules()

        self.assertEqual(
            [rule["rule_id"] for rule in rules],
            [
                "TG-DEP-PY-001",
                "TG-DOCKER-USER-001",
                "TG-FLASK-HEADERS-001",
                "TG-PY-HASH-001",
                "TG-PY-SECRET-001",
                "TG-PY-SHELL-001",
                "TG-PY-SQL-001",
                "TG-PY-YAML-001",
            ],
        )
        for rule in rules:
            with self.subTest(rule_id=rule["rule_id"]):
                self.assertEqual(
                    set(rule),
                    {
                        "rule_id",
                        "title",
                        "framework",
                        "preconditions",
                        "transformation",
                        "tests",
                        "rollback",
                        "risk_notes",
                    },
                )
                self.assertTrue(rule["preconditions"])
                self.assertTrue(rule["tests"])
                self.assertTrue(rule["risk_notes"])

    def test_apply_and_rollback_apis_are_available(self) -> None:
        self.assertTrue(callable(remediation.apply_remediation_plan))
        self.assertTrue(callable(remediation.rollback_remediation))

    def test_guided_remediation_api_is_available(self) -> None:
        self.assertTrue(callable(remediation.generate_guidance))

    def test_ai_remediation_state_transition_apis_are_available(self) -> None:
        self.assertTrue(callable(remediation.prepare_ai_context))
        self.assertTrue(callable(remediation.request_ai_patch))
        self.assertTrue(callable(remediation.stage_ai_patch))
        self.assertTrue(callable(remediation.verify_ai_remediation))
        self.assertTrue(callable(remediation.publish_ai_remediation))


if __name__ == "__main__":
    unittest.main()
