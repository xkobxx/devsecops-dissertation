from __future__ import annotations

import copy
import unittest

from trustgate.policy.models import PolicyDocument
from trustgate.schema import SchemaValidationError, validate_instance


def policy_document(when: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "version": 1,
        "policy_id": "product-policy",
        "policy_version": "2026.08.1",
        "policies": [
            {
                "name": "roadmap-rule",
                "action": "block",
                "when": when,
            }
        ],
    }


class PolicySchemaTests(unittest.TestCase):
    def test_nested_roadmap_example_validates(self) -> None:
        document = policy_document(
            {
                "any": [
                    {
                        "all": [
                            {"environment": "production"},
                            {"kev": True},
                        ]
                    },
                    {
                        "all": [
                            {"severity": "critical"},
                            {"reachability": "confirmed"},
                            {"cwe": ["CWE-78", "CWE-89", "CWE-94"]},
                            {"confidence_lower_bound": ">=0.80"},
                            {"introduced_in_pull_request": True},
                        ]
                    },
                ]
            }
        )

        validate_instance("policy", document)
        parsed = PolicyDocument.from_dict(document)
        self.assertEqual(parsed.version, 1)
        self.assertEqual(parsed.policy_id, "product-policy")
        self.assertEqual(parsed.default_action.value, "investigate")

    def test_schema_supports_all_seventeen_policy_predicates(self) -> None:
        predicates = {
            "severity": "critical",
            "cwe": ["CWE-89"],
            "cve": ["CVE-2026-1234"],
            "epss": ">=0.80",
            "kev": True,
            "reachability": "confirmed",
            "environment": "production",
            "repository": "example/trustgate",
            "branch": "main",
            "asset_criticality": "critical",
            "confidence_lower_bound": ">=0.80",
            "finding_status": "open",
            "introduced_in_pull_request": True,
            "fix_availability": True,
            "scanner_health": "healthy",
            "secret_validation_status": "valid",
            "suppression_expiry": "expired",
        }

        for field, value in predicates.items():
            with self.subTest(field=field):
                validate_instance("policy", policy_document({field: value}))

        self.assertEqual(len(predicates), 17)

    def test_unknown_or_malformed_predicates_fail_clearly(self) -> None:
        invalid_documents = (
            policy_document({"made_up_risk": True}),
            policy_document({"epss": ">=2.0"}),
            policy_document({"cwe": ["89"]}),
        )

        for document in invalid_documents:
            with self.subTest(document=document):
                with self.assertRaises(SchemaValidationError):
                    validate_instance("policy", document)

    def test_duplicate_policy_names_are_rejected(self) -> None:
        document = policy_document({"severity": "critical"})
        document["policies"].append(copy.deepcopy(document["policies"][0]))

        with self.assertRaisesRegex(ValueError, "duplicate policy name"):
            PolicyDocument.from_dict(document)


if __name__ == "__main__":
    unittest.main()
