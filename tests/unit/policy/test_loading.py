from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from trustgate.policy.loading import (
    PolicyLoadError,
    load_effective_policy,
    load_policy_file,
)

from tests.unit.policy.test_resolution import base_document, child_document


class PolicyLoadingTests(unittest.TestCase):
    def test_json_and_yaml_are_loaded_with_exact_parent_versions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            parent = workspace / "base.policy.json"
            parent.write_text(json.dumps(base_document()), encoding="utf-8")
            child = child_document()
            child["extends"][0]["path"] = parent.name
            policy = workspace / "service.policy.yml"
            import yaml

            policy.write_text(yaml.safe_dump(child), encoding="utf-8")

            loaded_parent = load_policy_file(parent)
            effective = load_effective_policy(
                policy,
                repository="example/critical-api",
            )

            self.assertEqual(loaded_parent.policy_id, "organisation-base")
            self.assertEqual(effective.default_action.value, "block")
            self.assertIn("base-high", [rule.name for rule in effective.policies])

    def test_inherited_file_identity_mismatch_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "base.policy.json").write_text(
                json.dumps({**base_document(), "policy_version": "9.0.0"}),
                encoding="utf-8",
            )
            child = child_document()
            child["extends"][0]["path"] = "base.policy.json"
            policy = workspace / "service.policy.json"
            policy.write_text(json.dumps(child), encoding="utf-8")

            with self.assertRaisesRegex(PolicyLoadError, "expected.*1.2.0"):
                load_effective_policy(policy)

    def test_inheritance_cycles_fail_instead_of_recursing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            first = base_document()
            first["extends"] = [
                {
                    "path": "second.policy.json",
                    "policy_id": "second",
                    "policy_version": "1.0.0",
                }
            ]
            second = {
                **base_document(),
                "policy_id": "second",
                "policy_version": "1.0.0",
                "extends": [
                    {
                        "path": "first.policy.json",
                        "policy_id": "organisation-base",
                        "policy_version": "1.2.0",
                    }
                ],
            }
            first_path = workspace / "first.policy.json"
            first_path.write_text(json.dumps(first), encoding="utf-8")
            (workspace / "second.policy.json").write_text(
                json.dumps(second),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PolicyLoadError, "cycle detected"):
                load_effective_policy(first_path)

    def test_unsafe_yaml_constructors_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "unsafe.policy.yml"
            policy.write_text(
                "!!python/object/apply:os.system ['echo unsafe']\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PolicyLoadError, "could not load"):
                load_policy_file(policy)


if __name__ == "__main__":
    unittest.main()
