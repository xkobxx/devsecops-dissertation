from __future__ import annotations

import json
from pathlib import Path
import unittest

from trustgate.policy.packs import available_policy_packs, policy_pack_directory
from trustgate.policy.loading import load_effective_policy
from trustgate.policy.tooling import run_policy_tests


EXPECTED_PACKS = {
    "startup-baseline",
    "high-assurance-baseline",
    "financial-services",
    "healthcare",
    "public-sector-supplier",
    "owasp-asvs-aligned",
    "nist-ssdf-aligned",
    "container-security",
    "secret-protection",
    "supply-chain-security",
}


class StandardPolicyPackTests(unittest.TestCase):
    def test_manifest_exposes_all_ten_standard_packs(self) -> None:
        records = available_policy_packs()

        self.assertEqual(set(records), EXPECTED_PACKS)
        self.assertEqual(len(records), 10)
        self.assertTrue(all(record["policy_version"] == "1.0.0" for record in records.values()))

    def test_every_pack_is_documented_schema_valid_and_has_passing_tests(self) -> None:
        root = policy_pack_directory()
        scan_run = json.loads(
            (root / "fixtures" / "saved-scan.json").read_text(encoding="utf-8")
        )

        for pack_name in sorted(EXPECTED_PACKS):
            with self.subTest(pack=pack_name):
                directory = root / pack_name
                policy = load_effective_policy(directory / "policy.yml")
                context = json.loads(
                    (directory / "runtime-context.json").read_text(encoding="utf-8")
                )
                expectations = json.loads(
                    (directory / "expectations.json").read_text(encoding="utf-8")
                )
                documentation = (directory / "README.md").read_text(encoding="utf-8")

                result = run_policy_tests(
                    policy,
                    scan_run,
                    expectations,
                    runtime_context=context.get("shared", {}),
                    finding_contexts=context.get("findings", {}),
                )

                self.assertGreaterEqual(len(policy.policies), 2)
                self.assertGreaterEqual(len(expectations["tests"]), 1)
                self.assertEqual(result["failed"], 0, result)
                self.assertIn("does not guarantee compliance", documentation.lower())

    def test_manifest_paths_stay_inside_the_pack_directory(self) -> None:
        root = policy_pack_directory().resolve()

        for record in available_policy_packs().values():
            path = (root / record["path"]).resolve()
            self.assertTrue(path.is_relative_to(root))
            self.assertTrue(path.is_file())

    def test_installed_pack_alias_loads_without_a_checkout_relative_path(self) -> None:
        policy = load_effective_policy("pack:startup-baseline")

        self.assertEqual(policy.policy_id, "trustgate.startup-baseline")
        self.assertEqual(policy.policy_version, "1.0.0")


if __name__ == "__main__":
    unittest.main()
