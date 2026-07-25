from pathlib import Path
import re
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class ReleaseWorkflowContractTests(unittest.TestCase):
    def test_release_workflow_builds_checksums_and_keyless_signatures(self) -> None:
        path = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"
        self.assertTrue(path.is_file(), "Release workflow is missing")
        workflow = path.read_text(encoding="utf-8")

        self.assertIn('tags: ["v*.*.*"]', workflow)
        self.assertIn("release-policy:", workflow)
        self.assertIn("needs: release-policy", workflow)
        self.assertIn("protection_rules", workflow)
        self.assertIn('type == "required_reviewers"', workflow)
        self.assertIn("(.reviewers | length) > 0", workflow)
        self.assertIn("environment:\n      name: release", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("artifact-metadata: write", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("scripts/build_release.py", workflow)
        self.assertIn("--sign", workflow)
        self.assertIn("SHA256SUMS", workflow)
        self.assertIn("subject-checksums: release/SHA256SUMS", workflow)
        self.assertIn("sbom-path:", workflow)
        self.assertIn("trustgate-${{ github.ref_name }}.cdx.json", workflow)
        self.assertIn("gh release create", workflow)
        self.assertIn("release/trustgate-*.cdx.json", workflow)
        self.assertIn("cosign-release: v3.0.6", workflow)
        self.assertEqual(
            workflow.count(
                "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"
                " # v4.2.0"
            ),
            2,
        )

        action_references = re.findall(
            r"^\s*uses:\s*([^#\s]+)",
            workflow,
            flags=re.MULTILINE,
        )
        self.assertGreaterEqual(len(action_references), 3)
        for reference in action_references:
            self.assertRegex(reference, r"@[0-9a-f]{40}$")

        policy_section = workflow.split("\n  release:\n", maxsplit=1)[0]
        self.assertNotIn("actions/checkout", policy_section)
        self.assertNotIn("contents: write", policy_section)
        self.assertLess(
            workflow.index("- name: Publish SBOM attestation"),
            workflow.index("- name: Publish GitHub release"),
        )

        builder = (REPOSITORY_ROOT / "scripts" / "build_release.py").read_text(
            encoding="utf-8"
        )
        self.assertLess(
            builder.index("generate_cyclonedx_sbom("),
            builder.index("generate_checksums("),
        )
        self.assertIn("[*archives, sbom]", builder)
        self.assertIn("[*archives, sbom, checksum_manifest]", builder)

    def test_release_verification_document_constrains_repository_identity(self) -> None:
        path = REPOSITORY_ROOT / "docs" / "RELEASE_VERIFICATION.md"
        self.assertTrue(path.is_file(), "Release verification guide is missing")
        guide = path.read_text(encoding="utf-8")

        self.assertIn("sha256sum --check SHA256SUMS", guide)
        self.assertIn("cosign verify-blob", guide)
        self.assertIn("gh attestation verify", guide)
        self.assertIn("--predicate-type https://cyclonedx.org/bom", guide)
        self.assertIn("--repo xkobxx/devsecops-dissertation", guide)
        self.assertIn("--signer-repo xkobxx/devsecops-dissertation", guide)
        self.assertIn(
            "--signer-workflow "
            "xkobxx/devsecops-dissertation/.github/workflows/release.yml",
            guide,
        )
        self.assertIn('--source-ref "refs/tags/v${VERSION}"', guide)
        self.assertIn(
            'EXPECTED_COMMIT="$(gh api '
            '"repos/xkobxx/devsecops-dissertation/commits/v${VERSION}"',
            guide,
        )
        self.assertIn('--source-digest "${EXPECTED_COMMIT}"', guide)
        self.assertIn('--signer-digest "${EXPECTED_COMMIT}"', guide)
        self.assertIn("--deny-self-hosted-runners", guide)
        self.assertIn("https://token.actions.githubusercontent.com", guide)
        self.assertIn(
            "xkobxx/devsecops-dissertation/.github/workflows/release.yml",
            guide,
        )


if __name__ == "__main__":
    unittest.main()
