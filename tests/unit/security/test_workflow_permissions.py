from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = REPOSITORY_ROOT / ".github" / "workflows"


class WorkflowPermissionContractTests(unittest.TestCase):
    def test_scan_workflow_is_read_only_and_delegates_publishing(self) -> None:
        workflow = (WORKFLOWS / "devsecops.yml").read_text(encoding="utf-8")
        header = workflow.split("\njobs:", maxsplit=1)[0]

        self.assertIn("permissions:\n  contents: read", header)
        self.assertNotIn("pages: write", header)
        self.assertNotIn("id-token: write", header)
        self.assertNotIn("pull-requests: write", header)
        self.assertNotIn("\n  deploy-pages:", workflow)
        self.assertIn(
            "uses: ./.github/workflows/publish-dashboard.yml",
            workflow,
        )

    def test_publish_workflow_has_narrow_permissions_and_no_checkout(self) -> None:
        path = WORKFLOWS / "publish-dashboard.yml"
        self.assertTrue(path.is_file(), "publishing workflow is missing")
        workflow = path.read_text(encoding="utf-8")

        self.assertIn('"on":\n  workflow_call:', workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("pages: write", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertNotIn("actions/checkout@", workflow)
        self.assertIn("environment:\n      name: github-pages", workflow)

    def test_untrusted_pull_requests_receive_no_secrets_or_publish_token(self) -> None:
        workflow = (WORKFLOWS / "devsecops.yml").read_text(encoding="utf-8")
        all_workflows = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(WORKFLOWS.glob("*.yml"))
            if not path.name.startswith("._")
        )

        self.assertNotIn("pull_request_target", all_workflows)
        self.assertNotIn("secrets.", workflow)
        self.assertIn(
            "github.event_name == 'push' && "
            "needs.generate-dashboard.result == 'success'",
            workflow,
        )
        self.assertIn(
            "github.event.pull_request.head.repo.full_name == github.repository",
            workflow,
        )

    def test_security_documents_define_the_workflow_trust_boundary(self) -> None:
        workflow_security_path = (
            REPOSITORY_ROOT / "docs" / "security" / "WORKFLOW_SECURITY.md"
        )
        threat_model_path = (
            REPOSITORY_ROOT / "docs" / "security" / "THREAT_MODEL.md"
        )
        self.assertTrue(
            workflow_security_path.is_file(),
            "workflow security document is missing",
        )
        self.assertTrue(threat_model_path.is_file(), "threat model is missing")
        workflow_security = workflow_security_path.read_text(encoding="utf-8")
        threat_model = threat_model_path.read_text(encoding="utf-8")

        self.assertIn("Untrusted pull requests", workflow_security)
        self.assertIn("read-only", workflow_security)
        self.assertIn("publishing", workflow_security.lower())
        self.assertIn("Trust boundaries", threat_model)
        self.assertIn("GITHUB_TOKEN", threat_model)
        self.assertIn("licence", threat_model.lower())

    def test_dast_inputs_are_validated_before_the_zap_action(self) -> None:
        workflow = (WORKFLOWS / "devsecops.yml").read_text(encoding="utf-8")

        self.assertIn("scripts/validate_inputs.py", workflow)
        self.assertLess(
            workflow.index("scripts/validate_inputs.py"),
            workflow.index("zaproxy/action-baseline@"),
        )


if __name__ == "__main__":
    unittest.main()
