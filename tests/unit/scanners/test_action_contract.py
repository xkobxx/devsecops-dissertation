from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class CompositeActionScannerContractTests(unittest.TestCase):
    def test_action_uses_health_aware_scanner_execution(self) -> None:
        action = (REPOSITORY_ROOT / "action.yml").read_text(encoding="utf-8")

        self.assertNotIn("|| true", action)
        self.assertGreaterEqual(action.count("scripts/run_scanner.py"), 4)
        self.assertIn("scripts/record_scanner.py", action)
        self.assertIn("scanner-timeout-seconds:", action)
        self.assertIn("severity-basis:", action)
        self.assertIn("--severity-basis", action)
        self.assertIn("redact-sensitive-content:", action)
        self.assertIn("--redact-sensitive-content", action)
        self.assertIn("--require-execution-metadata", action)
        self.assertIn("version: v0.69.3", action)
        self.assertIn("--exit-code 3", action)
        self.assertIn("--finding-exit-code 3", action)
        self.assertIn("id: validate", action)
        self.assertIn("scripts/validate_inputs.py", action)
        self.assertLess(
            action.index("scripts/validate_inputs.py"),
            action.index("Install SAST/SCA scanners"),
        )
        self.assertIn("steps.validate.outputs.target", action)
        self.assertIn("steps.validate.outputs.artifact-name", action)
        self.assertIn("policy-result-path:", action)
        self.assertIn("reports/policy-result.json", action)

    def test_action_packages_opt_in_digest_pinned_dast(self) -> None:
        action = (REPOSITORY_ROOT / "action.yml").read_text(encoding="utf-8")

        for name in (
            "dast-enabled:",
            "dast-target-url:",
            "dast-mode:",
            "dast-openapi-path:",
            "dast-auth-type:",
            "dast-auth-secret:",
            "dast-scope-hosts:",
            "dast-rate-limit:",
            "dast-request-limit:",
            "dast-max-duration-seconds:",
        ):
            self.assertIn(name, action)
        self.assertIn("scripts/run_dast.py", action)
        self.assertIn("--container-image", action)
        self.assertRegex(
            action,
            r"ghcr\.io/zaproxy/zaproxy@sha256:[0-9a-f]{64}",
        )
        self.assertIn("steps.validate.outputs.dast-enabled == 'true'", action)
        self.assertLess(
            action.index("Validate Action inputs"),
            action.index("Run bounded DAST"),
        )
        dast_step = action.split("- name: Run bounded DAST", 1)[1].split(
            "- name:", 1
        )[0]
        self.assertIn("TRUSTGATE_DAST_AUTH_SECRET", dast_step)
        self.assertNotIn("--auth-secret ", dast_step)

    def test_action_generates_and_publishes_sarif_artifact(self) -> None:
        action = (REPOSITORY_ROOT / "action.yml").read_text(encoding="utf-8")

        self.assertIn("sarif-path:", action)
        self.assertIn("steps.sarif.outputs.sarif-path", action)
        self.assertIn("-m trustgate sarif", action)
        self.assertIn("reports/trustgate.sarif", action)
        self.assertLess(
            action.index("Aggregate findings and evaluate gate"),
            action.index("Generate SARIF"),
        )
        artifact = action.split("- name: Upload dashboard artifact", 1)[1].split(
            "- name:", 1
        )[0]
        self.assertIn("reports/trustgate.sarif", artifact)

    def test_repository_workflow_uploads_sarif_with_least_privilege(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/devsecops.yml").read_text(
            encoding="utf-8"
        )
        gate = workflow.split("  security-gate:", 1)[1].split(
            "  upload-sarif:", 1
        )[0]
        upload = workflow.split("  upload-sarif:", 1)[1].split(
            "  generate-dashboard:", 1
        )[0]

        self.assertIn("-m trustgate sarif", gate)
        self.assertNotIn("security-events: write", gate)
        self.assertIn("security-events: write", upload)
        self.assertIn("contents: read", upload)
        self.assertNotIn("actions/checkout", upload)
        self.assertIn(
            "github/codeql-action/upload-sarif@"
            "8aad20d150bbac5944a9f9d289da16a4b0d87c1e # v4.36.2",
            upload,
        )
        self.assertIn("sarif_file: reports/trustgate.sarif", upload)
        self.assertIn("category: trustgate", upload)
        self.assertIn(
            "github.event.pull_request.head.repo.full_name == github.repository",
            upload,
        )
        self.assertIn("hashFiles('reports/trustgate.sarif') != ''", upload)

    def test_action_publishes_a_complete_github_check_summary(self) -> None:
        action = (REPOSITORY_ROOT / "action.yml").read_text(encoding="utf-8")

        self.assertIn("check-summary-path:", action)
        self.assertIn("steps.check-summary.outputs.check-summary-path", action)
        self.assertIn("-m trustgate checks", action)
        self.assertIn("--baseline-diff reports/baseline-diff.json", action)
        self.assertIn("--baseline-gate reports/baseline-gate.json", action)
        self.assertIn("reports/check-summary.md", action)
        self.assertIn(
            'cat reports/check-summary.md >> "$GITHUB_STEP_SUMMARY"',
            action,
        )
        artifact = action.split("- name: Upload dashboard artifact", 1)[1].split(
            "- name:", 1
        )[0]
        self.assertIn("reports/check-summary.md", artifact)

    def test_repository_gate_is_a_stable_required_check_with_summary(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/devsecops.yml").read_text(
            encoding="utf-8"
        )
        gate = workflow.split("  security-gate:", 1)[1].split(
            "  upload-sarif:", 1
        )[0]

        self.assertIn("name: Trust Gate", gate)
        self.assertIn("-m trustgate checks", gate)
        self.assertIn("GITHUB_STEP_SUMMARY", gate)
        self.assertIn("github.server_url", gate)
        self.assertIn("reports/check-summary.md", gate)
        self.assertNotIn("checks: write", gate)
        self.assertIn("merge_group:", workflow)
        self.assertIn("types: [checks_requested]", workflow)

    def test_action_generates_a_safe_consolidated_pr_comment_artifact(self) -> None:
        action = (REPOSITORY_ROOT / "action.yml").read_text(encoding="utf-8")

        self.assertIn("pr-comment-path:", action)
        self.assertIn("steps.pr-comment.outputs.pr-comment-path", action)
        self.assertIn("-m trustgate pr-comment", action)
        self.assertIn("--repository \"$TRUSTGATE_REPOSITORY\"", action)
        self.assertIn("--commit \"$TRUSTGATE_COMMIT\"", action)
        self.assertIn("reports/pr-comment.md", action)
        artifact = action.split("- name: Upload dashboard artifact", 1)[1].split(
            "- name:", 1
        )[0]
        self.assertIn("reports/pr-comment.md", artifact)

    def test_repository_workflow_upserts_one_bot_owned_pr_summary(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/devsecops.yml").read_text(
            encoding="utf-8"
        )
        gate = workflow.split("  security-gate:", 1)[1].split(
            "  upload-sarif:", 1
        )[0]
        comment = workflow.split("  comment-pr-summary:", 1)[1]

        self.assertIn("-m trustgate pr-comment", gate)
        self.assertIn("reports/pr-comment.md", gate)
        self.assertIn("name: Update Trust Gate PR summary", comment)
        self.assertIn("actions: read", comment)
        self.assertIn("pull-requests: write", comment)
        self.assertNotIn("actions/checkout", comment)
        self.assertNotIn("\n        run:", comment)
        self.assertIn("name: unified-findings", comment)
        self.assertIn("reports/pr-comment.md", comment)
        self.assertIn("<!-- trustgate-pr-summary -->", comment)
        self.assertIn("concurrency:", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("github.event.pull_request.number || github.ref", workflow)
        self.assertIn("github-actions[bot]", comment)
        self.assertIn("comment.user?.type === 'Bot'", comment)
        self.assertEqual(comment.count("github.rest.issues.createComment"), 1)
        self.assertEqual(comment.count("github.rest.issues.updateComment"), 1)
        self.assertIn(
            "github.event.pull_request.head.repo.full_name == github.repository",
            comment,
        )


if __name__ == "__main__":
    unittest.main()
