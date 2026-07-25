from pathlib import Path
import re
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class OpenSSFScorecardWorkflowTests(unittest.TestCase):
    def test_scorecard_workflow_is_immutable_and_least_privilege(self) -> None:
        path = (
            REPOSITORY_ROOT
            / ".github"
            / "workflows"
            / "scorecard-analysis.yml"
        )
        self.assertTrue(path.is_file(), "Scorecard workflow is missing")
        workflow = path.read_text(encoding="utf-8")

        self.assertIn("permissions: read-all", workflow)
        self.assertIn("security-events: write", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertNotIn("\n    env:", workflow)
        self.assertNotIn("\n      - run:", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("publish_results: true", workflow)
        self.assertIn("branches: [main]", workflow)
        self.assertIn("schedule:", workflow)

        action_references = re.findall(
            r"^\s*uses:\s*([^#\s]+)",
            workflow,
            flags=re.MULTILINE,
        )
        self.assertGreaterEqual(len(action_references), 4)
        for reference in action_references:
            self.assertRegex(reference, r"@[0-9a-f]{40}$")

        self.assertIn(
            "ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc"
            " # v2.4.4",
            workflow,
        )

    def test_scorecard_review_records_the_permission_result(self) -> None:
        path = (
            REPOSITORY_ROOT
            / "docs"
            / "audits"
            / "OPENSSF_SCORECARD_REVIEW.md"
        )
        self.assertTrue(path.is_file(), "Scorecard review evidence is missing")
        review = path.read_text(encoding="utf-8")

        self.assertIn("OpenSSF Scorecard 5.5.0", review)
        self.assertIn("Token-Permissions", review)
        self.assertIn("10 / 10", review)
        self.assertIn("Dangerous-Workflow", review)
        self.assertIn("Pinned-Dependencies", review)
        self.assertIn("scorecard-analysis.yml", review)


if __name__ == "__main__":
    unittest.main()
