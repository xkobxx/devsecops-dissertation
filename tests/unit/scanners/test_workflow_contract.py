from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class RepositoryWorkflowScannerContractTests(unittest.TestCase):
    def test_workflow_preserves_scanner_health_evidence(self) -> None:
        workflow = (
            REPOSITORY_ROOT / ".github" / "workflows" / "devsecops.yml"
        ).read_text(encoding="utf-8")

        self.assertNotIn("|| true", workflow)
        self.assertNotIn("creating empty placeholder", workflow)
        self.assertGreaterEqual(workflow.count("scripts/run_scanner.py"), 7)
        self.assertGreaterEqual(workflow.count("scripts/record_scanner.py"), 2)
        self.assertGreaterEqual(workflow.count("_execution.json"), 9)
        self.assertIn("--require-execution-metadata", workflow)
        self.assertIn("version: v0.69.3", workflow)
        self.assertIn("--exit-code 3", workflow)
        self.assertIn("--finding-exit-code 3", workflow)
        self.assertIn("reports/policy-result.json", workflow)


if __name__ == "__main__":
    unittest.main()
