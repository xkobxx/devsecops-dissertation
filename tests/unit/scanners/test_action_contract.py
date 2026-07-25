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


if __name__ == "__main__":
    unittest.main()
