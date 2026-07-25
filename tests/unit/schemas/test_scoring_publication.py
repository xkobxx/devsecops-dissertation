"""Confidence scoring must preserve and republish the canonical contract."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from trustgate.benchmarks.statistics import posterior_precision
from trustgate.schema import validate_instance
from trustgate.scoring.legacy import main


class ScoringPublicationTests(unittest.TestCase):
    @patch(
        "trustgate.scoring.legacy.verify",
        return_value=(True, "ok", {"plan": "team"}),
    )
    def test_scoring_migrates_and_validates_output_before_publication(
        self,
        _verify: unittest.mock.Mock,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            findings_path = root / "findings.json"
            findings_path.write_text(
                json.dumps(
                    {
                        "target": ".",
                        "total": 1,
                        "findings": [
                            {
                                "tool": "Bandit",
                                "rule_id": "B608",
                                "severity": "MEDIUM",
                                "description": "Possible SQL injection.",
                                "file": "app.py",
                                "line": 12,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            confidence_path = root / "confidence.json"
            confidence_path.write_text(
                json.dumps(
                    {
                        "rules": {
                            "Bandit:B608": posterior_precision(15, 5)
                        },
                        "tool_baseline": {},
                    }
                ),
                encoding="utf-8",
            )

            main(
                [
                    "--input",
                    str(findings_path),
                    "--confidence-table",
                    str(confidence_path),
                    "--license-key",
                    "test-key",
                ]
            )

            scored = json.loads(findings_path.read_text(encoding="utf-8"))
            validate_instance("scan-run", scored)
            finding = scored["findings"][0]
            self.assertEqual(finding["confidence"], 0.727273)
            self.assertEqual(finding["confidence_sample_size"], 20)
            self.assertEqual(
                finding["confidence_method"],
                "rule:beta-binomial:1.0.0",
            )
            for component in (
                "scanner_rule_reliability",
                "finding_validity_confidence",
                "reachability_confidence",
                "exploitability_confidence",
                "remediation_confidence",
                "overall_decision_confidence",
            ):
                self.assertIn(component, finding)
            self.assertIsNone(
                finding["exploitability_confidence"]["estimate"]
            )
            self.assertNotIn("confidence_tier", finding)


if __name__ == "__main__":
    unittest.main()
