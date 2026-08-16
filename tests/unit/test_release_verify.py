"""Tests for the verify-release command (PDF p. 43)."""

import unittest
from pathlib import Path
from unittest.mock import patch

from trustgate.release_verify import (
    _check_action_pinning,
    _check_changelog,
    _check_dependency_pinning,
    _check_examples,
    _check_release_signatures,
    _check_sbom,
    _check_sarif,
    _check_schemas,
    _check_vex,
    _check_version_consistency,
    verify_release,
)

ROOT = Path(__file__).resolve().parents[2]


class TestCheckSchemas(unittest.TestCase):

    def test_valid_schemas(self):
        passed, detail = _check_schemas(ROOT)
        self.assertTrue(passed, detail)
        self.assertIn("schemas valid", detail)

    def test_missing_directory(self):
        passed, detail = _check_schemas(Path("/nonexistent"))
        self.assertFalse(passed)


class TestCheckDependencyPinning(unittest.TestCase):

    def test_real_pyproject(self):
        passed, detail = _check_dependency_pinning(ROOT)
        self.assertTrue(passed, detail)


class TestCheckActionPinning(unittest.TestCase):

    def test_real_workflows(self):
        passed, detail = _check_action_pinning(ROOT)
        self.assertTrue(passed, detail)


class TestCheckChangelog(unittest.TestCase):

    def test_real_changelog(self):
        passed, detail = _check_changelog(ROOT)
        self.assertTrue(passed, detail)


class TestCheckExamples(unittest.TestCase):

    def test_real_examples(self):
        passed, detail = _check_examples(ROOT)
        self.assertTrue(passed, detail)


class TestCheckVersionConsistency(unittest.TestCase):

    def test_real_version(self):
        passed, detail = _check_version_consistency(ROOT)
        self.assertTrue(passed, detail)


class TestCheckSbom(unittest.TestCase):

    def test_importable(self):
        passed, detail = _check_sbom(ROOT)
        self.assertTrue(passed, detail)


class TestCheckVex(unittest.TestCase):

    def test_importable(self):
        passed, detail = _check_vex(ROOT)
        self.assertTrue(passed, detail)


class TestCheckSarif(unittest.TestCase):

    def test_importable(self):
        passed, detail = _check_sarif(ROOT)
        self.assertTrue(passed, detail)


class TestCheckReleaseSignatures(unittest.TestCase):

    def test_signing_configured(self):
        passed, detail = _check_release_signatures(ROOT)
        self.assertTrue(passed, detail)


class TestVerifyRelease(unittest.TestCase):
    """Test verify_release with test gates mocked to avoid running pytest recursively."""

    @patch("trustgate.release_verify._check_tests", return_value=(True, "mocked"))
    @patch("trustgate.release_verify._check_benchmark", return_value=(True, "mocked"))
    def test_returns_structured_result(self, mock_bench, mock_tests):
        # Patch the lookup table too
        with patch.dict(
            "trustgate.release_verify._CHECK_MAP",
            {"_check_tests": mock_tests, "_check_benchmark": mock_bench},
        ):
            result = verify_release(ROOT)
        self.assertIn("all_passed", result)
        self.assertIn("gates", result)
        self.assertEqual(result["total"], 16)
        self.assertIsInstance(result["passed_count"], int)
        self.assertIsInstance(result["failed_count"], int)
        self.assertEqual(
            result["passed_count"] + result["failed_count"],
            result["total"],
        )

    @patch("trustgate.release_verify._check_tests", return_value=(True, "mocked"))
    @patch("trustgate.release_verify._check_benchmark", return_value=(True, "mocked"))
    def test_each_gate_has_required_fields(self, mock_bench, mock_tests):
        with patch.dict(
            "trustgate.release_verify._CHECK_MAP",
            {"_check_tests": mock_tests, "_check_benchmark": mock_bench},
        ):
            result = verify_release(ROOT)
        for gate in result["gates"]:
            self.assertIn("name", gate)
            self.assertIn("passed", gate)
            self.assertIn("detail", gate)


if __name__ == "__main__":
    unittest.main()
