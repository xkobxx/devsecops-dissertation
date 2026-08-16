"""Tests for the multilingual benchmark corpus contract."""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from trustgate.cli import main as cli_main
from trustgate.benchmarks.corpus import (
    BenchmarkCorpusError,
    validate_corpus,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
CORPUS_PATH = PROJECT_ROOT / "benchmarks/corpora/multilingual-v1.json"


def load_corpus() -> dict[str, object]:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


class BenchmarkCorpusTests(unittest.TestCase):
    def test_cli_validates_repository_corpus(self) -> None:
        self.assertEqual(
            cli_main(
                [
                    "benchmark",
                    "--corpus-check",
                    "--corpus",
                    "benchmarks/corpora/multilingual-v1.json",
                ]
            ),
            0,
        )

    def test_repository_corpus_has_every_required_coverage_dimension(self) -> None:
        result = validate_corpus(PROJECT_ROOT, load_corpus())

        self.assertEqual(result["corpus_id"], "trustgate-multilingual")
        self.assertEqual(result["corpus_version"], "1.0.0")
        self.assertEqual(
            set(result["coverage"]["languages"]),
            {"python", "javascript", "typescript", "java", "go", "ruby", "csharp"},
        )
        self.assertEqual(
            set(result["coverage"]["targets"]),
            {"source", "infrastructure_as_code", "container", "kubernetes"},
        )
        self.assertGreaterEqual(len(result["coverage"]["frameworks"]), 7)
        self.assertEqual(
            set(result["coverage"]["classifications"]),
            {"vulnerable", "patched", "safe_lookalike"},
        )
        self.assertEqual(
            set(result["coverage"]["reachability"]),
            {"reachable", "unreachable", "sanitised", "not_applicable"},
        )
        self.assertEqual(
            set(result["coverage"]["code_scopes"]),
            {"production", "test", "not_applicable"},
        )
        self.assertEqual(
            set(result["coverage"]["dependency_scopes"]),
            {"production", "development", "not_applicable"},
        )
        self.assertTrue(result["coverage"]["cross_file"])

    def test_every_vulnerability_has_a_distinct_patched_equivalent(self) -> None:
        result = validate_corpus(PROJECT_ROOT, load_corpus())
        cases = {case["case_id"]: case for case in result["cases"]}

        for case in cases.values():
            if case["classification"] != "vulnerable":
                continue
            pair = cases[case["paired_case_id"]]
            self.assertEqual(pair["classification"], "patched")
            self.assertEqual(pair["paired_case_id"], case["case_id"])
            self.assertEqual(pair["vulnerability_class"], case["vulnerability_class"])
            self.assertNotEqual(set(pair["files"]), set(case["files"]))

    def test_every_file_is_hash_bound_and_referenced_by_a_case(self) -> None:
        result = validate_corpus(PROJECT_ROOT, load_corpus())
        referenced = {
            path
            for case in result["cases"]
            for path in case["files"]
        }
        declared = {record["path"] for record in result["files"]}

        self.assertEqual(referenced, declared)
        self.assertTrue(all(record["bytes"] > 0 for record in result["files"]))

    def test_rejects_hash_tampering_missing_coverage_and_path_escape(self) -> None:
        corpus = load_corpus()
        corpus["files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(BenchmarkCorpusError, "hash mismatch"):
            validate_corpus(PROJECT_ROOT, corpus)

        missing = load_corpus()
        missing["cases"] = [
            case for case in missing["cases"] if case["language"] != "csharp"
        ]
        with self.assertRaisesRegex(BenchmarkCorpusError, "coverage"):
            validate_corpus(PROJECT_ROOT, missing)

        escaping = load_corpus()
        escaping["files"][0]["path"] = "../outside.py"
        with self.assertRaisesRegex(BenchmarkCorpusError, "escapes"):
            validate_corpus(PROJECT_ROOT, escaping)

    def test_rejects_broken_pairing_and_undeclared_case_files(self) -> None:
        corpus = load_corpus()
        vulnerable = next(
            case for case in corpus["cases"] if case["classification"] == "vulnerable"
        )
        vulnerable["paired_case_id"] = "missing"
        with self.assertRaisesRegex(BenchmarkCorpusError, "paired"):
            validate_corpus(PROJECT_ROOT, corpus)

        undeclared = load_corpus()
        undeclared["cases"][0]["files"].append("benchmarks/fixtures/missing.py")
        with self.assertRaisesRegex(BenchmarkCorpusError, "undeclared"):
            validate_corpus(PROJECT_ROOT, undeclared)


if __name__ == "__main__":
    unittest.main()
