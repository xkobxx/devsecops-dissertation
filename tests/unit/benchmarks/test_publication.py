"""Tests for the benchmark source-of-truth and publication gate."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

from trustgate.benchmarks.publication import (
    BenchmarkPublicationError,
    GENERATED_END,
    GENERATED_START,
    check_publication,
    evaluate_manifest,
    validate_manifest,
    write_publication,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = (
    PROJECT_ROOT / "benchmarks/manifests/flask-vulnerable-v1.json"
)


def load_manifest() -> dict[str, object]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def copy_publication_fixture(destination: Path) -> Path:
    shutil.copytree(PROJECT_ROOT / "benchmarks", destination / "benchmarks")
    (destination / "docs/research").mkdir(parents=True)
    shutil.copy2(PROJECT_ROOT / "README.md", destination / "README.md")
    shutil.copy2(
        PROJECT_ROOT / "docs/research/README.md",
        destination / "docs/research/README.md",
    )
    return destination / "benchmarks/manifests/flask-vulnerable-v1.json"


class BenchmarkPublicationTests(unittest.TestCase):
    def test_repository_publication_is_reproducible_and_consistent(self) -> None:
        metrics = check_publication(PROJECT_ROOT, MANIFEST_PATH)

        self.assertEqual(metrics["benchmark_version"], "1.0.0")
        self.assertEqual(
            len(metrics["evidence"]["runs_considered"]),
            1,
        )
        self.assertEqual(
            len(metrics["evidence"]["duplicate_runs_excluded"]),
            4,
        )
        self.assertEqual(metrics["overall"]["false_negatives"], 2)
        self.assertEqual(metrics["overall"]["precision"], 0.8)
        self.assertEqual(metrics["overall"]["recall"], 0.8)

    def test_every_match_carries_an_explanation(self) -> None:
        metrics = evaluate_manifest(PROJECT_ROOT, load_manifest())

        for tool in metrics["tools"].values():
            for decision in tool["matches"]:
                self.assertTrue(decision["matching_reason"])
                self.assertIn("included_in_metrics", decision)

    def test_invalid_artifact_hash_blocks_publication(self) -> None:
        manifest = load_manifest()
        manifest["dataset"]["sha256"] = "0" * 64

        with self.assertRaisesRegex(
            BenchmarkPublicationError,
            "hash mismatch",
        ):
            validate_manifest(PROJECT_ROOT, manifest)

    def test_missing_exact_commit_blocks_publication(self) -> None:
        manifest = load_manifest()
        manifest["runs"][0]["commit"] = "main"

        with self.assertRaisesRegex(
            BenchmarkPublicationError,
            "exact 40-character",
        ):
            validate_manifest(PROJECT_ROOT, manifest)

    def test_byte_identical_runs_cannot_both_claim_independence(self) -> None:
        manifest = load_manifest()
        manifest["runs"][1]["statistically_independent"] = True
        manifest["runs"][1].pop("duplicate_of")

        with self.assertRaisesRegex(
            BenchmarkPublicationError,
            "byte-identical",
        ):
            validate_manifest(PROJECT_ROOT, manifest)

    def test_changed_generated_document_blocks_release(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = copy_publication_fixture(root)
            write_publication(root, manifest)
            readme = root / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8").replace(
                    "| Bandit | 0.714",
                    "| Bandit | 0.999",
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                BenchmarkPublicationError,
                "inconsistent",
            ):
                check_publication(root, manifest)

    def test_every_generated_document_uses_the_same_table(self) -> None:
        documents = [
            PROJECT_ROOT / "README.md",
            PROJECT_ROOT / "benchmarks/README.md",
            PROJECT_ROOT / "docs/research/README.md",
        ]
        generated: set[str] = set()
        for document in documents:
            text = document.read_text(encoding="utf-8")
            generated.add(
                text[
                    text.index(GENERATED_START) :
                    text.index(GENERATED_END) + len(GENERATED_END)
                ]
            )

        self.assertEqual(len(generated), 1)


if __name__ == "__main__":
    unittest.main()
