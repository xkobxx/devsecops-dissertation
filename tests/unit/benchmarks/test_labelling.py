"""Tests for independent benchmark labelling and partition controls."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.cli import main as cli_main
from trustgate.benchmarks.corpus import validate_corpus
from trustgate.benchmarks.labelling import (
    BenchmarkLabellingError,
    create_label_commitment,
    create_review_template,
    evaluate_reviews,
    seal_adjudication,
    seal_review,
    validate_partitions,
    validate_tuning_inputs,
    verify_label_commitment,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
CORPUS_PATH = PROJECT_ROOT / "benchmarks/corpora/multilingual-v1.json"
PARTITIONS_PATH = PROJECT_ROOT / "benchmarks/partitions/multilingual-v1.json"


def corpus_result() -> dict[str, object]:
    value = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    return validate_corpus(PROJECT_ROOT, value)


def partition_result(corpus: dict[str, object]) -> dict[str, object]:
    value = json.loads(PARTITIONS_PATH.read_text(encoding="utf-8"))
    return validate_partitions(PROJECT_ROOT, corpus, value)


def review(
    corpus: dict[str, object],
    partitions: dict[str, object],
    reviewer_id: str,
    *,
    override: dict[str, str] | None = None,
) -> dict[str, object]:
    file_hashes = {record["path"]: record["sha256"] for record in corpus["files"]}
    decisions = []
    for case in corpus["cases"]:
        if case["case_id"] not in partitions["development_case_ids"]:
            continue
        path = case["files"][0]
        decisions.append(
            {
                "case_id": case["case_id"],
                "decision": (override or {}).get(
                    case["case_id"], case["classification"]
                ),
                "confidence": "certain",
                "evidence": [
                    {
                        "path": path,
                        "sha256": file_hashes[path],
                        "line_start": 1,
                        "line_end": 1,
                    }
                ],
                "rationale": (
                    "The recorded source pattern and paired equivalent "
                    "support this decision."
                ),
            }
        )
    return seal_review(
        {
            "schema_version": "1.0.0",
            "review_id": "review-" + reviewer_id,
            "corpus_digest": corpus["corpus_digest"],
            "partition_digest": partitions["partition_digest"],
            "rules_digest": partitions["rules_digest"],
            "reviewer_id": reviewer_id,
            "independence_attestation": True,
            "conflict_disclosure": "none",
            "completed_at": "2026-08-09T12:00:00Z",
            "decisions": decisions,
        }
    )


class BenchmarkLabellingTests(unittest.TestCase):
    def test_review_template_withholds_labels_and_commitments_open_exactly(
        self,
    ) -> None:
        corpus = corpus_result()
        partitions = partition_result(corpus)

        template = create_review_template(corpus, partitions, "reviewer-alpha")

        self.assertEqual(len(template["decisions"]), 27)
        self.assertTrue(all(item["decision"] is None for item in template["decisions"]))
        self.assertNotIn("classification", json.dumps(template))
        commitment = create_label_commitment(
            "BLIND-TEST-001", "vulnerable", "a-secret-salt-value"
        )
        self.assertTrue(
            verify_label_commitment(
                commitment,
                "BLIND-TEST-001",
                "vulnerable",
                "a-secret-salt-value",
            )
        )
        self.assertFalse(
            verify_label_commitment(
                commitment,
                "BLIND-TEST-001",
                "patched",
                "a-secret-salt-value",
            )
        )

    def test_cli_checks_partitions_and_publishes_review_receipt(self) -> None:
        self.assertEqual(cli_main(["benchmark", "--partition-check"]), 0)
        corpus = corpus_result()
        partitions = partition_result(corpus)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            review_paths = []
            for reviewer_id in ("reviewer-alpha", "reviewer-beta"):
                path = root / f"{reviewer_id}.json"
                path.write_text(
                    json.dumps(review(corpus, partitions, reviewer_id)),
                    encoding="utf-8",
                )
                review_paths.append(path)
            output = root / "labelling.json"

            result = cli_main(
                [
                    "benchmark",
                    "--labelling-check",
                    "--review",
                    str(review_paths[0]),
                    "--review",
                    str(review_paths[1]),
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(result, 0)
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(receipt["status"], "reviewed")
            self.assertEqual(receipt["agreement"]["cohens_kappa"], 1.0)

    def test_partitions_separate_public_blind_and_private_data(self) -> None:
        corpus = corpus_result()
        partitions = partition_result(corpus)

        self.assertEqual(len(partitions["development_case_ids"]), 27)
        self.assertTrue(partitions["public_blind_items"])
        self.assertTrue(partitions["private_commitments"])
        self.assertEqual(
            partitions["tuning_policy"],
            {
                "allowed_partitions": ["development_public"],
                "forbidden_partitions": [
                    "evaluation_private",
                    "evaluation_public_blind",
                ],
            },
        )
        self.assertFalse(
            set(partitions["development_case_ids"])
            & {item["blind_id"] for item in partitions["public_blind_items"]}
        )

    def test_two_reviews_produce_reproducible_agreement_metrics(self) -> None:
        corpus = corpus_result()
        partitions = partition_result(corpus)
        reviews = [
            review(corpus, partitions, "reviewer-alpha"),
            review(corpus, partitions, "reviewer-beta"),
        ]

        first = evaluate_reviews(corpus, partitions, reviews, [])
        second = evaluate_reviews(corpus, partitions, reviews, [])

        self.assertEqual(first, second)
        self.assertEqual(first["status"], "reviewed")
        self.assertEqual(first["reviewer_count"], 2)
        self.assertEqual(first["agreement"]["raw_agreement"], 1.0)
        self.assertEqual(first["agreement"]["cohens_kappa"], 1.0)
        self.assertEqual(first["disagreements"], [])
        self.assertTrue(
            all(label["uncertainty"] == "certain" for label in first["labels"])
        )
        self.assertRegex(first["labelling_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_disagreement_requires_independent_adjudication(self) -> None:
        corpus = corpus_result()
        partitions = partition_result(corpus)
        case_id = partitions["development_case_ids"][0]
        reviews = [
            review(corpus, partitions, "reviewer-alpha"),
            review(
                corpus,
                partitions,
                "reviewer-beta",
                override={case_id: "safe_lookalike"},
            ),
        ]

        with self.assertRaisesRegex(BenchmarkLabellingError, "adjudication"):
            evaluate_reviews(corpus, partitions, reviews, [])

        adjudication = seal_adjudication(
            {
                "schema_version": "1.0.0",
                "adjudication_id": "adjudication-1",
                "case_id": case_id,
                "review_digests": [review["review_digest"] for review in reviews],
                "adjudicator_id": "adjudicator-gamma",
                "decision": "vulnerable",
                "confidence": "probable",
                "rationale": (
                    "The source reaches the unsafe sink; the patched pair "
                    "removes that flow."
                ),
                "adjudicated_at": "2026-08-09T13:00:00Z",
            }
        )
        result = evaluate_reviews(corpus, partitions, reviews, [adjudication])

        self.assertEqual(result["status"], "reviewed_with_adjudication")
        self.assertEqual(result["disagreements"], [case_id])
        label = next(label for label in result["labels"] if label["case_id"] == case_id)
        self.assertEqual(label["decision"], "vulnerable")
        self.assertEqual(label["uncertainty"], "probable")
        self.assertEqual(label["decision_source"], "adjudication")

        same_person = deepcopy(adjudication)
        same_person.pop("adjudication_digest")
        same_person["adjudicator_id"] = "reviewer-alpha"
        same_person = seal_adjudication(same_person)
        with self.assertRaisesRegex(BenchmarkLabellingError, "independent"):
            evaluate_reviews(corpus, partitions, reviews, [same_person])

    def test_missing_decisions_and_tuning_leakage_fail_closed(self) -> None:
        corpus = corpus_result()
        partitions = partition_result(corpus)
        complete = review(corpus, partitions, "reviewer-alpha")
        incomplete_body = deepcopy(complete)
        incomplete_body.pop("review_digest")
        incomplete_body["decisions"].pop()
        incomplete = seal_review(incomplete_body)

        with self.assertRaisesRegex(BenchmarkLabellingError, "every development case"):
            evaluate_reviews(
                corpus,
                partitions,
                [incomplete, review(corpus, partitions, "reviewer-beta")],
                [],
            )
        with self.assertRaisesRegex(BenchmarkLabellingError, "distinct"):
            evaluate_reviews(corpus, partitions, [complete, complete], [])

        self.assertEqual(
            validate_tuning_inputs(
                partitions,
                {
                    "schema_version": "1.0.0",
                    "configuration_id": "rules-v2",
                    "training_partitions": ["development_public"],
                    "excluded_partitions": [
                        "evaluation_public_blind",
                        "evaluation_private",
                    ],
                },
            )["status"],
            "leakage_controls_passed",
        )
        leaking = {
            "schema_version": "1.0.0",
            "configuration_id": "rules-v2",
            "training_partitions": ["evaluation_public_blind"],
            "excluded_partitions": ["evaluation_private"],
        }
        with self.assertRaisesRegex(BenchmarkLabellingError, "leakage"):
            validate_tuning_inputs(partitions, leaking)

    def test_partition_tampering_and_private_paths_are_rejected(self) -> None:
        corpus = corpus_result()
        partition = json.loads(PARTITIONS_PATH.read_text(encoding="utf-8"))
        partition["evaluation_public_blind"]["items"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(BenchmarkLabellingError, "hash mismatch"):
            validate_partitions(PROJECT_ROOT, corpus, partition)

        overlap = json.loads(PARTITIONS_PATH.read_text(encoding="utf-8"))
        overlap["evaluation_public_blind"]["items"][0]["blind_id"] = overlap[
            "development_public"
        ]["case_ids"][0]
        with self.assertRaisesRegex(BenchmarkLabellingError, "overlap"):
            validate_partitions(PROJECT_ROOT, corpus, overlap)

        private_path = json.loads(PARTITIONS_PATH.read_text(encoding="utf-8"))
        private_path["evaluation_private"]["items"][0]["path"] = "private.json"
        with self.assertRaisesRegex(BenchmarkLabellingError, "fields"):
            validate_partitions(PROJECT_ROOT, corpus, private_path)


if __name__ == "__main__":
    unittest.main()
