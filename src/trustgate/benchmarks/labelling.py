"""Independent benchmark review, adjudication, and partition controls."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime
import hmac
import hashlib
import json
from pathlib import Path
import re
from typing import Any


class BenchmarkLabellingError(ValueError):
    """Raised when benchmark review evidence or partitioning is invalid."""


LABELLING_SCHEMA_VERSION = "1.0.0"
DEFAULT_PARTITIONS = "benchmarks/partitions/multilingual-v1.json"
_CLASSIFICATIONS = frozenset({"vulnerable", "patched", "safe_lookalike"})
_CONFIDENCE = frozenset({"certain", "probable", "uncertain"})
_CONFIDENCE_RANK = {"certain": 0, "probable": 1, "uncertain": 2}
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_PARTITION_FIELDS = frozenset(
    {
        "schema_version",
        "partition_id",
        "partition_version",
        "corpus_digest",
        "labelling_rules",
        "development_public",
        "evaluation_public_blind",
        "evaluation_private",
        "tuning_policy",
    }
)
_RULES_REF_FIELDS = frozenset({"path", "version", "sha256"})
_DEVELOPMENT_FIELDS = frozenset({"visibility", "case_ids"})
_BLIND_FIELDS = frozenset({"visibility", "items"})
_BLIND_ITEM_FIELDS = frozenset(
    {"blind_id", "path", "sha256", "label_commitment"}
)
_PRIVATE_ITEM_FIELDS = frozenset(
    {"blind_id", "fixture_commitment", "label_commitment"}
)
_TUNING_POLICY_FIELDS = frozenset(
    {"allowed_partitions", "forbidden_partitions"}
)
_REVIEW_BODY_FIELDS = frozenset(
    {
        "schema_version",
        "review_id",
        "corpus_digest",
        "partition_digest",
        "rules_digest",
        "reviewer_id",
        "independence_attestation",
        "conflict_disclosure",
        "completed_at",
        "decisions",
    }
)
_REVIEW_FIELDS = _REVIEW_BODY_FIELDS | {"review_digest"}
_DECISION_FIELDS = frozenset(
    {"case_id", "decision", "confidence", "evidence", "rationale"}
)
_EVIDENCE_FIELDS = frozenset(
    {"path", "sha256", "line_start", "line_end"}
)
_ADJUDICATION_BODY_FIELDS = frozenset(
    {
        "schema_version",
        "adjudication_id",
        "case_id",
        "review_digests",
        "adjudicator_id",
        "decision",
        "confidence",
        "rationale",
        "adjudicated_at",
    }
)
_ADJUDICATION_FIELDS = _ADJUDICATION_BODY_FIELDS | {"adjudication_digest"}
_TUNING_FIELDS = frozenset(
    {
        "schema_version",
        "configuration_id",
        "training_partitions",
        "excluded_partitions",
    }
)


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _text(value: object, *, label: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BenchmarkLabellingError(f"{label} must be a non-empty string")
    result = value.strip()
    if len(result) > maximum or any(ord(character) < 32 for character in result):
        raise BenchmarkLabellingError(f"{label} contains unsafe text")
    return result


def _timestamp(value: object, *, label: str) -> str:
    result = _text(value, label=label, maximum=64)
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as error:
        raise BenchmarkLabellingError(
            f"{label} must be an ISO-8601 timestamp"
        ) from error
    if parsed.tzinfo is None:
        raise BenchmarkLabellingError(f"{label} must include a timezone")
    return result


def _digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise BenchmarkLabellingError(f"{label} must be a SHA-256 digest")
    return value


def _unique_text_list(value: object, *, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise BenchmarkLabellingError(f"{label} must be a non-empty list")
    result = [_text(item, label=f"{label} item", maximum=256) for item in value]
    if len(result) != len(set(result)):
        raise BenchmarkLabellingError(f"{label} contains duplicates")
    return result


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _blind_path(root: Path, value: object, *, label: str) -> tuple[str, Path]:
    logical = _text(value, label=label)
    candidate = Path(logical)
    unresolved = root / candidate
    if candidate.is_absolute() or unresolved.is_symlink():
        raise BenchmarkLabellingError(f"{label} escapes public blind fixtures")
    resolved = unresolved.resolve()
    blind_root = (root / "benchmarks/blind").resolve()
    if not resolved.is_relative_to(blind_root):
        raise BenchmarkLabellingError(f"{label} escapes public blind fixtures")
    if not resolved.is_file():
        raise BenchmarkLabellingError(f"{label} does not exist")
    if resolved.stat().st_size > 1024 * 1024:
        raise BenchmarkLabellingError(f"{label} is too large")
    try:
        resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise BenchmarkLabellingError(f"{label} must be UTF-8") from error
    return resolved.relative_to(root).as_posix(), resolved


def validate_partitions(
    root: str | Path,
    corpus: Mapping[str, Any],
    partition: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate disjoint public development, public blind, and private sets."""

    repository = Path(root).resolve()
    if not repository.is_dir():
        raise BenchmarkLabellingError("repository root must be a directory")
    if not isinstance(partition, Mapping) or set(partition) != _PARTITION_FIELDS:
        raise BenchmarkLabellingError("partition fields are invalid")
    if partition.get("schema_version") != LABELLING_SCHEMA_VERSION:
        raise BenchmarkLabellingError("unsupported partition schema version")
    partition_id = _text(partition["partition_id"], label="partition_id")
    version = partition["partition_version"]
    if not isinstance(version, str) or not _SEMVER.fullmatch(version):
        raise BenchmarkLabellingError("partition_version must be semantic")
    corpus_digest = _digest(partition["corpus_digest"], label="corpus_digest")
    if corpus_digest != corpus.get("corpus_digest"):
        raise BenchmarkLabellingError("partition is not bound to this corpus")
    rules = partition["labelling_rules"]
    if not isinstance(rules, Mapping) or set(rules) != _RULES_REF_FIELDS:
        raise BenchmarkLabellingError("labelling_rules fields are invalid")
    rules_logical = _text(rules["path"], label="labelling_rules.path")
    rules_candidate = Path(rules_logical)
    rules_path = (repository / rules_candidate).resolve()
    rules_root = (repository / "benchmarks/labelling").resolve()
    if (
        rules_candidate.is_absolute()
        or not rules_path.is_relative_to(rules_root)
        or not rules_path.is_file()
        or (repository / rules_candidate).is_symlink()
    ):
        raise BenchmarkLabellingError("labelling rules path is unsafe or missing")
    rules_version = rules["version"]
    if not isinstance(rules_version, str) or not _SEMVER.fullmatch(rules_version):
        raise BenchmarkLabellingError("labelling rules version must be semantic")
    expected_rules_hash = rules["sha256"]
    if (
        not isinstance(expected_rules_hash, str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_rules_hash)
    ):
        raise BenchmarkLabellingError("labelling rules sha256 is invalid")
    actual_rules_hash = _sha256(rules_path)
    if actual_rules_hash != expected_rules_hash:
        raise BenchmarkLabellingError("labelling rules hash mismatch")
    try:
        rules_document = json.loads(rules_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkLabellingError(
            "labelling rules are not valid UTF-8 JSON"
        ) from error
    if (
        not isinstance(rules_document, Mapping)
        or rules_document.get("schema_version") != LABELLING_SCHEMA_VERSION
        or rules_document.get("rules_version") != rules_version
    ):
        raise BenchmarkLabellingError("labelling rules version binding is invalid")
    rules_digest = "sha256:" + actual_rules_hash

    development = partition["development_public"]
    if not isinstance(development, Mapping) or set(development) != _DEVELOPMENT_FIELDS:
        raise BenchmarkLabellingError("development_public fields are invalid")
    if development.get("visibility") != "public":
        raise BenchmarkLabellingError("development partition must be public")
    development_ids = _unique_text_list(
        development["case_ids"], label="development case_ids"
    )
    corpus_ids = {case["case_id"] for case in corpus.get("cases", [])}
    if set(development_ids) != corpus_ids:
        raise BenchmarkLabellingError(
            "development partition must contain every labelled corpus case"
        )

    public_blind = partition["evaluation_public_blind"]
    if not isinstance(public_blind, Mapping) or set(public_blind) != _BLIND_FIELDS:
        raise BenchmarkLabellingError("evaluation_public_blind fields are invalid")
    if public_blind.get("visibility") != "public_labels_withheld":
        raise BenchmarkLabellingError("public blind labels must be withheld")
    blind_items = public_blind["items"]
    if not isinstance(blind_items, list) or not blind_items:
        raise BenchmarkLabellingError("public blind partition cannot be empty")
    corpus_hashes = {record["sha256"] for record in corpus.get("files", [])}
    validated_blind: list[dict[str, str]] = []
    blind_ids: set[str] = set()
    blind_hashes: set[str] = set()
    for index, item in enumerate(blind_items):
        label = f"evaluation_public_blind.items[{index}]"
        if not isinstance(item, Mapping) or set(item) != _BLIND_ITEM_FIELDS:
            raise BenchmarkLabellingError(f"{label} fields are invalid")
        blind_id = _text(item["blind_id"], label=f"{label}.blind_id", maximum=128)
        if blind_id in blind_ids:
            raise BenchmarkLabellingError("public blind IDs overlap")
        blind_ids.add(blind_id)
        logical, path = _blind_path(repository, item["path"], label=f"{label}.path")
        expected = item["sha256"]
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise BenchmarkLabellingError(f"{label}.sha256 is invalid")
        actual = _sha256(path)
        if actual != expected:
            raise BenchmarkLabellingError(
                f"{label} hash mismatch: expected {expected}, got {actual}"
            )
        if actual in corpus_hashes or actual in blind_hashes:
            raise BenchmarkLabellingError(
                "public blind fixture overlaps development data"
            )
        blind_hashes.add(actual)
        commitment = _digest(
            item["label_commitment"], label=f"{label}.label_commitment"
        )
        validated_blind.append(
            {
                "blind_id": blind_id,
                "path": logical,
                "sha256": actual,
                "label_commitment": commitment,
            }
        )

    private = partition["evaluation_private"]
    if not isinstance(private, Mapping) or set(private) != _BLIND_FIELDS:
        raise BenchmarkLabellingError("evaluation_private fields are invalid")
    if private.get("visibility") != "commitments_only":
        raise BenchmarkLabellingError("private partition may publish only commitments")
    private_items = private["items"]
    if not isinstance(private_items, list) or not private_items:
        raise BenchmarkLabellingError("private evaluation partition cannot be empty")
    validated_private: list[dict[str, str]] = []
    private_ids: set[str] = set()
    fixture_commitments: set[str] = set()
    for index, item in enumerate(private_items):
        label = f"evaluation_private.items[{index}]"
        if not isinstance(item, Mapping) or set(item) != _PRIVATE_ITEM_FIELDS:
            raise BenchmarkLabellingError(f"{label} fields are invalid")
        blind_id = _text(item["blind_id"], label=f"{label}.blind_id", maximum=128)
        if blind_id in private_ids:
            raise BenchmarkLabellingError("private blind IDs overlap")
        private_ids.add(blind_id)
        fixture_commitment = _digest(
            item["fixture_commitment"], label=f"{label}.fixture_commitment"
        )
        if fixture_commitment in fixture_commitments:
            raise BenchmarkLabellingError("private fixture commitments overlap")
        fixture_commitments.add(fixture_commitment)
        validated_private.append(
            {
                "blind_id": blind_id,
                "fixture_commitment": fixture_commitment,
                "label_commitment": _digest(
                    item["label_commitment"], label=f"{label}.label_commitment"
                ),
            }
        )
    if set(development_ids) & blind_ids or set(development_ids) & private_ids:
        raise BenchmarkLabellingError("partition identifiers overlap")
    if blind_ids & private_ids:
        raise BenchmarkLabellingError("public and private blind identifiers overlap")

    tuning = partition["tuning_policy"]
    if not isinstance(tuning, Mapping) or set(tuning) != _TUNING_POLICY_FIELDS:
        raise BenchmarkLabellingError("tuning_policy fields are invalid")
    allowed = _unique_text_list(
        tuning["allowed_partitions"], label="allowed_partitions"
    )
    forbidden = _unique_text_list(
        tuning["forbidden_partitions"], label="forbidden_partitions"
    )
    if set(allowed) != {"development_public"} or set(forbidden) != {
        "evaluation_public_blind",
        "evaluation_private",
    }:
        raise BenchmarkLabellingError("tuning policy permits benchmark leakage")

    body: dict[str, Any] = {
        "schema_version": LABELLING_SCHEMA_VERSION,
        "partition_id": partition_id,
        "partition_version": version,
        "corpus_digest": corpus_digest,
        "rules_digest": rules_digest,
        "development_case_ids": sorted(development_ids),
        "public_blind_items": sorted(
            validated_blind, key=lambda item: item["blind_id"]
        ),
        "private_commitments": sorted(
            validated_private, key=lambda item: item["blind_id"]
        ),
        "tuning_policy": {
            "allowed_partitions": sorted(allowed),
            "forbidden_partitions": sorted(forbidden),
        },
    }
    return {**body, "partition_digest": _canonical_digest(body)}


def seal_review(review: Mapping[str, Any]) -> dict[str, Any]:
    """Return an integrity-bound review record."""

    if not isinstance(review, Mapping) or set(review) != _REVIEW_BODY_FIELDS:
        raise BenchmarkLabellingError("review fields are invalid")
    body = deepcopy(dict(review))
    return {**body, "review_digest": _canonical_digest(body)}


def seal_adjudication(adjudication: Mapping[str, Any]) -> dict[str, Any]:
    """Return an integrity-bound disagreement adjudication."""

    if (
        not isinstance(adjudication, Mapping)
        or set(adjudication) != _ADJUDICATION_BODY_FIELDS
    ):
        raise BenchmarkLabellingError("adjudication fields are invalid")
    body = deepcopy(dict(adjudication))
    return {**body, "adjudication_digest": _canonical_digest(body)}


def create_label_commitment(
    blind_id: str,
    decision: str,
    salt: str,
) -> str:
    """Commit a withheld blind label without publishing the label or salt."""

    identifier = _text(blind_id, label="blind_id", maximum=128)
    if decision not in _CLASSIFICATIONS:
        raise BenchmarkLabellingError("blind label decision is invalid")
    secret = _text(salt, label="blind label salt", maximum=1024)
    if len(secret) < 16:
        raise BenchmarkLabellingError(
            "blind label salt must contain at least 16 characters"
        )
    return _canonical_digest(
        {"blind_id": identifier, "decision": decision, "salt": secret}
    )


def verify_label_commitment(
    commitment: str,
    blind_id: str,
    decision: str,
    salt: str,
) -> bool:
    """Verify a blind label after the evaluation result is frozen."""

    expected = _digest(commitment, label="label_commitment")
    actual = create_label_commitment(blind_id, decision, salt)
    return hmac.compare_digest(expected, actual)


def create_review_template(
    corpus: Mapping[str, Any],
    partitions: Mapping[str, Any],
    reviewer_id: str,
) -> dict[str, Any]:
    """Create an incomplete review draft without asserted classifications."""

    identity = _text(reviewer_id, label="reviewer_id", maximum=128)
    file_hashes = {
        record["path"]: record["sha256"] for record in corpus.get("files", [])
    }
    cases = {case["case_id"]: case for case in corpus.get("cases", [])}
    decisions = []
    for case_id in sorted(partitions.get("development_case_ids", [])):
        case = cases[case_id]
        path = case["files"][0]
        decisions.append(
            {
                "case_id": case_id,
                "decision": None,
                "confidence": None,
                "evidence": [
                    {
                        "path": path,
                        "sha256": file_hashes[path],
                        "line_start": 1,
                        "line_end": 1,
                    }
                ],
                "rationale": "",
            }
        )
    return {
        "schema_version": LABELLING_SCHEMA_VERSION,
        "review_id": f"review-{identity}-DRAFT",
        "corpus_digest": corpus["corpus_digest"],
        "partition_digest": partitions["partition_digest"],
        "rules_digest": partitions["rules_digest"],
        "reviewer_id": identity,
        "independence_attestation": False,
        "conflict_disclosure": "",
        "completed_at": "",
        "decisions": decisions,
    }


def _validate_review(
    corpus: Mapping[str, Any],
    partitions: Mapping[str, Any],
    review: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(review, Mapping) or set(review) != _REVIEW_FIELDS:
        raise BenchmarkLabellingError("review record fields are invalid")
    body = {
        key: deepcopy(value)
        for key, value in review.items()
        if key != "review_digest"
    }
    if review["review_digest"] != _canonical_digest(body):
        raise BenchmarkLabellingError("review record integrity check failed")
    if review.get("schema_version") != LABELLING_SCHEMA_VERSION:
        raise BenchmarkLabellingError("unsupported review schema version")
    if review.get("corpus_digest") != corpus.get("corpus_digest"):
        raise BenchmarkLabellingError("review is not bound to this corpus")
    if review.get("partition_digest") != partitions.get("partition_digest"):
        raise BenchmarkLabellingError("review is not bound to these partitions")
    if review.get("rules_digest") != partitions.get("rules_digest"):
        raise BenchmarkLabellingError("review is not bound to the labelling rules")
    _text(review["review_id"], label="review_id", maximum=128)
    reviewer_id = _text(review["reviewer_id"], label="reviewer_id", maximum=128)
    if review["independence_attestation"] is not True:
        raise BenchmarkLabellingError("reviewer must attest independent review")
    _text(review["conflict_disclosure"], label="conflict_disclosure", maximum=1024)
    _timestamp(review["completed_at"], label="completed_at")
    decisions = review["decisions"]
    if not isinstance(decisions, list) or not decisions:
        raise BenchmarkLabellingError("review must contain decisions")
    corpus_cases = {case["case_id"]: case for case in corpus.get("cases", [])}
    file_hashes = {
        record["path"]: record["sha256"]
        for record in corpus.get("files", [])
    }
    validated: dict[str, dict[str, Any]] = {}
    for index, decision in enumerate(decisions):
        label = f"decisions[{index}]"
        if not isinstance(decision, Mapping) or set(decision) != _DECISION_FIELDS:
            raise BenchmarkLabellingError(f"{label} fields are invalid")
        case_id = _text(decision["case_id"], label=f"{label}.case_id", maximum=128)
        case = corpus_cases.get(case_id)
        if case is None or case_id in validated:
            raise BenchmarkLabellingError(f"{label} case is unknown or duplicated")
        classification = decision["decision"]
        if classification not in _CLASSIFICATIONS:
            raise BenchmarkLabellingError(f"{label}.decision is invalid")
        confidence = decision["confidence"]
        if confidence not in _CONFIDENCE:
            raise BenchmarkLabellingError(f"{label}.confidence is invalid")
        _text(decision["rationale"], label=f"{label}.rationale")
        evidence = decision["evidence"]
        if not isinstance(evidence, list) or not evidence:
            raise BenchmarkLabellingError(f"{label}.evidence is required")
        validated_evidence: list[dict[str, Any]] = []
        for evidence_index, item in enumerate(evidence):
            evidence_label = f"{label}.evidence[{evidence_index}]"
            if not isinstance(item, Mapping) or set(item) != _EVIDENCE_FIELDS:
                raise BenchmarkLabellingError(f"{evidence_label} fields are invalid")
            path = item["path"]
            if path not in case["files"] or item["sha256"] != file_hashes.get(path):
                raise BenchmarkLabellingError(
                    f"{evidence_label} is not bound to case fixture evidence"
                )
            start = item["line_start"]
            end = item["line_end"]
            if (
                isinstance(start, bool)
                or not isinstance(start, int)
                or isinstance(end, bool)
                or not isinstance(end, int)
                or start < 1
                or end < start
            ):
                raise BenchmarkLabellingError(f"{evidence_label} line range is invalid")
            validated_evidence.append(dict(item))
        validated[case_id] = {
            "reviewer_id": reviewer_id,
            "decision": classification,
            "confidence": confidence,
            "evidence": validated_evidence,
            "rationale": decision["rationale"],
        }
    if set(validated) != set(partitions.get("development_case_ids", [])):
        raise BenchmarkLabellingError("review must decide every development case")
    return {
        "review_id": review["review_id"],
        "review_digest": review["review_digest"],
        "reviewer_id": reviewer_id,
        "completed_at": review["completed_at"],
        "conflict_disclosure": review["conflict_disclosure"],
        "decisions": validated,
    }


def _agreement(first: list[str], second: list[str]) -> tuple[float, float]:
    total = len(first)
    matches = sum(left == right for left, right in zip(first, second, strict=True))
    observed = matches / total
    first_counts = Counter(first)
    second_counts = Counter(second)
    expected = sum(
        (first_counts[label] / total) * (second_counts[label] / total)
        for label in _CLASSIFICATIONS
    )
    if expected == 1.0:
        kappa = 1.0 if observed == 1.0 else 0.0
    else:
        kappa = (observed - expected) / (1.0 - expected)
    return round(observed, 6), round(kappa, 6)


def evaluate_reviews(
    corpus: Mapping[str, Any],
    partitions: Mapping[str, Any],
    reviews: list[Mapping[str, Any]],
    adjudications: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """Combine exactly two independent reviews and adjudicate disagreements."""

    if not isinstance(reviews, list) or len(reviews) != 2:
        raise BenchmarkLabellingError("exactly two independent reviews are required")
    validated = [
        _validate_review(corpus, partitions, review) for review in reviews
    ]
    reviewer_ids = {review["reviewer_id"] for review in validated}
    review_ids = {review["review_id"] for review in validated}
    review_digests = {review["review_digest"] for review in validated}
    if len(reviewer_ids) != 2 or len(review_ids) != 2 or len(review_digests) != 2:
        raise BenchmarkLabellingError(
            "reviews must have distinct independent reviewers"
        )
    case_ids = sorted(partitions.get("development_case_ids", []))
    first_values = [
        validated[0]["decisions"][case_id]["decision"] for case_id in case_ids
    ]
    second_values = [
        validated[1]["decisions"][case_id]["decision"] for case_id in case_ids
    ]
    raw_agreement, kappa = _agreement(first_values, second_values)
    disagreements = [
        case_id
        for case_id, first, second in zip(
            case_ids, first_values, second_values, strict=True
        )
        if first != second
    ]

    if not isinstance(adjudications, list):
        raise BenchmarkLabellingError("adjudications must be a list")
    adjudication_by_case: dict[str, dict[str, Any]] = {}
    for item in adjudications:
        if not isinstance(item, Mapping) or set(item) != _ADJUDICATION_FIELDS:
            raise BenchmarkLabellingError("adjudication record fields are invalid")
        body = {
            key: deepcopy(value)
            for key, value in item.items()
            if key != "adjudication_digest"
        }
        if item["adjudication_digest"] != _canonical_digest(body):
            raise BenchmarkLabellingError("adjudication integrity check failed")
        if item.get("schema_version") != LABELLING_SCHEMA_VERSION:
            raise BenchmarkLabellingError("unsupported adjudication schema version")
        case_id = _text(item["case_id"], label="adjudication case_id", maximum=128)
        if case_id not in disagreements or case_id in adjudication_by_case:
            raise BenchmarkLabellingError(
                "adjudication does not match one disagreement"
            )
        if set(item["review_digests"]) != review_digests:
            raise BenchmarkLabellingError("adjudication is not bound to both reviews")
        adjudicator = _text(
            item["adjudicator_id"], label="adjudicator_id", maximum=128
        )
        if adjudicator in reviewer_ids:
            raise BenchmarkLabellingError(
                "adjudicator must be independent of reviewers"
            )
        if item["decision"] not in _CLASSIFICATIONS:
            raise BenchmarkLabellingError("adjudication decision is invalid")
        if item["confidence"] not in _CONFIDENCE:
            raise BenchmarkLabellingError("adjudication confidence is invalid")
        _text(item["adjudication_id"], label="adjudication_id", maximum=128)
        _text(item["rationale"], label="adjudication rationale")
        _timestamp(item["adjudicated_at"], label="adjudicated_at")
        adjudication_by_case[case_id] = dict(item)
    if set(adjudication_by_case) != set(disagreements):
        missing = sorted(set(disagreements) - set(adjudication_by_case))
        raise BenchmarkLabellingError(
            "every disagreement requires adjudication: " + ", ".join(missing)
        )

    labels: list[dict[str, Any]] = []
    for case_id in case_ids:
        decisions = [review["decisions"][case_id] for review in validated]
        adjudication = adjudication_by_case.get(case_id)
        if adjudication is not None:
            decision = adjudication["decision"]
            uncertainty = adjudication["confidence"]
            source = "adjudication"
        else:
            decision = decisions[0]["decision"]
            uncertainty = max(
                (item["confidence"] for item in decisions),
                key=lambda value: _CONFIDENCE_RANK[value],
            )
            source = "reviewer_agreement"
        labels.append(
            {
                "case_id": case_id,
                "decision": decision,
                "uncertainty": uncertainty,
                "decision_source": source,
                "reviewer_decisions": decisions,
                "adjudication_digest": (
                    adjudication["adjudication_digest"]
                    if adjudication is not None
                    else None
                ),
            }
        )
    body: dict[str, Any] = {
        "schema_version": LABELLING_SCHEMA_VERSION,
        "status": "reviewed_with_adjudication" if disagreements else "reviewed",
        "corpus_digest": corpus["corpus_digest"],
        "partition_digest": partitions["partition_digest"],
        "rules_digest": partitions["rules_digest"],
        "reviewer_count": 2,
        "review_digests": sorted(review_digests),
        "agreement": {
            "method": "cohens_kappa",
            "items": len(case_ids),
            "raw_agreement": raw_agreement,
            "cohens_kappa": kappa,
        },
        "disagreements": disagreements,
        "labels": labels,
    }
    return {**body, "labelling_digest": _canonical_digest(body)}


def validate_tuning_inputs(
    partitions: Mapping[str, Any],
    configuration: Mapping[str, Any],
) -> dict[str, Any]:
    """Fail closed when blind or private partitions enter rule tuning."""

    if not isinstance(configuration, Mapping) or set(configuration) != _TUNING_FIELDS:
        raise BenchmarkLabellingError("tuning configuration fields are invalid")
    if configuration.get("schema_version") != LABELLING_SCHEMA_VERSION:
        raise BenchmarkLabellingError("unsupported tuning configuration version")
    configuration_id = _text(
        configuration["configuration_id"], label="configuration_id", maximum=128
    )
    training = _unique_text_list(
        configuration["training_partitions"], label="training_partitions"
    )
    excluded = _unique_text_list(
        configuration["excluded_partitions"], label="excluded_partitions"
    )
    policy = partitions.get("tuning_policy")
    if not isinstance(policy, Mapping):
        raise BenchmarkLabellingError("partition tuning policy is missing")
    allowed = set(policy["allowed_partitions"])
    forbidden = set(policy["forbidden_partitions"])
    if not set(training).issubset(allowed) or forbidden & set(training):
        raise BenchmarkLabellingError("benchmark leakage detected in tuning inputs")
    if not forbidden.issubset(set(excluded)):
        raise BenchmarkLabellingError("benchmark leakage exclusions are incomplete")
    body = {
        "schema_version": LABELLING_SCHEMA_VERSION,
        "status": "leakage_controls_passed",
        "configuration_id": configuration_id,
        "partition_digest": partitions["partition_digest"],
        "training_partitions": sorted(training),
        "excluded_partitions": sorted(excluded),
    }
    return {**body, "control_digest": _canonical_digest(body)}


__all__ = [
    "BenchmarkLabellingError",
    "DEFAULT_PARTITIONS",
    "LABELLING_SCHEMA_VERSION",
    "evaluate_reviews",
    "create_label_commitment",
    "create_review_template",
    "seal_adjudication",
    "seal_review",
    "validate_partitions",
    "validate_tuning_inputs",
    "verify_label_commitment",
]
