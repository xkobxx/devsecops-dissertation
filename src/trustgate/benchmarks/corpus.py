"""Versioned, hash-bound multilingual benchmark corpus validation."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
import re
from typing import Any


class BenchmarkCorpusError(ValueError):
    """Raised when benchmark corpus evidence is incomplete or unsafe."""


CORPUS_SCHEMA_VERSION = "1.0.0"
DEFAULT_CORPUS = "benchmarks/corpora/multilingual-v1.json"
REQUIRED_LANGUAGES = frozenset(
    {"python", "javascript", "typescript", "java", "go", "ruby", "csharp"}
)
REQUIRED_TARGETS = frozenset(
    {"source", "infrastructure_as_code", "container", "kubernetes"}
)
REQUIRED_CLASSIFICATIONS = frozenset(
    {"vulnerable", "patched", "safe_lookalike"}
)
REQUIRED_REACHABILITY = frozenset(
    {"reachable", "unreachable", "sanitised", "not_applicable"}
)
REQUIRED_CODE_SCOPES = frozenset({"production", "test", "not_applicable"})
REQUIRED_DEPENDENCY_SCOPES = frozenset(
    {"production", "development", "not_applicable"}
)
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "corpus_id",
        "corpus_version",
        "description",
        "safety_notice",
        "required_coverage",
        "files",
        "cases",
    }
)
_COVERAGE_FIELDS = frozenset(
    {
        "languages",
        "targets",
        "classifications",
        "reachability",
        "code_scopes",
        "dependency_scopes",
        "minimum_frameworks",
        "cross_file_required",
    }
)
_FILE_FIELDS = frozenset({"path", "sha256"})
_CASE_FIELDS = frozenset(
    {
        "case_id",
        "classification",
        "vulnerability_class",
        "cwe",
        "language",
        "framework",
        "target",
        "files",
        "paired_case_id",
        "cross_file",
        "reachability",
        "code_scope",
        "dependency_scope",
        "description",
    }
)
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CWE = re.compile(r"^CWE-[1-9][0-9]*$")
_CASE_ID = re.compile(r"^[A-Z0-9][A-Z0-9-]{2,63}$")
_MAX_FIXTURE_BYTES = 1024 * 1024


def _text(value: object, *, label: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BenchmarkCorpusError(f"{label} must be a non-empty string")
    result = value.strip()
    if len(result) > maximum or any(ord(character) < 32 for character in result):
        raise BenchmarkCorpusError(f"{label} contains unsafe text")
    return result


def _string_set(value: object, *, label: str) -> set[str]:
    if not isinstance(value, list) or not value:
        raise BenchmarkCorpusError(f"{label} must be a non-empty list")
    values = {_text(item, label=f"{label} item", maximum=128) for item in value}
    if len(values) != len(value):
        raise BenchmarkCorpusError(f"{label} contains duplicates")
    return values


def _fixture_path(root: Path, value: object, *, label: str) -> tuple[str, Path]:
    logical = _text(value, label=label)
    candidate = Path(logical)
    unresolved = root / candidate
    if candidate.is_absolute() or unresolved.is_symlink():
        raise BenchmarkCorpusError(f"{label} escapes the benchmark repository")
    resolved = unresolved.resolve()
    fixture_root = (root / "benchmarks/fixtures").resolve()
    if not resolved.is_relative_to(fixture_root):
        raise BenchmarkCorpusError(f"{label} escapes the benchmark fixture root")
    if not resolved.is_file():
        raise BenchmarkCorpusError(f"{label} does not exist: {logical}")
    if resolved.stat().st_size > _MAX_FIXTURE_BYTES:
        raise BenchmarkCorpusError(f"{label} exceeds the fixture size limit")
    try:
        resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise BenchmarkCorpusError(f"{label} must be UTF-8") from error
    return resolved.relative_to(root).as_posix(), resolved


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_digest(value: object) -> str:
    content = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(content).hexdigest()


def validate_corpus(
    root: str | Path,
    corpus: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate corpus integrity, pairings, and all Phase 17.1 dimensions."""

    repository = Path(root).resolve()
    if not repository.is_dir():
        raise BenchmarkCorpusError("benchmark repository root must be a directory")
    if not isinstance(corpus, Mapping) or set(corpus) != _TOP_LEVEL_FIELDS:
        raise BenchmarkCorpusError("benchmark corpus fields are invalid")
    if corpus.get("schema_version") != CORPUS_SCHEMA_VERSION:
        raise BenchmarkCorpusError("unsupported benchmark corpus schema version")
    corpus_id = _text(corpus["corpus_id"], label="corpus_id", maximum=128)
    corpus_version = corpus["corpus_version"]
    if not isinstance(corpus_version, str) or not _SEMVER.fullmatch(corpus_version):
        raise BenchmarkCorpusError("corpus_version must be semantic")
    description = _text(corpus["description"], label="description")
    safety_notice = _text(corpus["safety_notice"], label="safety_notice")
    if "not" not in safety_notice.lower() or "deploy" not in safety_notice.lower():
        raise BenchmarkCorpusError("safety_notice must explicitly prohibit deployment")

    coverage = corpus["required_coverage"]
    if not isinstance(coverage, Mapping) or set(coverage) != _COVERAGE_FIELDS:
        raise BenchmarkCorpusError("required_coverage fields are invalid")
    declared_sets = {
        name: _string_set(coverage[name], label=f"required_coverage.{name}")
        for name in (
            "languages",
            "targets",
            "classifications",
            "reachability",
            "code_scopes",
            "dependency_scopes",
        )
    }
    mandatory_sets = {
        "languages": REQUIRED_LANGUAGES,
        "targets": REQUIRED_TARGETS,
        "classifications": REQUIRED_CLASSIFICATIONS,
        "reachability": REQUIRED_REACHABILITY,
        "code_scopes": REQUIRED_CODE_SCOPES,
        "dependency_scopes": REQUIRED_DEPENDENCY_SCOPES,
    }
    for dimension, required in mandatory_sets.items():
        if declared_sets[dimension] != required:
            raise BenchmarkCorpusError(
                f"required {dimension} coverage does not match Phase 17.1"
            )
    minimum_frameworks = coverage["minimum_frameworks"]
    if (
        isinstance(minimum_frameworks, bool)
        or not isinstance(minimum_frameworks, int)
        or minimum_frameworks < 2
    ):
        raise BenchmarkCorpusError("minimum_frameworks must be at least two")
    if coverage["cross_file_required"] is not True:
        raise BenchmarkCorpusError("cross-file coverage must be required")

    file_records = corpus["files"]
    if not isinstance(file_records, list) or not file_records:
        raise BenchmarkCorpusError("benchmark corpus requires fixture files")
    declared_files: dict[str, dict[str, Any]] = {}
    validated_files: list[dict[str, Any]] = []
    for index, record in enumerate(file_records):
        label = f"files[{index}]"
        if not isinstance(record, Mapping) or set(record) != _FILE_FIELDS:
            raise BenchmarkCorpusError(f"{label} fields are invalid")
        logical, path = _fixture_path(repository, record["path"], label=label)
        if logical in declared_files:
            raise BenchmarkCorpusError(f"duplicate fixture file {logical}")
        expected = record["sha256"]
        if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
            raise BenchmarkCorpusError(f"{label}.sha256 is invalid")
        actual = _sha256(path)
        if actual != expected:
            raise BenchmarkCorpusError(
                f"{label} hash mismatch: expected {expected}, got {actual}"
            )
        declared_files[logical] = dict(record)
        validated_files.append(
            {**record, "path": logical, "bytes": path.stat().st_size}
        )

    case_records = corpus["cases"]
    if not isinstance(case_records, list) or not case_records:
        raise BenchmarkCorpusError("benchmark corpus requires cases")
    cases: dict[str, dict[str, Any]] = {}
    observed: dict[str, set[str]] = {
        name: set()
        for name in (
            "languages",
            "targets",
            "classifications",
            "reachability",
            "code_scopes",
            "dependency_scopes",
        )
    }
    frameworks: set[str] = set()
    referenced_files: set[str] = set()
    any_cross_file = False
    for index, record in enumerate(case_records):
        label = f"cases[{index}]"
        if not isinstance(record, Mapping) or set(record) != _CASE_FIELDS:
            raise BenchmarkCorpusError(f"{label} fields are invalid")
        case_id = _text(record["case_id"], label=f"{label}.case_id", maximum=64)
        if not _CASE_ID.fullmatch(case_id) or case_id in cases:
            raise BenchmarkCorpusError(f"{label}.case_id is invalid or duplicated")
        classification = record["classification"]
        language = _text(record["language"], label=f"{label}.language", maximum=64)
        framework = _text(record["framework"], label=f"{label}.framework", maximum=128)
        target = record["target"]
        reachability = record["reachability"]
        code_scope = record["code_scope"]
        dependency_scope = record["dependency_scope"]
        values = {
            "classifications": classification,
            "targets": target,
            "reachability": reachability,
            "code_scopes": code_scope,
            "dependency_scopes": dependency_scope,
        }
        for dimension, value in values.items():
            if value not in declared_sets[dimension]:
                raise BenchmarkCorpusError(
                    f"{label}.{dimension} value is outside declared coverage"
                )
            observed[dimension].add(str(value))
        if target == "source":
            if language not in declared_sets["languages"]:
                raise BenchmarkCorpusError(
                    f"{label}.language value is outside declared coverage"
                )
            observed["languages"].add(language)
        elif language not in {"hcl", "dockerfile", "yaml"}:
            raise BenchmarkCorpusError(
                f"{label}.language is invalid for a non-source target"
            )
        cwe = record["cwe"]
        if not isinstance(cwe, str) or not _CWE.fullmatch(cwe):
            raise BenchmarkCorpusError(f"{label}.cwe is invalid")
        _text(
            record["vulnerability_class"],
            label=f"{label}.vulnerability_class",
            maximum=128,
        )
        _text(record["description"], label=f"{label}.description")
        case_files = record["files"]
        if not isinstance(case_files, list) or not case_files:
            raise BenchmarkCorpusError(f"{label}.files must be non-empty")
        if len(case_files) != len(set(case_files)):
            raise BenchmarkCorpusError(f"{label}.files contains duplicates")
        for logical in case_files:
            if not isinstance(logical, str) or logical not in declared_files:
                raise BenchmarkCorpusError(
                    f"{label} references undeclared fixture file"
                )
            referenced_files.add(logical)
        cross_file = record["cross_file"]
        if not isinstance(cross_file, bool):
            raise BenchmarkCorpusError(f"{label}.cross_file must be boolean")
        if cross_file and len(case_files) < 2:
            raise BenchmarkCorpusError(f"{label} cross-file case needs multiple files")
        any_cross_file = any_cross_file or cross_file
        paired_case_id = record["paired_case_id"]
        if paired_case_id is not None and (
            not isinstance(paired_case_id, str)
            or not _CASE_ID.fullmatch(paired_case_id)
        ):
            raise BenchmarkCorpusError(f"{label}.paired_case_id is invalid")
        cases[case_id] = dict(record)
        frameworks.add(framework)

    for dimension, required in declared_sets.items():
        if observed[dimension] != required:
            missing = sorted(required - observed[dimension])
            raise BenchmarkCorpusError(
                f"{dimension} coverage is incomplete; missing {missing}"
            )
    if len(frameworks) < minimum_frameworks:
        raise BenchmarkCorpusError("framework coverage is incomplete")
    if not any_cross_file:
        raise BenchmarkCorpusError("cross-file coverage is incomplete")
    if referenced_files != set(declared_files):
        raise BenchmarkCorpusError(
            "every declared fixture file must be referenced by a case"
        )

    for case_id, case in cases.items():
        classification = case["classification"]
        paired_id = case["paired_case_id"]
        if classification == "safe_lookalike":
            if paired_id is not None:
                raise BenchmarkCorpusError(
                    f"safe lookalike {case_id} cannot be paired as a vulnerability"
                )
            continue
        if not isinstance(paired_id, str) or paired_id not in cases:
            raise BenchmarkCorpusError(f"{case_id} has no valid paired case")
        paired = cases[paired_id]
        expected = "patched" if classification == "vulnerable" else "vulnerable"
        if (
            paired["classification"] != expected
            or paired["paired_case_id"] != case_id
            or paired["vulnerability_class"] != case["vulnerability_class"]
            or paired["cwe"] != case["cwe"]
            or paired["language"] != case["language"]
            or paired["target"] != case["target"]
            or set(paired["files"]) == set(case["files"])
        ):
            raise BenchmarkCorpusError(f"{case_id} has an inconsistent paired case")

    result: dict[str, Any] = {
        "schema_version": CORPUS_SCHEMA_VERSION,
        "corpus_id": corpus_id,
        "corpus_version": corpus_version,
        "description": description,
        "safety_notice": safety_notice,
        "coverage": {
            **{dimension: sorted(values) for dimension, values in observed.items()},
            "frameworks": sorted(frameworks),
            "cross_file": any_cross_file,
        },
        "files": validated_files,
        "cases": [cases[case_id] for case_id in sorted(cases)],
    }
    return {**result, "corpus_digest": _canonical_digest(result)}


def load_and_validate_corpus(root: str | Path, path: str | Path) -> dict[str, Any]:
    """Load a JSON corpus within root and validate its complete contract."""

    repository = Path(root).resolve()
    candidate = Path(path)
    corpus_path = (
        candidate.resolve()
        if candidate.is_absolute()
        else (repository / candidate).resolve()
    )
    if not corpus_path.is_relative_to(repository):
        raise BenchmarkCorpusError("corpus manifest path escapes repository")
    try:
        value = json.loads(corpus_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkCorpusError(
            f"could not load corpus manifest: {error}"
        ) from error
    if not isinstance(value, Mapping):
        raise BenchmarkCorpusError("corpus manifest must contain a JSON object")
    return validate_corpus(repository, value)


__all__ = [
    "BenchmarkCorpusError",
    "CORPUS_SCHEMA_VERSION",
    "DEFAULT_CORPUS",
    "load_and_validate_corpus",
    "validate_corpus",
]
