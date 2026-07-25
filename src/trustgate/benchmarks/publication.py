"""Single-source benchmark evaluation, generation, and publication checks."""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import tempfile
from typing import Any

from .matching import MATCHING_METHODOLOGY_VERSION, match_findings
from .statistics import (
    CONFIDENCE_METHODOLOGY_VERSION,
    classification_metrics,
    posterior_precision,
    probability_vector,
)


BENCHMARK_ARTIFACT_VERSION = "1.0.0"
DEFAULT_MANIFEST = "benchmarks/manifests/flask-vulnerable-v1.json"
GENERATED_START = "<!-- trustgate:benchmark-metrics:start -->"
GENERATED_END = "<!-- trustgate:benchmark-metrics:end -->"
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class BenchmarkPublicationError(ValueError):
    """Raised when benchmark evidence cannot be published safely."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BenchmarkPublicationError(f"could not load {path}: {error}") from error
    if not isinstance(value, dict):
        raise BenchmarkPublicationError(f"{path} must contain a JSON object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _path(root: Path, value: Any, *, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise BenchmarkPublicationError(f"{label} path must be a non-empty string")
    resolved = (root / value).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise BenchmarkPublicationError(
            f"{label} path escapes the repository: {value}"
        ) from error
    return resolved


def _version(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not _SEMVER.fullmatch(value):
        raise BenchmarkPublicationError(f"{label} must be a semantic version")
    return value


def _artifact(
    root: Path,
    record: Any,
    *,
    label: str,
) -> tuple[Path, dict[str, Any]]:
    if not isinstance(record, dict):
        raise BenchmarkPublicationError(f"{label} must be an object")
    path = _path(root, record.get("path"), label=label)
    if not path.is_file():
        raise BenchmarkPublicationError(f"{label} does not exist: {path}")
    expected = record.get("sha256")
    if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
        raise BenchmarkPublicationError(f"{label} sha256 must be 64 lowercase hex")
    actual = _sha256(path)
    if actual != expected:
        raise BenchmarkPublicationError(
            f"{label} hash mismatch: expected {expected}, got {actual}"
        )
    _version(record.get("version"), label=f"{label} version")
    return path, record


def validate_manifest(
    root: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Validate all version, hash, commit, and independence claims."""

    root = root.resolve()
    _version(
        manifest.get("schema_version"),
        label="manifest schema_version",
    )
    _version(
        manifest.get("benchmark_version"),
        label="benchmark_version",
    )
    methodology = manifest.get("methodology")
    if not isinstance(methodology, dict):
        raise BenchmarkPublicationError("methodology must be an object")
    if methodology.get("matching_version") != MATCHING_METHODOLOGY_VERSION:
        raise BenchmarkPublicationError(
            "manifest matching methodology does not match the runtime"
        )
    if methodology.get("confidence_version") != CONFIDENCE_METHODOLOGY_VERSION:
        raise BenchmarkPublicationError(
            "manifest confidence methodology does not match the runtime"
        )

    for directory in (
        "benchmarks/datasets",
        "benchmarks/ground_truth",
        "benchmarks/configurations",
        "benchmarks/results",
        "benchmarks/reports",
        "benchmarks/manifests",
    ):
        if not (root / directory).is_dir():
            raise BenchmarkPublicationError(
                f"required benchmark directory is missing: {directory}"
            )

    dataset_path, _ = _artifact(root, manifest.get("dataset"), label="dataset")
    ground_truth_path, _ = _artifact(
        root,
        manifest.get("ground_truth"),
        label="ground_truth",
    )
    configuration_path, _ = _artifact(
        root,
        manifest.get("configuration"),
        label="configuration",
    )
    rules_path, _ = _artifact(root, manifest.get("rules"), label="rules")
    adjudications_path, _ = _artifact(
        root,
        manifest.get("adjudications"),
        label="adjudications",
    )

    dataset = _load_json(dataset_path)
    ground_truth = _load_json(ground_truth_path)
    configuration = _load_json(configuration_path)
    rules = _load_json(rules_path)
    adjudications = _load_json(adjudications_path)
    benchmark_version = manifest["benchmark_version"]
    dataset_files = dataset.get("files")
    if not isinstance(dataset_files, list) or not dataset_files:
        raise BenchmarkPublicationError(
            "dataset must bind at least one fixture file"
        )
    for index, file_record in enumerate(dataset_files):
        label = f"dataset.files[{index}]"
        if not isinstance(file_record, dict):
            raise BenchmarkPublicationError(f"{label} must be an object")
        fixture_path = _path(root, file_record.get("path"), label=label)
        if not fixture_path.is_file():
            raise BenchmarkPublicationError(
                f"{label} does not exist: {fixture_path}"
            )
        expected_hash = file_record.get("sha256")
        if (
            not isinstance(expected_hash, str)
            or not _SHA256.fullmatch(expected_hash)
        ):
            raise BenchmarkPublicationError(f"{label}.sha256 is invalid")
        actual_hash = _sha256(fixture_path)
        if actual_hash != expected_hash:
            raise BenchmarkPublicationError(
                f"{label} hash mismatch: expected {expected_hash}, got {actual_hash}"
            )
    if dataset.get("dataset_version") != benchmark_version:
        raise BenchmarkPublicationError(
            "dataset version does not match benchmark_version"
        )
    if ground_truth.get("ground_truth_version") != benchmark_version:
        raise BenchmarkPublicationError(
            "ground-truth version does not match benchmark_version"
        )
    if configuration.get("configuration_version") != benchmark_version:
        raise BenchmarkPublicationError(
            "scanner configuration is not versioned with the benchmark"
        )
    if rules.get("ruleset_version") != benchmark_version:
        raise BenchmarkPublicationError(
            "scanner rules are not versioned with the benchmark"
        )
    if adjudications.get("benchmark_version") != benchmark_version:
        raise BenchmarkPublicationError(
            "adjudications are not versioned with the benchmark"
        )

    runs = manifest.get("runs")
    if not isinstance(runs, list) or not runs:
        raise BenchmarkPublicationError("manifest must define at least one run")
    independent_hashes: set[str] = set()
    run_ids: set[str] = set()
    validated_runs: list[dict[str, Any]] = []
    for index, run in enumerate(runs):
        label = f"runs[{index}]"
        if not isinstance(run, dict):
            raise BenchmarkPublicationError(f"{label} must be an object")
        run_id = run.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            raise BenchmarkPublicationError(f"{label}.run_id is required")
        if run_id in run_ids:
            raise BenchmarkPublicationError(f"duplicate run_id {run_id}")
        run_ids.add(run_id)
        path = _path(root, run.get("path"), label=label)
        if not path.is_file():
            raise BenchmarkPublicationError(f"{label} does not exist: {path}")
        expected_hash = run.get("sha256")
        if not isinstance(expected_hash, str) or not _SHA256.fullmatch(expected_hash):
            raise BenchmarkPublicationError(f"{label}.sha256 is invalid")
        actual_hash = _sha256(path)
        if actual_hash != expected_hash:
            raise BenchmarkPublicationError(
                f"{label} hash mismatch: expected {expected_hash}, got {actual_hash}"
            )
        commit = run.get("commit")
        if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
            raise BenchmarkPublicationError(
                f"{label}.commit must be an exact 40-character commit SHA"
            )
        if not isinstance(run.get("recorded_at"), str) or not run["recorded_at"]:
            raise BenchmarkPublicationError(f"{label}.recorded_at is required")
        independent = run.get("statistically_independent")
        if not isinstance(independent, bool):
            raise BenchmarkPublicationError(
                f"{label}.statistically_independent must be boolean"
            )
        if independent:
            if actual_hash in independent_hashes:
                raise BenchmarkPublicationError(
                    "byte-identical runs cannot both be statistically independent"
                )
            independent_hashes.add(actual_hash)
        else:
            duplicate_of = run.get("duplicate_of")
            if duplicate_of not in run_ids:
                raise BenchmarkPublicationError(
                    f"{label}.duplicate_of must reference an earlier run"
                )
        validated_runs.append({**run, "resolved_path": path})

    return {
        "dataset": dataset,
        "ground_truth": ground_truth,
        "configuration": configuration,
        "rules": rules,
        "adjudications": adjudications.get("adjudications") or {},
        "runs": validated_runs,
    }


def _expected_truth_ids(
    ground_truth: list[dict[str, Any]],
    tool: str,
) -> set[str]:
    return {
        str(item["id"])
        for item in ground_truth
        if tool in (item.get("expected_tools") or [])
    }


def _finding_tool(finding: dict[str, Any]) -> str:
    return str(finding.get("scanner", finding.get("tool", "Unknown")))


def _rule_key(finding: dict[str, Any]) -> str:
    return f"{_finding_tool(finding)}:{finding.get('rule_id') or 'unknown'}"


def _evaluate_tool(
    tool: str,
    run_findings: list[list[dict[str, Any]]],
    ground_truth: list[dict[str, Any]],
    adjudications: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    all_decisions: list[dict[str, Any]] = []
    rule_labels: dict[str, list[int]] = defaultdict(list)
    matched_truth: set[str] = set()
    true_positives = 0
    false_positives = 0
    ambiguous_excluded = 0
    independent_runs = len(run_findings)
    for findings in run_findings:
        tool_findings = [
            finding for finding in findings if _finding_tool(finding) == tool
        ]
        matching = match_findings(
            tool_findings,
            ground_truth,
            adjudications=adjudications,
        )
        for finding, decision in zip(
            tool_findings,
            matching["decisions"],
            strict=True,
        ):
            public_decision = {
                "finding_key": decision["finding_key"],
                "rule_id": finding.get("rule_id"),
                "status": decision["status"],
                "ground_truth_id": decision["ground_truth_id"],
                "candidate_ids": decision["candidate_ids"],
                "included_in_metrics": decision["included_in_metrics"],
                "matching_reason": decision["matching_reason"],
            }
            all_decisions.append(public_decision)
            if not decision["included_in_metrics"]:
                ambiguous_excluded += 1
                continue
            label = 1 if decision["status"] == "matched" else 0
            rule_labels[_rule_key(finding)].append(label)
            if label:
                true_positives += 1
                matched_truth.add(str(decision["ground_truth_id"]))
            else:
                false_positives += 1

    expected = _expected_truth_ids(ground_truth, tool)
    detected_truth = matched_truth & expected
    false_negatives = len(expected - detected_truth)
    rule_scores = {
        key: posterior_precision(
            sum(labels),
            len(labels) - sum(labels),
            independently_reproduced=independent_runs > 1,
        )
        for key, labels in sorted(rule_labels.items())
    }
    labels: list[int] = []
    probabilities: list[float] = []
    for key, values in sorted(rule_labels.items()):
        rule_labels_checked, rule_probabilities = probability_vector(
            values,
            rule_scores[key]["displayed_estimate"],
        )
        labels.extend(rule_labels_checked)
        probabilities.extend(rule_probabilities)
    metrics = classification_metrics(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        labels=labels,
        probabilities=probabilities,
    )
    recall = (
        len(detected_truth) / len(expected)
        if expected
        else 0.0
    )
    metrics["recall"] = round(recall, 6)
    metrics["f1"] = round(
        (
            2.0
            * metrics["precision"]
            * recall
            / (metrics["precision"] + recall)
        )
        if metrics["precision"] + recall
        else 0.0,
        6,
    )
    metrics["detected_ground_truth"] = len(detected_truth)
    posterior = posterior_precision(
        true_positives,
        false_positives,
        independently_reproduced=independent_runs > 1,
    )
    return {
        **metrics,
        "posterior_precision": posterior,
        "sample_size": true_positives + false_positives,
        "expected_ground_truth": len(expected),
        "matched_ground_truth_ids": sorted(detected_truth),
        "missed_ground_truth_ids": sorted(expected - detected_truth),
        "ambiguous_excluded": ambiguous_excluded,
        "rule_scores": rule_scores,
        "matches": all_decisions,
    }


def evaluate_manifest(
    root: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Recalculate the canonical benchmark metrics from manifest evidence."""

    root = root.resolve()
    evidence = validate_manifest(root, manifest)
    ground_truth = evidence["ground_truth"].get("vulnerabilities")
    if not isinstance(ground_truth, list) or not ground_truth:
        raise BenchmarkPublicationError(
            "ground_truth must define a non-empty vulnerabilities list"
        )
    independent_runs = [
        run for run in evidence["runs"] if run["statistically_independent"]
    ]
    duplicate_runs = [
        {
            "run_id": run["run_id"],
            "duplicate_of": run["duplicate_of"],
            "sha256": run["sha256"],
        }
        for run in evidence["runs"]
        if not run["statistically_independent"]
    ]
    run_findings: list[list[dict[str, Any]]] = []
    considered_runs: list[dict[str, Any]] = []
    all_tools: set[str] = set()
    for run in independent_runs:
        raw = _load_json(run["resolved_path"])
        findings = raw.get("findings")
        if not isinstance(findings, list):
            raise BenchmarkPublicationError(
                f"{run['run_id']} findings must be an array"
            )
        run_findings.append(findings)
        all_tools.update(_finding_tool(finding) for finding in findings)
        considered_runs.append(
            {
                "run_id": run["run_id"],
                "commit": run["commit"],
                "recorded_at": run["recorded_at"],
                "sha256": run["sha256"],
                "scanner_versions": deepcopy(run.get("scanner_versions") or {}),
            }
        )
    covered_tools = sorted(
        {
            tool
            for item in ground_truth
            for tool in (item.get("expected_tools") or [])
        }
    )
    tool_results = {
        tool: _evaluate_tool(
            tool,
            run_findings,
            ground_truth,
            evidence["adjudications"],
        )
        for tool in covered_tools
    }
    overall_tp = sum(result["true_positives"] for result in tool_results.values())
    overall_fp = sum(result["false_positives"] for result in tool_results.values())
    overall_fn = sum(result["false_negatives"] for result in tool_results.values())
    overall_detected = sum(
        result["detected_ground_truth"] for result in tool_results.values()
    )
    overall_expected = sum(
        result["expected_ground_truth"] for result in tool_results.values()
    )
    overall = classification_metrics(
        true_positives=overall_tp,
        false_positives=overall_fp,
        false_negatives=overall_fn,
    )
    overall["posterior_precision"] = posterior_precision(overall_tp, overall_fp)
    overall["sample_size"] = overall_tp + overall_fp
    overall_recall = (
        overall_detected / overall_expected if overall_expected else 0.0
    )
    overall["recall"] = round(overall_recall, 6)
    overall["f1"] = round(
        (
            2.0
            * overall["precision"]
            * overall_recall
            / (overall["precision"] + overall_recall)
        )
        if overall["precision"] + overall_recall
        else 0.0,
        6,
    )
    overall["detected_ground_truth"] = overall_detected
    overall["expected_ground_truth"] = overall_expected
    overall["ambiguous_excluded"] = sum(
        result["ambiguous_excluded"] for result in tool_results.values()
    )
    return {
        "artifact_version": BENCHMARK_ARTIFACT_VERSION,
        "benchmark_id": manifest["benchmark_id"],
        "benchmark_version": manifest["benchmark_version"],
        "calculation_method": {
            "matching": "explainable multi-signal identity with manual adjudication",
            "matching_version": MATCHING_METHODOLOGY_VERSION,
            "confidence": "Beta-Binomial posterior with Beta(1, 1) prior",
            "confidence_version": CONFIDENCE_METHODOLOGY_VERSION,
            "displayed_estimate": "posterior_mean",
            "gating_estimate": "95% lower credible bound",
            "ambiguous_matches": "excluded_until_adjudicated",
            "duplicate_runs": "byte-identical artifacts count once",
            "counting_basis": (
                "precision counts emitted findings; recall counts distinct "
                "expected ground-truth items detected per scanner"
            ),
        },
        "evidence": {
            "dataset": deepcopy(manifest["dataset"]),
            "ground_truth": deepcopy(manifest["ground_truth"]),
            "configuration": deepcopy(manifest["configuration"]),
            "rules": deepcopy(manifest["rules"]),
            "runs_considered": considered_runs,
            "duplicate_runs_excluded": duplicate_runs,
        },
        "overall": overall,
        "tools": tool_results,
        "unscored_tools": sorted(all_tools - set(covered_tools)),
    }


def build_confidence_table(metrics: dict[str, Any]) -> dict[str, Any]:
    """Build the runtime lookup directly from the canonical metrics artifact."""

    rules: dict[str, Any] = {}
    tool_baseline: dict[str, Any] = {}
    for tool, result in sorted(metrics["tools"].items()):
        tool_baseline[tool] = deepcopy(result["posterior_precision"])
        for key, score in result["rule_scores"].items():
            rules[key] = deepcopy(score)
    return {
        "artifact_version": BENCHMARK_ARTIFACT_VERSION,
        "benchmark_id": metrics["benchmark_id"],
        "benchmark_version": metrics["benchmark_version"],
        "methodology_version": CONFIDENCE_METHODOLOGY_VERSION,
        "rules": rules,
        "tool_baseline": tool_baseline,
        "unscored_tools": deepcopy(metrics["unscored_tools"]),
    }


def render_metrics_markdown(metrics: dict[str, Any]) -> str:
    """Render the one generated Markdown representation used by every document."""

    lines = [
        GENERATED_START,
        "> Generated from the versioned benchmark manifest. Do not edit this block.",
        "",
        "| Tool | Precision | Recall | F1 | Posterior precision | 95% credible interval | Conservative bound | Maturity | n |",
        "|---|---:|---:|---:|---:|---:|---:|---|---:|",
    ]
    for tool, result in sorted(metrics["tools"].items()):
        posterior = result["posterior_precision"]
        interval = posterior["interval"]
        lines.append(
            "| "
            + " | ".join(
                [
                    tool,
                    f"{result['precision']:.3f}",
                    f"{result['recall']:.3f}",
                    f"{result['f1']:.3f}",
                    f"{posterior['displayed_estimate']:.3f}",
                    (
                        f"{interval['lower']:.3f}–"
                        f"{interval['upper']:.3f}"
                    ),
                    f"{posterior['gating_estimate']:.3f}",
                    posterior["maturity"],
                    str(result["sample_size"]),
                ]
            )
            + " |"
        )
    duplicates = metrics["evidence"]["duplicate_runs_excluded"]
    lines.extend(
        [
            "",
            (
                f"Methodology `{metrics['calculation_method']['confidence_version']}` "
                "uses a Beta(1, 1) prior. Displayed confidence is the posterior "
                "mean; decisions use the 95% lower credible bound."
            ),
            (
                f"{len(duplicates)} byte-identical repeat run(s) are retained for "
                "provenance but excluded as independent statistical samples."
            ),
            GENERATED_END,
        ]
    )
    return "\n".join(lines)


def _replace_generated_section(text: str, generated: str) -> str:
    if GENERATED_START in text or GENERATED_END in text:
        if text.count(GENERATED_START) != 1 or text.count(GENERATED_END) != 1:
            raise BenchmarkPublicationError(
                "generated benchmark markers must occur exactly once"
            )
        start = text.index(GENERATED_START)
        end = text.index(GENERATED_END) + len(GENERATED_END)
        return text[:start] + generated + text[end:]
    suffix = "\n" if text.endswith("\n") else "\n\n"
    return text + suffix + "## Generated benchmark metrics\n\n" + generated + "\n"


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        handle.write(content)
    temporary.replace(path)


def publication_outputs(
    root: Path,
    manifest_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[Path, str]]:
    root = root.resolve()
    manifest_path = manifest_path.resolve()
    manifest = _load_json(manifest_path)
    metrics = evaluate_manifest(root, manifest)
    confidence = build_confidence_table(metrics)
    metrics_path = _path(root, manifest.get("metrics_path"), label="metrics_path")
    confidence_path = _path(
        root,
        manifest.get("confidence_path"),
        label="confidence_path",
    )
    generated = render_metrics_markdown(metrics)
    outputs = {
        metrics_path: _canonical_json(metrics),
        confidence_path: _canonical_json(confidence),
    }
    documents = manifest.get("generated_documents")
    if not isinstance(documents, list) or not documents:
        raise BenchmarkPublicationError(
            "manifest must define generated_documents"
        )
    for index, value in enumerate(documents):
        document = _path(root, value, label=f"generated_documents[{index}]")
        if not document.is_file():
            raise BenchmarkPublicationError(
                f"generated document does not exist: {document}"
            )
        current = document.read_text(encoding="utf-8")
        outputs[document] = _replace_generated_section(current, generated)
    return metrics, confidence, outputs


def write_publication(root: Path, manifest_path: Path) -> dict[str, Any]:
    root = root.resolve()
    metrics, _, outputs = publication_outputs(root, manifest_path)
    for path, content in outputs.items():
        _write_atomic(path, content)
    return metrics


def check_publication(root: Path, manifest_path: Path) -> dict[str, Any]:
    """Fail when any published metric or generated consumer is inconsistent."""

    root = root.resolve()
    metrics, _, outputs = publication_outputs(root, manifest_path)
    inconsistent = [
        str(path.relative_to(root))
        for path, expected in outputs.items()
        if not path.is_file() or path.read_text(encoding="utf-8") != expected
    ]
    if inconsistent:
        raise BenchmarkPublicationError(
            "benchmark publication is inconsistent; regenerate: "
            + ", ".join(inconsistent)
        )
    generated_bodies = {
        path.read_text(encoding="utf-8")[
            path.read_text(encoding="utf-8").index(GENERATED_START) :
            path.read_text(encoding="utf-8").index(GENERATED_END)
            + len(GENERATED_END)
        ]
        for path in outputs
        if path.suffix == ".md"
    }
    if len(generated_bodies) != 1:
        raise BenchmarkPublicationError(
            "README and research documents do not share identical metrics"
        )
    return metrics
