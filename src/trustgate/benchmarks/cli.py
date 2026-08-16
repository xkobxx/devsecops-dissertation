"""CLI integration for benchmark publication and consistency checks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
from typing import Any

from .corpus import (
    BenchmarkCorpusError,
    DEFAULT_CORPUS,
    load_and_validate_corpus,
)
from .labelling import (
    BenchmarkLabellingError,
    DEFAULT_PARTITIONS,
    create_review_template,
    evaluate_reviews,
    seal_adjudication,
    seal_review,
    validate_partitions,
    validate_tuning_inputs,
)
from .publication import (
    BenchmarkPublicationError,
    DEFAULT_MANIFEST,
    check_publication,
    write_publication,
)
from .regression import (
    BenchmarkRegressionError,
    compare_evaluations,
    render_regression_report,
)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--manifest",
        default=DEFAULT_MANIFEST,
        help=f"Versioned benchmark manifest (default: {DEFAULT_MANIFEST})",
    )
    parser.add_argument(
        "--partitions",
        default=DEFAULT_PARTITIONS,
        help=f"Benchmark partition manifest (default: {DEFAULT_PARTITIONS})",
    )
    parser.add_argument(
        "--review",
        action="append",
        default=[],
        help="Integrity-bound independent review JSON (repeat exactly twice)",
    )
    parser.add_argument(
        "--adjudication",
        action="append",
        default=[],
        help="Integrity-bound disagreement adjudication JSON (repeat as needed)",
    )
    parser.add_argument(
        "--tuning-config",
        help="Rule-tuning partition declaration JSON",
    )
    parser.add_argument(
        "--output",
        default="reports/benchmark-labelling.json",
        help="Labelling or leakage-control receipt output",
    )
    parser.add_argument(
        "--reviewer-id",
        help="Reviewer identifier for an incomplete review template",
    )
    parser.add_argument(
        "--corpus",
        default=DEFAULT_CORPUS,
        help=f"Versioned multilingual corpus (default: {DEFAULT_CORPUS})",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--write",
        action="store_true",
        help="Regenerate canonical metrics, confidence data, and documentation",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="Verify every published benchmark consumer is consistent",
    )
    mode.add_argument(
        "--corpus-check",
        action="store_true",
        help="Verify multilingual fixture hashes, pairs, and coverage",
    )
    mode.add_argument(
        "--partition-check",
        action="store_true",
        help="Verify public, blind, private, and rule-tuning separation",
    )
    mode.add_argument(
        "--labelling-check",
        action="store_true",
        help="Combine two reviews, agreement metrics, and adjudications",
    )
    mode.add_argument(
        "--tuning-check",
        action="store_true",
        help="Reject blind or private evaluation data in rule tuning",
    )
    mode.add_argument(
        "--review-template",
        action="store_true",
        help="Create a label-empty review draft for one independent reviewer",
    )
    mode.add_argument(
        "--seal-review",
        action="store_true",
        help="Seal one completed review draft with a canonical digest",
    )
    mode.add_argument(
        "--seal-adjudication",
        action="store_true",
        help="Seal one completed disagreement adjudication draft",
    )
    mode.add_argument(
        "--regression-check",
        action="store_true",
        help="Compare current metrics against a baseline and detect regressions",
    )
    parser.add_argument(
        "--baseline",
        help="Baseline metrics JSON for regression comparison",
    )
    parser.add_argument(
        "--max-precision-drop",
        type=float,
        help="Maximum allowed precision drop (default: 0.05)",
    )
    parser.add_argument(
        "--max-recall-drop",
        type=float,
        help="Maximum allowed recall drop (default: 0.05)",
    )
    parser.add_argument(
        "--runtime-baseline",
        help="JSON file mapping tool names to baseline runtime seconds",
    )
    parser.add_argument(
        "--runtime-current",
        help="JSON file mapping tool names to current runtime seconds",
    )


def _object(path: str | Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkLabellingError(f"could not load {label}: {error}") from error
    if not isinstance(value, dict):
        raise BenchmarkLabellingError(f"{label} must contain a JSON object")
    return value


def _write_json(path: str | Path, value: object) -> Path:
    output = Path(path)
    if output.is_symlink():
        raise BenchmarkLabellingError(f"refusing symlinked output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            delete=False,
        ) as temporary:
            json.dump(value, temporary, indent=2, sort_keys=True)
            temporary.write("\n")
            temporary_path = Path(temporary.name)
        temporary_path.replace(output)
    except BaseException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise
    return output


def _labelling_inputs(
    root: Path, corpus_path: str, partition_path: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    corpus = load_and_validate_corpus(root, corpus_path)
    partition = validate_partitions(
        root,
        corpus,
        _object(partition_path, label="partition manifest"),
    )
    return corpus, partition


def run(args: argparse.Namespace) -> int:
    root = Path.cwd().resolve()
    if args.corpus_check:
        try:
            corpus = load_and_validate_corpus(root, args.corpus)
        except BenchmarkCorpusError as error:
            print(f"benchmark corpus failed: {error}", file=sys.stderr)
            return 1
        print(
            f"Benchmark corpus {corpus['corpus_id']} "
            f"{corpus['corpus_version']} verified: "
            f"{len(corpus['cases'])} cases, {len(corpus['files'])} files."
        )
        return 0
    if args.partition_check:
        try:
            _corpus, partitions = _labelling_inputs(
                root, args.corpus, args.partitions
            )
        except BenchmarkLabellingError as error:
            print(f"benchmark partitions failed: {error}", file=sys.stderr)
            return 1
        print(
            f"Benchmark partitions {partitions['partition_id']} "
            f"{partitions['partition_version']} verified: "
            f"{len(partitions['development_case_ids'])} development, "
            f"{len(partitions['public_blind_items'])} public blind, "
            f"{len(partitions['private_commitments'])} private commitment(s)."
        )
        return 0
    if args.review_template:
        if not args.reviewer_id:
            print(
                "benchmark review template failed: --reviewer-id is required",
                file=sys.stderr,
            )
            return 1
        try:
            corpus, partitions = _labelling_inputs(
                root, args.corpus, args.partitions
            )
            template = create_review_template(
                corpus, partitions, args.reviewer_id
            )
            output = _write_json(args.output, template)
        except (BenchmarkLabellingError, OSError) as error:
            print(f"benchmark review template failed: {error}", file=sys.stderr)
            return 1
        print(f"Incomplete independent-review template created: {output}")
        return 0
    if args.seal_review:
        if len(args.review) != 1:
            print(
                "benchmark review sealing failed: pass one --review draft",
                file=sys.stderr,
            )
            return 1
        try:
            result = seal_review(
                _object(args.review[0], label="completed review draft")
            )
            output = _write_json(args.output, result)
        except (BenchmarkLabellingError, OSError) as error:
            print(f"benchmark review sealing failed: {error}", file=sys.stderr)
            return 1
        print(f"Benchmark review sealed: {output}")
        return 0
    if args.seal_adjudication:
        if len(args.adjudication) != 1:
            print(
                "benchmark adjudication sealing failed: "
                "pass one --adjudication draft",
                file=sys.stderr,
            )
            return 1
        try:
            result = seal_adjudication(
                _object(
                    args.adjudication[0],
                    label="completed adjudication draft",
                )
            )
            output = _write_json(args.output, result)
        except (BenchmarkLabellingError, OSError) as error:
            print(f"benchmark adjudication sealing failed: {error}", file=sys.stderr)
            return 1
        print(f"Benchmark adjudication sealed: {output}")
        return 0
    if args.labelling_check:
        try:
            corpus, partitions = _labelling_inputs(
                root, args.corpus, args.partitions
            )
            reviews = [
                _object(path, label="review record") for path in args.review
            ]
            adjudications = [
                _object(path, label="adjudication record")
                for path in args.adjudication
            ]
            result = evaluate_reviews(
                corpus, partitions, reviews, adjudications
            )
            output = _write_json(args.output, result)
        except (BenchmarkLabellingError, OSError) as error:
            print(f"benchmark labelling failed: {error}", file=sys.stderr)
            return 1
        print(f"Benchmark labelling verified: {output}")
        return 0
    if args.tuning_check:
        if not args.tuning_config:
            print(
                "benchmark tuning failed: --tuning-config is required",
                file=sys.stderr,
            )
            return 1
        try:
            _corpus, partitions = _labelling_inputs(
                root, args.corpus, args.partitions
            )
            result = validate_tuning_inputs(
                partitions,
                _object(args.tuning_config, label="tuning configuration"),
            )
            output = _write_json(args.output, result)
        except (BenchmarkLabellingError, OSError) as error:
            print(f"benchmark tuning failed: {error}", file=sys.stderr)
            return 1
        print(f"Benchmark tuning boundary verified: {output}")
        return 0
    if args.regression_check:
        if not args.baseline:
            print(
                "benchmark regression check failed: --baseline is required",
                file=sys.stderr,
            )
            return 1
        try:
            baseline_metrics = _object(args.baseline, label="baseline metrics")
            manifest_path = (root / args.manifest).resolve()
            current_metrics = check_publication(root, manifest_path)
            thresholds: dict[str, float] = {}
            if args.max_precision_drop is not None:
                thresholds["max_precision_drop"] = args.max_precision_drop
            if args.max_recall_drop is not None:
                thresholds["max_recall_drop"] = args.max_recall_drop
            runtime_baseline = None
            runtime_current = None
            if args.runtime_baseline:
                runtime_baseline = json.loads(
                    Path(args.runtime_baseline).read_text(encoding="utf-8")
                )
            if args.runtime_current:
                runtime_current = json.loads(
                    Path(args.runtime_current).read_text(encoding="utf-8")
                )
            report = compare_evaluations(
                baseline_metrics,
                current_metrics,
                thresholds=thresholds or None,
                runtime_baseline=runtime_baseline,
                runtime_current=runtime_current,
            )
            print(render_regression_report(report))
            output = _write_json(args.output, report)
            print(f"\nRegression report written to: {output}")
            return 0 if report["passed"] else 1
        except (
            BenchmarkPublicationError,
            BenchmarkRegressionError,
            BenchmarkLabellingError,
            OSError,
        ) as error:
            print(f"benchmark regression check failed: {error}", file=sys.stderr)
            return 1
    manifest = (root / args.manifest).resolve()
    try:
        metrics = (
            write_publication(root, manifest)
            if args.write
            else check_publication(root, manifest)
        )
    except BenchmarkPublicationError as error:
        print(f"benchmark publication failed: {error}", file=sys.stderr)
        return 1
    mode = "generated" if args.write else "verified"
    print(
        f"Benchmark {metrics['benchmark_id']} "
        f"{metrics['benchmark_version']} {mode}: "
        f"{len(metrics['tools'])} scored tools."
    )
    return 0


__all__ = ["add_arguments", "run"]
