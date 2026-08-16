"""Versioned benchmark evaluation and publication for Trust Gate."""

from .corpus import (
    BenchmarkCorpusError,
    CORPUS_SCHEMA_VERSION,
    DEFAULT_CORPUS,
    load_and_validate_corpus,
    validate_corpus,
)
from .labelling import (
    BenchmarkLabellingError,
    LABELLING_SCHEMA_VERSION,
    create_label_commitment,
    create_review_template,
    evaluate_reviews,
    seal_adjudication,
    seal_review,
    validate_partitions,
    validate_tuning_inputs,
    verify_label_commitment,
)

from .matching import (
    MATCHING_METHODOLOGY_VERSION,
    adjudication_key,
    code_region_hash,
    match_finding,
    match_findings,
)
from .regression import (
    BenchmarkRegressionError,
    DEFAULT_THRESHOLDS,
    REGRESSION_SCHEMA_VERSION,
    compare_evaluations,
    render_regression_report,
)
from .statistics import (
    CONFIDENCE_METHODOLOGY_VERSION,
    classification_metrics,
    maturity_level,
    posterior_precision,
)

__all__ = [
    "BenchmarkRegressionError",
    "DEFAULT_THRESHOLDS",
    "REGRESSION_SCHEMA_VERSION",
    "compare_evaluations",
    "render_regression_report",
    "BenchmarkCorpusError",
    "BenchmarkLabellingError",
    "CORPUS_SCHEMA_VERSION",
    "DEFAULT_CORPUS",
    "CONFIDENCE_METHODOLOGY_VERSION",
    "MATCHING_METHODOLOGY_VERSION",
    "LABELLING_SCHEMA_VERSION",
    "create_label_commitment",
    "create_review_template",
    "adjudication_key",
    "classification_metrics",
    "code_region_hash",
    "match_finding",
    "match_findings",
    "maturity_level",
    "posterior_precision",
    "evaluate_reviews",
    "load_and_validate_corpus",
    "validate_corpus",
    "seal_adjudication",
    "seal_review",
    "validate_partitions",
    "validate_tuning_inputs",
    "verify_label_commitment",
]
