"""Statistically conservative benchmark and confidence calculations."""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from typing import Any


CONFIDENCE_METHODOLOGY_VERSION = "1.0.0"
DEFAULT_CONFIDENCE_LEVEL = 0.95
DEFAULT_PRIOR_ALPHA = 1.0
DEFAULT_PRIOR_BETA = 1.0


def _require_count(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _require_probability(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number between 0 and 1")
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} must be a number between 0 and 1")
    return result


def maturity_level(
    sample_size: int,
    *,
    independently_reproduced: bool = False,
) -> str:
    """Return the roadmap maturity band for a labelled sample."""

    _require_count(sample_size, "sample_size")
    if independently_reproduced and sample_size >= 100:
        return "Verified"
    if sample_size < 5:
        return "Experimental"
    if sample_size < 30:
        return "Directional"
    if sample_size < 100:
        return "Moderate"
    return "Mature"


def _beta_continued_fraction(a: float, b: float, x: float) -> float:
    """Evaluate the continued fraction used by the regularized beta CDF."""

    maximum_iterations = 300
    epsilon = 3e-14
    minimum = 1e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < minimum:
        d = minimum
    d = 1.0 / d
    result = d
    for iteration in range(1, maximum_iterations + 1):
        doubled = 2 * iteration
        coefficient = (
            iteration
            * (b - iteration)
            * x
            / ((qam + doubled) * (a + doubled))
        )
        d = 1.0 + coefficient * d
        if abs(d) < minimum:
            d = minimum
        c = 1.0 + coefficient / c
        if abs(c) < minimum:
            c = minimum
        d = 1.0 / d
        result *= d * c

        coefficient = -(
            (a + iteration)
            * (qab + iteration)
            * x
            / ((a + doubled) * (qap + doubled))
        )
        d = 1.0 + coefficient * d
        if abs(d) < minimum:
            d = minimum
        c = 1.0 + coefficient / c
        if abs(c) < minimum:
            c = minimum
        d = 1.0 / d
        delta = d * c
        result *= delta
        if abs(delta - 1.0) <= epsilon:
            return result
    raise ArithmeticError("beta continued fraction did not converge")


def _regularized_beta(x: float, a: float, b: float) -> float:
    if not a > 0 or not b > 0:
        raise ValueError("beta distribution parameters must be positive")
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    logarithm = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log1p(-x)
    )
    factor = math.exp(logarithm)
    if x < (a + 1.0) / (a + b + 2.0):
        return factor * _beta_continued_fraction(a, b, x) / a
    return 1.0 - factor * _beta_continued_fraction(b, a, 1.0 - x) / b


def _beta_quantile(probability: float, a: float, b: float) -> float:
    probability = _require_probability(probability, "probability")
    if probability == 0:
        return 0.0
    if probability == 1:
        return 1.0
    lower = 0.0
    upper = 1.0
    for _ in range(120):
        midpoint = (lower + upper) / 2.0
        if _regularized_beta(midpoint, a, b) < probability:
            lower = midpoint
        else:
            upper = midpoint
    return (lower + upper) / 2.0


def posterior_precision(
    true_positives: int,
    false_positives: int,
    *,
    prior_alpha: float = DEFAULT_PRIOR_ALPHA,
    prior_beta: float = DEFAULT_PRIOR_BETA,
    confidence_level: float = DEFAULT_CONFIDENCE_LEVEL,
    independently_reproduced: bool = False,
) -> dict[str, Any]:
    """Return a Beta-Binomial posterior with a conservative gating bound."""

    true_positives = _require_count(true_positives, "true_positives")
    false_positives = _require_count(false_positives, "false_positives")
    if not prior_alpha > 0 or not prior_beta > 0:
        raise ValueError("prior parameters must be positive")
    confidence_level = _require_probability(confidence_level, "confidence_level")
    if confidence_level == 0:
        raise ValueError("confidence_level must be greater than zero")

    posterior_alpha = prior_alpha + true_positives
    posterior_beta = prior_beta + false_positives
    tail = (1.0 - confidence_level) / 2.0
    lower = _beta_quantile(tail, posterior_alpha, posterior_beta)
    upper = _beta_quantile(1.0 - tail, posterior_alpha, posterior_beta)
    mean = posterior_alpha / (posterior_alpha + posterior_beta)
    sample_size = true_positives + false_positives
    maturity = maturity_level(
        sample_size,
        independently_reproduced=independently_reproduced,
    )
    if sample_size < 5:
        decision_tier = "Experimental"
    elif sample_size < 30:
        decision_tier = "Directional"
    elif lower >= 0.7:
        decision_tier = "High"
    elif lower >= 0.3:
        decision_tier = "Likely"
    else:
        decision_tier = "Noise"
    return {
        "method": "beta-binomial",
        "methodology_version": CONFIDENCE_METHODOLOGY_VERSION,
        "prior": {
            "alpha": prior_alpha,
            "beta": prior_beta,
        },
        "true_positives": true_positives,
        "false_positives": false_positives,
        "sample_size": sample_size,
        "displayed_estimate": round(mean, 6),
        "gating_estimate": round(lower, 6),
        "interval": {
            "lower": round(lower, 6),
            "upper": round(upper, 6),
            "confidence_level": confidence_level,
        },
        "maturity": maturity,
        "decision_tier": decision_tier,
    }


def classification_metrics(
    *,
    true_positives: int,
    false_positives: int,
    false_negatives: int,
    labels: Sequence[int] | None = None,
    probabilities: Sequence[float] | None = None,
    calibration_bins: int = 10,
) -> dict[str, Any]:
    """Calculate classification and calibration metrics without inventing TNs."""

    true_positives = _require_count(true_positives, "true_positives")
    false_positives = _require_count(false_positives, "false_positives")
    false_negatives = _require_count(false_negatives, "false_negatives")
    if isinstance(calibration_bins, bool) or calibration_bins < 1:
        raise ValueError("calibration_bins must be a positive integer")

    predicted_positive = true_positives + false_positives
    actual_positive = true_positives + false_negatives
    precision = true_positives / predicted_positive if predicted_positive else 0.0
    recall = true_positives / actual_positive if actual_positive else 0.0
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    if (labels is None) != (probabilities is None):
        raise ValueError("labels and probabilities must be supplied together")
    brier_score: float | None = None
    calibration_error: float | None = None
    calibration_quality = "unavailable"
    if labels is not None and probabilities is not None:
        if len(labels) != len(probabilities):
            raise ValueError("labels and probabilities must have the same length")
        checked_labels: list[int] = []
        checked_probabilities: list[float] = []
        for label, probability in zip(labels, probabilities, strict=True):
            if isinstance(label, bool) or label not in (0, 1):
                raise ValueError("labels must contain only 0 and 1")
            checked_labels.append(label)
            checked_probabilities.append(
                _require_probability(probability, "probability")
            )
        if checked_labels:
            brier_score = sum(
                (probability - label) ** 2
                for label, probability in zip(
                    checked_labels,
                    checked_probabilities,
                    strict=True,
                )
            ) / len(checked_labels)
            weighted_error = 0.0
            for index in range(calibration_bins):
                low = index / calibration_bins
                high = (index + 1) / calibration_bins
                members = [
                    (label, probability)
                    for label, probability in zip(
                        checked_labels,
                        checked_probabilities,
                        strict=True,
                    )
                    if low <= probability < high
                    or (index == calibration_bins - 1 and probability == 1.0)
                ]
                if not members:
                    continue
                observed = sum(label for label, _ in members) / len(members)
                predicted = sum(probability for _, probability in members) / len(
                    members
                )
                weighted_error += (
                    len(members)
                    / len(checked_labels)
                    * abs(observed - predicted)
                )
            calibration_error = weighted_error
            calibration_quality = (
                "good"
                if weighted_error <= 0.05
                else "moderate"
                if weighted_error <= 0.15
                else "poor"
            )

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "brier_score": (
            round(brier_score, 6) if brier_score is not None else None
        ),
        "calibration_error": (
            round(calibration_error, 6)
            if calibration_error is not None
            else None
        ),
        "calibration_quality": calibration_quality,
    }


def probability_vector(
    labels: Iterable[int],
    estimate: float,
) -> tuple[list[int], list[float]]:
    """Create an explicitly constant forecast vector for calibration reporting."""

    estimate = _require_probability(estimate, "estimate")
    checked = list(labels)
    for label in checked:
        if isinstance(label, bool) or label not in (0, 1):
            raise ValueError("labels must contain only 0 and 1")
    return checked, [estimate] * len(checked)
