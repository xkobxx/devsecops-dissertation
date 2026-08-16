"""Local Bayesian calibration models for per-repository rule reliability.

Uses Beta-Binomial conjugate updates with Bayesian shrinkage toward
the global prior to prevent small local samples from creating extreme
confidence overrides.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CALIBRATION_MODEL_VERSION = "1.0.0"

# ponytail: minimum evidence before local overrides affect gating
MIN_LOCAL_SAMPLES = 5
# Shrinkage weight toward global prior (0 = pure local, 1 = pure global)
# ponytail: fixed weight, adaptive shrinkage when sample sizes justify it
SHRINKAGE_WEIGHT = 0.3


class CalibrationModelError(ValueError):
    """Raised when calibration model construction fails."""


@dataclass
class RuleCalibration:
    """Per-rule local calibration from customer feedback."""

    rule_id: str
    scanner: str
    true_positives: int = 0
    false_positives: int = 0
    sample_size: int = 0

    @property
    def local_precision(self) -> float:
        """Raw local precision (posterior mean with Beta(1,1) prior)."""
        alpha = 1 + self.true_positives
        beta = 1 + self.false_positives
        return alpha / (alpha + beta)

    @property
    def has_sufficient_evidence(self) -> bool:
        return self.sample_size >= MIN_LOCAL_SAMPLES


@dataclass
class CalibrationModel:
    """A calibration model combining global benchmark data with local feedback."""

    model_version: str = CALIBRATION_MODEL_VERSION
    scope: str = "repository"  # "repository" or "organisation"
    scope_id: str = ""
    rules: dict[str, RuleCalibration] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "scope": self.scope,
            "scope_id": self.scope_id,
            "rules": {
                key: {
                    "rule_id": cal.rule_id,
                    "scanner": cal.scanner,
                    "true_positives": cal.true_positives,
                    "false_positives": cal.false_positives,
                    "sample_size": cal.sample_size,
                    "local_precision": round(cal.local_precision, 6),
                    "has_sufficient_evidence": cal.has_sufficient_evidence,
                }
                for key, cal in sorted(self.rules.items())
            },
        }


def build_calibration_model(
    feedback: list[dict[str, Any]],
    *,
    scope: str = "repository",
    scope_id: str = "",
) -> CalibrationModel:
    """Build a calibration model from customer feedback records.

    Counts confirmed_true_positive and confirmed_false_positive
    feedback per rule to compute local rule reliability.
    """
    model = CalibrationModel(scope=scope, scope_id=scope_id)

    for entry in feedback:
        rule_id = entry.get("rule_id", "")
        scanner = entry.get("scanner", "")
        feedback_type = entry.get("feedback_type", "")
        if not rule_id or not scanner:
            continue
        # Only precision-relevant feedback creates calibration entries
        if feedback_type not in (
            "confirmed_true_positive",
            "confirmed_false_positive",
        ):
            continue
        key = f"{scanner}:{rule_id}"
        if key not in model.rules:
            model.rules[key] = RuleCalibration(
                rule_id=rule_id, scanner=scanner
            )
        cal = model.rules[key]
        if feedback_type == "confirmed_true_positive":
            cal.true_positives += 1
        else:
            cal.false_positives += 1
        cal.sample_size += 1

    return model


def merge_global_and_local(
    global_estimate: float,
    local_model: CalibrationModel,
    rule_key: str,
    *,
    shrinkage: float = SHRINKAGE_WEIGHT,
) -> dict[str, Any]:
    """Merge global benchmark precision with local calibration.

    Uses Bayesian shrinkage: the local estimate is pulled toward the
    global prior proportionally to shrinkage weight and inversely to
    local sample size.  Rules with insufficient local evidence return
    the global estimate unchanged.

    Returns a dict with both estimates and the merged result for
    transparency.
    """
    cal = local_model.rules.get(rule_key)
    if cal is None or not cal.has_sufficient_evidence:
        return {
            "global_estimate": round(global_estimate, 6),
            "local_estimate": None,
            "merged_estimate": round(global_estimate, 6),
            "source": "global_only",
            "local_sample_size": 0 if cal is None else cal.sample_size,
            "shrinkage_applied": False,
            "model_version": CALIBRATION_MODEL_VERSION,
        }

    local = cal.local_precision
    # Shrinkage toward global: more local evidence = less shrinkage
    # ponytail: linear shrinkage, exponential decay when sample sizes matter
    effective_shrinkage = shrinkage * (MIN_LOCAL_SAMPLES / max(cal.sample_size, 1))
    effective_shrinkage = min(effective_shrinkage, shrinkage)  # cap at base
    merged = (1 - effective_shrinkage) * local + effective_shrinkage * global_estimate

    return {
        "global_estimate": round(global_estimate, 6),
        "local_estimate": round(local, 6),
        "merged_estimate": round(merged, 6),
        "source": "merged",
        "local_sample_size": cal.sample_size,
        "shrinkage_applied": True,
        "shrinkage_weight": round(effective_shrinkage, 6),
        "model_version": CALIBRATION_MODEL_VERSION,
    }


def detect_drift(
    global_estimate: float,
    local_model: CalibrationModel,
    rule_key: str,
    *,
    drift_threshold: float = 0.2,
) -> dict[str, Any] | None:
    """Detect when local calibration diverges significantly from global.

    Returns a drift report if the absolute difference exceeds the
    threshold, or None if no drift is detected.
    """
    cal = local_model.rules.get(rule_key)
    if cal is None or not cal.has_sufficient_evidence:
        return None

    diff = abs(cal.local_precision - global_estimate)
    if diff <= drift_threshold:
        return None

    return {
        "rule_key": rule_key,
        "global_estimate": round(global_estimate, 6),
        "local_estimate": round(cal.local_precision, 6),
        "drift": round(diff, 6),
        "threshold": drift_threshold,
        "local_sample_size": cal.sample_size,
        "direction": "higher" if cal.local_precision > global_estimate else "lower",
    }
