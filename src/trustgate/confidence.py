"""Separate, explainable confidence concepts for Trust Gate decisions."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from trustgate.benchmarks.statistics import CONFIDENCE_METHODOLOGY_VERSION


CONFIDENCE_FIELDS = (
    "scanner_rule_reliability",
    "finding_validity_confidence",
    "reachability_confidence",
    "exploitability_confidence",
    "remediation_confidence",
    "overall_decision_confidence",
)

CONFIDENCE_DEFINITIONS = {
    "scanner_rule_reliability": (
        "How consistently this scanner rule produced valid findings in the "
        "versioned labelled benchmark."
    ),
    "finding_validity_confidence": (
        "How likely the specific reported finding is to represent a real issue."
    ),
    "reachability_confidence": (
        "How strong the evidence is that an execution path can reach the issue."
    ),
    "exploitability_confidence": (
        "How strong the evidence is that the issue can be exploited in its "
        "observed environment."
    ),
    "remediation_confidence": (
        "How strong the evidence is that the proposed remediation is applicable."
    ),
    "overall_decision_confidence": (
        "The conservative confidence in the resulting Trust Gate decision."
    ),
}

CONFIDENCE_EVIDENCE = {
    "scanner_rule_reliability": (
        "versioned benchmark labels",
        "rule sample size",
        "credible interval",
    ),
    "finding_validity_confidence": (
        "scanner-rule reliability",
        "independent corroboration",
        "manual validation",
    ),
    "reachability_confidence": (
        "data-flow evidence",
        "runtime reachability evidence",
    ),
    "exploitability_confidence": (
        "exploit validation",
        "environment preconditions",
        "known-exploited evidence",
    ),
    "remediation_confidence": (
        "remediation references",
        "fix validation",
    ),
    "overall_decision_confidence": (
        "finding validity",
        "reachability",
        "exploitability",
        "remediation",
    ),
}

# Scanner reliability feeds finding validity once. Overall confidence consumes
# finding validity, never scanner reliability directly, so it cannot be counted
# twice. Exploitability has no dependency on scanner reliability.
CONFIDENCE_DEPENDENCIES = {
    "scanner_rule_reliability": (),
    "finding_validity_confidence": ("scanner_rule_reliability",),
    "reachability_confidence": (),
    "exploitability_confidence": (),
    "remediation_confidence": (),
    "overall_decision_confidence": (
        "finding_validity_confidence",
        "reachability_confidence",
        "exploitability_confidence",
        "remediation_confidence",
    ),
}


def validate_dependency_graph(
    dependencies: dict[str, tuple[str, ...]] = CONFIDENCE_DEPENDENCIES,
) -> None:
    """Reject circular or unknown confidence dependencies."""

    unknown = {
        dependency
        for values in dependencies.values()
        for dependency in values
        if dependency not in dependencies
    }
    if unknown:
        raise ValueError(f"unknown confidence dependencies: {sorted(unknown)}")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            raise ValueError(f"circular confidence dependency at {name}")
        if name in visited:
            return
        visiting.add(name)
        for dependency in dependencies[name]:
            visit(dependency)
        visiting.remove(name)
        visited.add(name)

    for field in dependencies:
        visit(field)


def _component(
    *,
    estimate: float | None,
    conservative_bound: float | None,
    sample_size: int | None,
    method: str,
    evidence: list[str],
    explanation: str,
    maturity: str | None = None,
    decision_tier: str = "Unscored",
) -> dict[str, Any]:
    for value, label in (
        (estimate, "estimate"),
        (conservative_bound, "conservative_bound"),
    ):
        if value is not None and not 0.0 <= value <= 1.0:
            raise ValueError(f"{label} must be between 0 and 1")
    return {
        "estimate": estimate,
        "conservative_bound": conservative_bound,
        "sample_size": sample_size,
        "method": method,
        "methodology_version": CONFIDENCE_METHODOLOGY_VERSION,
        "evidence": evidence,
        "explanation": explanation,
        "maturity": maturity,
        "decision_tier": decision_tier,
    }


def _decision_tier(
    conservative_bound: float | None,
    sample_size: int | None,
) -> str:
    if conservative_bound is None:
        return "Unscored"
    if sample_size is None:
        return "Evidence-based"
    if sample_size < 5:
        return "Experimental"
    if sample_size < 30:
        return "Directional"
    if conservative_bound >= 0.7:
        return "High"
    if conservative_bound >= 0.3:
        return "Likely"
    return "Noise"


def unscored_component(name: str, explanation: str) -> dict[str, Any]:
    if name not in CONFIDENCE_DEFINITIONS:
        raise ValueError(f"unknown confidence field {name}")
    return _component(
        estimate=None,
        conservative_bound=None,
        sample_size=None,
        method="unscored",
        evidence=[],
        explanation=explanation,
    )


def _evidence_kinds(finding: dict[str, Any]) -> set[str]:
    return {
        str(item.get("kind"))
        for item in finding.get("evidence") or []
        if isinstance(item, dict) and item.get("kind")
    }


def build_confidence_components(
    finding: dict[str, Any],
    reliability_score: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Build all confidence components from non-circular evidence sources."""

    validate_dependency_graph()
    evidence_kinds = _evidence_kinds(finding)
    if reliability_score is None:
        scanner = unscored_component(
            "scanner_rule_reliability",
            "No versioned labelled benchmark covers this scanner rule.",
        )
        validity = unscored_component(
            "finding_validity_confidence",
            "Finding validity cannot inherit an unscored rule baseline.",
        )
    else:
        estimate = float(reliability_score["displayed_estimate"])
        bound = float(reliability_score["gating_estimate"])
        sample_size = int(reliability_score["sample_size"])
        maturity = str(reliability_score["maturity"])
        decision_tier = str(reliability_score["decision_tier"])
        scanner = _component(
            estimate=estimate,
            conservative_bound=bound,
            sample_size=sample_size,
            method="benchmark-rule-posterior",
            evidence=[
                (
                    f"{reliability_score['true_positives']} valid and "
                    f"{reliability_score['false_positives']} invalid labelled "
                    "finding(s)"
                ),
                (
                    f"{reliability_score['interval']['confidence_level']:.0%} "
                    "credible interval"
                ),
            ],
            explanation=(
                "Rule reliability is the benchmark posterior, with the lower "
                "credible bound reserved for decisions."
            ),
            maturity=maturity,
            decision_tier=decision_tier,
        )
        corroboration = "corroboration" in evidence_kinds
        validation = "manual_validation" in evidence_kinds
        uplift = 0.05 if corroboration else 0.0
        uplift += 0.05 if validation else 0.0
        validity_estimate = min(1.0, estimate + uplift)
        validity_bound = min(validity_estimate, bound + uplift)
        validity_evidence = ["scanner-rule reliability"]
        if corroboration:
            validity_evidence.append("independent scanner corroboration")
        if validation:
            validity_evidence.append("manual finding validation")
        validity = _component(
            estimate=round(validity_estimate, 6),
            conservative_bound=round(validity_bound, 6),
            sample_size=sample_size,
            method="finding-validity-evidence",
            evidence=validity_evidence,
            explanation=(
                "Finding validity starts from rule reliability and can receive "
                "an explicitly recorded uplift for independent corroboration or "
                "manual validation."
            ),
            maturity=maturity,
            decision_tier=_decision_tier(validity_bound, sample_size),
        )

    reachability_state = finding.get("reachability")
    reachability_values = {
        "reachable": (0.9, 0.7),
        "potentially_reachable": (0.6, 0.35),
        "unreachable": (0.1, 0.02),
    }
    if reachability_state in reachability_values:
        estimate, bound = reachability_values[str(reachability_state)]
        reachability = _component(
            estimate=estimate,
            conservative_bound=bound,
            sample_size=None,
            method="reachability-evidence-state",
            evidence=[f"reachability={reachability_state}"],
            explanation=(
                "Reachability confidence comes only from the canonical "
                "reachability state and supporting data-flow evidence."
            ),
            decision_tier="Evidence-based",
        )
    else:
        reachability = unscored_component(
            "reachability_confidence",
            "No affirmative reachability evidence is available.",
        )

    exploit_evidence = [
        kind
        for kind in ("exploit_validation", "known_exploited", "exploit_precondition")
        if kind in evidence_kinds
    ]
    if exploit_evidence:
        exploitability = _component(
            estimate=0.8 if "exploit_validation" in exploit_evidence else 0.6,
            conservative_bound=(
                0.6 if "exploit_validation" in exploit_evidence else 0.35
            ),
            sample_size=None,
            method="exploitability-evidence",
            evidence=exploit_evidence,
            explanation=(
                "Exploitability uses exploit-specific evidence and never scanner "
                "reliability."
            ),
            decision_tier="Evidence-based",
        )
    else:
        exploitability = unscored_component(
            "exploitability_confidence",
            "Scanner reliability is not exploitability evidence; no exploit-specific evidence is available.",
        )

    remediation_value = finding.get("remediation")
    remediation_references = (
        remediation_value.get("references") or []
        if isinstance(remediation_value, dict)
        else []
    )
    if remediation_references:
        remediation = _component(
            estimate=0.7,
            conservative_bound=0.5,
            sample_size=len(remediation_references),
            method="remediation-reference-evidence",
            evidence=[str(reference) for reference in remediation_references],
            explanation=(
                "Remediation confidence reflects applicable references, not "
                "finding validity or exploitability."
            ),
            decision_tier="Evidence-based",
        )
    else:
        remediation = unscored_component(
            "remediation_confidence",
            "No remediation references or fix-validation evidence are available.",
        )

    leaf_components = [
        validity,
        reachability,
        exploitability,
        remediation,
    ]
    scored = [
        component
        for component in leaf_components
        if component["estimate"] is not None
    ]
    if scored:
        overall_estimate = min(float(component["estimate"]) for component in scored)
        bounds = [
            float(component["conservative_bound"])
            for component in scored
            if component["conservative_bound"] is not None
        ]
        overall_bound = min(bounds) if bounds else None
        overall = _component(
            estimate=round(overall_estimate, 6),
            conservative_bound=(
                round(overall_bound, 6) if overall_bound is not None else None
            ),
            sample_size=validity["sample_size"],
            method="conservative-leaf-minimum",
            evidence=[
                name
                for name, component in zip(
                    CONFIDENCE_DEPENDENCIES["overall_decision_confidence"],
                    leaf_components,
                    strict=True,
                )
                if component["estimate"] is not None
            ],
            explanation=(
                "Overall decision confidence is the minimum available leaf "
                "component. Scanner reliability is consumed through finding "
                "validity and is not counted a second time."
            ),
            maturity=validity["maturity"],
            decision_tier=_decision_tier(
                overall_bound,
                validity["sample_size"],
            ),
        )
    else:
        overall = unscored_component(
            "overall_decision_confidence",
            "No decision-relevant confidence component is scored.",
        )

    components = {
        "scanner_rule_reliability": scanner,
        "finding_validity_confidence": validity,
        "reachability_confidence": reachability,
        "exploitability_confidence": exploitability,
        "remediation_confidence": remediation,
        "overall_decision_confidence": overall,
    }
    return deepcopy(components)


__all__ = [
    "CONFIDENCE_DEFINITIONS",
    "CONFIDENCE_DEPENDENCIES",
    "CONFIDENCE_EVIDENCE",
    "CONFIDENCE_FIELDS",
    "build_confidence_components",
    "unscored_component",
    "validate_dependency_graph",
]
