"""Immutable contracts for contextual decision evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


COMPONENT_NAMES = (
    "finding_validity_confidence",
    "original_severity",
    "normalised_severity",
    "reachability",
    "epss",
    "cisa_kev",
    "public_exploit_availability",
    "internet_exposure",
    "authentication_requirements",
    "data_sensitivity",
    "asset_criticality",
    "runtime_environment",
    "existing_controls",
    "fix_availability",
    "new_existing_status",
    "human_triage_state",
)


class DecisionOutcome(StrEnum):
    BLOCK_IMMEDIATELY = "BLOCK_IMMEDIATELY"
    FIX_BEFORE_RELEASE = "FIX_BEFORE_RELEASE"
    FIX_WITHIN_SLA = "FIX_WITHIN_SLA"
    INVESTIGATE = "INVESTIGATE"
    MONITOR = "MONITOR"
    TEMPORARILY_SUPPRESSED = "TEMPORARILY_SUPPRESSED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    LIKELY_NOISE = "LIKELY_NOISE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


@dataclass(frozen=True)
class DecisionComponent:
    name: str
    value: Any
    evidence: tuple[str, ...] = ()
    uncertainty: str | None = None

    def __post_init__(self) -> None:
        if self.name not in COMPONENT_NAMES:
            raise ValueError(f"unknown decision component: {self.name}")
        if self.value is None and not self.uncertainty:
            raise ValueError(f"missing {self.name} requires explicit uncertainty")

    def to_dict(self) -> dict[str, Any]:
        value = list(self.value) if isinstance(self.value, tuple) else self.value
        return {
            "value": value,
            "evidence": list(self.evidence),
            "uncertainty": self.uncertainty,
        }

    @classmethod
    def from_dict(cls, name: str, value: dict[str, Any]) -> "DecisionComponent":
        component_value = value.get("value")
        if name == "existing_controls" and isinstance(component_value, list):
            component_value = tuple(str(item) for item in component_value)
        return cls(
            name=name,
            value=component_value,
            evidence=tuple(str(item) for item in value.get("evidence", ())),
            uncertainty=(
                str(value["uncertainty"])
                if value.get("uncertainty") is not None
                else None
            ),
        )


@dataclass(frozen=True)
class DecisionContext:
    finding_id: str
    components: tuple[DecisionComponent, ...]

    def __post_init__(self) -> None:
        if not self.finding_id:
            raise ValueError("finding_id is required")
        names = [component.name for component in self.components]
        if len(names) != len(set(names)):
            raise ValueError("decision component names must be unique")
        missing = set(COMPONENT_NAMES) - set(names)
        unknown = set(names) - set(COMPONENT_NAMES)
        if missing or unknown:
            raise ValueError(
                f"decision context mismatch; missing={sorted(missing)} "
                f"unknown={sorted(unknown)}"
            )

    def component(self, name: str) -> DecisionComponent:
        for component in self.components:
            if component.name == name:
                return component
        raise KeyError(name)

    def value(self, name: str) -> Any:
        value = self.component(name).value
        return list(value) if isinstance(value, tuple) else value

    def unresolved_uncertainty(self) -> list[str]:
        return [
            component.name
            for component in self.components
            if component.uncertainty is not None
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "components": {
                component.name: component.to_dict()
                for component in self.components
            },
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DecisionContext":
        raw_components = value.get("components")
        if not isinstance(raw_components, dict):
            raise ValueError("decision context components must be an object")
        return cls(
            finding_id=str(value.get("finding_id") or ""),
            components=tuple(
                DecisionComponent.from_dict(name, raw_components[name])
                for name in COMPONENT_NAMES
                if name in raw_components
            ),
        )


_OPERATORS = {"equals", "not_equals", "in", "gte", "lte", "contains", "is_known"}


@dataclass(frozen=True)
class Condition:
    component: str
    operator: str
    expected: Any

    def __post_init__(self) -> None:
        if self.component not in COMPONENT_NAMES:
            raise ValueError(f"unknown decision component: {self.component}")
        if self.operator not in _OPERATORS:
            raise ValueError(f"unsupported condition operator: {self.operator}")

    def matches(self, context: DecisionContext) -> bool:
        actual = context.value(self.component)
        if self.operator == "equals":
            return actual == self.expected
        if self.operator == "not_equals":
            return actual != self.expected
        if self.operator == "in":
            return actual in self.expected
        if self.operator == "gte":
            return actual is not None and actual >= self.expected
        if self.operator == "lte":
            return actual is not None and actual <= self.expected
        if self.operator == "contains":
            return actual is not None and self.expected in actual
        return (actual is not None) is bool(self.expected)

    def to_dict(self) -> dict[str, Any]:
        expected = list(self.expected) if isinstance(self.expected, tuple) else self.expected
        return {
            "component": self.component,
            "operator": self.operator,
            "expected": expected,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Condition":
        expected = value.get("expected")
        if value.get("operator") == "in" and isinstance(expected, list):
            expected = tuple(expected)
        return cls(
            component=str(value["component"]),
            operator=str(value["operator"]),
            expected=expected,
        )


@dataclass(frozen=True)
class DecisionRule:
    rule_id: str
    outcome: DecisionOutcome
    all_of: tuple[Condition, ...]
    explanation: str

    def __post_init__(self) -> None:
        if not self.rule_id or not self.explanation:
            raise ValueError("decision rules require an id and explanation")
        if not self.all_of:
            raise ValueError("decision rules require at least one condition")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "outcome": self.outcome.value,
            "conditions": [condition.to_dict() for condition in self.all_of],
            "explanation": self.explanation,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DecisionRule":
        return cls(
            rule_id=str(value["rule_id"]),
            outcome=DecisionOutcome(str(value["outcome"])),
            all_of=tuple(
                Condition.from_dict(condition)
                for condition in value.get("conditions", ())
            ),
            explanation=str(value["explanation"]),
        )


@dataclass(frozen=True)
class DecisionPolicy:
    policy_id: str
    version: str
    rules: tuple[DecisionRule, ...]
    default_outcome: DecisionOutcome

    def __post_init__(self) -> None:
        if not self.policy_id or not self.version:
            raise ValueError("policy id and version are required")
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("duplicate rule id in decision policy")

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "rules": [rule.to_dict() for rule in self.rules],
            "default_outcome": self.default_outcome.value,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DecisionPolicy":
        return cls(
            policy_id=str(value["policy_id"]),
            version=str(value["version"]),
            rules=tuple(
                DecisionRule.from_dict(rule)
                for rule in value.get("rules", ())
            ),
            default_outcome=DecisionOutcome(str(value["default_outcome"])),
        )


@dataclass(frozen=True)
class EvidenceStrength:
    level: str
    known_components: int
    total_components: int
    finding_validity_lower_bound: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "known_components": self.known_components,
            "total_components": self.total_components,
            "finding_validity_lower_bound": self.finding_validity_lower_bound,
        }


@dataclass(frozen=True)
class Decision:
    decision_id: str
    finding_id: str
    outcome: DecisionOutcome
    policy: dict[str, Any]
    context: DecisionContext
    explanation: tuple[str, ...]
    evidence_strength: EvidenceStrength
    unresolved_uncertainty: tuple[str, ...]
    evaluation_trace: tuple[dict[str, Any], ...]
    reproduction_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "decision_id": self.decision_id,
            "finding_id": self.finding_id,
            "outcome": self.outcome.value,
            "policy": self.policy,
            "context": self.context.to_dict(),
            "explanation": list(self.explanation),
            "evidence_strength": self.evidence_strength.to_dict(),
            "unresolved_uncertainty": list(self.unresolved_uncertainty),
            "evaluation_trace": list(self.evaluation_trace),
            "reproduction_digest": self.reproduction_digest,
        }
