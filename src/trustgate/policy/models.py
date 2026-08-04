"""Typed public contracts for Trust Gate policy-as-code."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from trustgate.schema import validate_instance


class PolicyAction(StrEnum):
    BLOCK = "block"
    FIX_BEFORE_RELEASE = "fix_before_release"
    FIX_WITHIN_SLA = "fix_within_sla"
    INVESTIGATE = "investigate"
    MONITOR = "monitor"
    TEMPORARILY_SUPPRESS = "temporarily_suppress"
    ACCEPT_RISK = "accept_risk"
    LIKELY_NOISE = "likely_noise"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


ACTION_OUTCOMES = {
    PolicyAction.BLOCK: "BLOCK_IMMEDIATELY",
    PolicyAction.FIX_BEFORE_RELEASE: "FIX_BEFORE_RELEASE",
    PolicyAction.FIX_WITHIN_SLA: "FIX_WITHIN_SLA",
    PolicyAction.INVESTIGATE: "INVESTIGATE",
    PolicyAction.MONITOR: "MONITOR",
    PolicyAction.TEMPORARILY_SUPPRESS: "TEMPORARILY_SUPPRESSED",
    PolicyAction.ACCEPT_RISK: "ACCEPTED_RISK",
    PolicyAction.LIKELY_NOISE: "LIKELY_NOISE",
    PolicyAction.INSUFFICIENT_EVIDENCE: "INSUFFICIENT_EVIDENCE",
}


@dataclass(frozen=True)
class PolicyRule:
    name: str
    action: PolicyAction
    when: dict[str, Any]
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "action": self.action.value,
            "when": deepcopy(self.when),
        }
        if self.description:
            result["description"] = self.description
        return result


@dataclass(frozen=True)
class PolicyReference:
    path: str
    policy_id: str
    policy_version: str

    def to_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class PolicyLayer:
    policies: tuple[PolicyRule, ...] = ()
    default_action: PolicyAction | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.default_action is not None:
            result["default_action"] = self.default_action.value
        if self.policies:
            result["policies"] = [rule.to_dict() for rule in self.policies]
        return result


@dataclass(frozen=True)
class RepositoryOverride:
    repositories: tuple[str, ...]
    policies: tuple[PolicyRule, ...] = ()
    default_action: PolicyAction | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "repositories": list(self.repositories),
        }
        if self.default_action is not None:
            result["default_action"] = self.default_action.value
        if self.policies:
            result["policies"] = [rule.to_dict() for rule in self.policies]
        return result


def _rules(values: list[dict[str, Any]]) -> tuple[PolicyRule, ...]:
    rules = tuple(
        PolicyRule(
            name=str(rule["name"]),
            action=PolicyAction(str(rule["action"])),
            when=deepcopy(rule["when"]),
            description=str(rule.get("description") or ""),
        )
        for rule in values
    )
    names = [rule.name for rule in rules]
    if len(names) != len(set(names)):
        raise ValueError("duplicate policy name")
    return rules


@dataclass(frozen=True)
class PolicyDocument:
    version: int
    policy_id: str
    policy_version: str
    policies: tuple[PolicyRule, ...]
    default_action: PolicyAction = PolicyAction.INVESTIGATE
    description: str = ""
    schema_version: str = "1.0.0"
    extends: tuple[PolicyReference, ...] = ()
    organisation_defaults: PolicyLayer | None = None
    repository_overrides: tuple[RepositoryOverride, ...] = ()
    default_action_explicit: bool = True

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "PolicyDocument":
        validate_instance("policy", value)
        rules = _rules(value["policies"])
        organisation_value = value.get("organisation_defaults")
        organisation_defaults = None
        if isinstance(organisation_value, dict):
            organisation_defaults = PolicyLayer(
                policies=_rules(organisation_value.get("policies", [])),
                default_action=(
                    PolicyAction(str(organisation_value["default_action"]))
                    if "default_action" in organisation_value
                    else None
                ),
            )
        repository_overrides = tuple(
            RepositoryOverride(
                repositories=(
                    (str(override["repositories"]),)
                    if isinstance(override["repositories"], str)
                    else tuple(str(item) for item in override["repositories"])
                ),
                policies=_rules(override.get("policies", [])),
                default_action=(
                    PolicyAction(str(override["default_action"]))
                    if "default_action" in override
                    else None
                ),
            )
            for override in value.get("repository_overrides", [])
        )
        return cls(
            schema_version=str(value["schema_version"]),
            version=int(value["version"]),
            policy_id=str(value["policy_id"]),
            policy_version=str(value["policy_version"]),
            description=str(value.get("description") or ""),
            default_action=PolicyAction(
                str(value.get("default_action") or "investigate")
            ),
            policies=rules,
            extends=tuple(
                PolicyReference(
                    path=str(reference["path"]),
                    policy_id=str(reference["policy_id"]),
                    policy_version=str(reference["policy_version"]),
                )
                for reference in value.get("extends", [])
            ),
            organisation_defaults=organisation_defaults,
            repository_overrides=repository_overrides,
            default_action_explicit="default_action" in value,
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": self.schema_version,
            "version": self.version,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "default_action": self.default_action.value,
            "policies": [rule.to_dict() for rule in self.policies],
        }
        if self.description:
            result["description"] = self.description
        if self.extends:
            result["extends"] = [reference.to_dict() for reference in self.extends]
        if self.organisation_defaults is not None:
            result["organisation_defaults"] = self.organisation_defaults.to_dict()
        if self.repository_overrides:
            result["repository_overrides"] = [
                override.to_dict() for override in self.repository_overrides
            ]
        return result


@dataclass(frozen=True)
class PolicyEvaluation:
    policy_id: str
    policy_version: str
    matched_policy: str | None
    action: PolicyAction
    outcome: str
    explanation: str
    context: dict[str, Any]
    trace: tuple[dict[str, Any], ...]
    evaluation_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "matched_policy": self.matched_policy,
            "action": self.action.value,
            "outcome": self.outcome,
            "explanation": self.explanation,
            "context": deepcopy(self.context),
            "trace": deepcopy(list(self.trace)),
            "evaluation_digest": self.evaluation_digest,
        }


__all__ = [
    "ACTION_OUTCOMES",
    "PolicyAction",
    "PolicyDocument",
    "PolicyEvaluation",
    "PolicyLayer",
    "PolicyReference",
    "PolicyRule",
    "RepositoryOverride",
]
