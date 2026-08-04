"""Exact-version policy inheritance and override resolution."""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Mapping

from .models import PolicyAction, PolicyDocument, PolicyRule


class PolicyResolutionError(ValueError):
    """Raised when policy inheritance cannot be resolved safely."""


def _deduplicate(rules: list[PolicyRule]) -> tuple[PolicyRule, ...]:
    retained: list[PolicyRule] = []
    names: set[str] = set()
    for rule in rules:
        if rule.name in names:
            continue
        names.add(rule.name)
        retained.append(rule)
    return tuple(retained)


def resolve_policy(
    document: PolicyDocument,
    *,
    inherited: Mapping[tuple[str, str], PolicyDocument] | None = None,
    repository: str | None = None,
) -> PolicyDocument:
    """Resolve exact parents, defaults, and matching repository overrides."""

    available = inherited or {}
    parents: list[PolicyDocument] = []
    for reference in document.extends:
        identity = (reference.policy_id, reference.policy_version)
        parent = available.get(identity)
        if parent is None:
            raise PolicyResolutionError(
                f"required inherited policy {reference.policy_id}@"
                f"{reference.policy_version} was not provided"
            )
        parents.append(parent)

    matching_overrides = [
        override
        for override in document.repository_overrides
        if repository is not None
        and any(fnmatchcase(repository, pattern) for pattern in override.repositories)
    ]
    ordered_rules: list[PolicyRule] = []
    for override in matching_overrides:
        ordered_rules.extend(override.policies)
    ordered_rules.extend(document.policies)
    if document.organisation_defaults is not None:
        ordered_rules.extend(document.organisation_defaults.policies)
    for parent in parents:
        ordered_rules.extend(parent.policies)

    default_action: PolicyAction | None = next(
        (
            override.default_action
            for override in matching_overrides
            if override.default_action is not None
        ),
        None,
    )
    if default_action is None and document.default_action_explicit:
        default_action = document.default_action
    if (
        default_action is None
        and document.organisation_defaults is not None
        and document.organisation_defaults.default_action is not None
    ):
        default_action = document.organisation_defaults.default_action
    if default_action is None and parents:
        default_action = parents[0].default_action
    if default_action is None:
        default_action = PolicyAction.INVESTIGATE

    return PolicyDocument(
        schema_version=document.schema_version,
        version=document.version,
        policy_id=document.policy_id,
        policy_version=document.policy_version,
        description=document.description,
        default_action=default_action,
        default_action_explicit=True,
        policies=_deduplicate(ordered_rules),
    )


__all__ = ["PolicyResolutionError", "resolve_policy"]
