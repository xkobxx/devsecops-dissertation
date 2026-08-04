"""Safe JSON/YAML loading and exact-version policy inheritance."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .models import PolicyDocument
from .resolution import PolicyResolutionError, resolve_policy


class PolicyLoadError(ValueError):
    """Raised when a policy document cannot be loaded safely."""


def _requested_policy_path(path: str | Path) -> Path:
    value = str(path)
    if not value.startswith("pack:"):
        return Path(path)
    name = value.removeprefix("pack:")
    from .packs import available_policy_packs, policy_pack_directory

    records = available_policy_packs()
    record = records.get(name)
    if record is None:
        available = ", ".join(sorted(records))
        raise PolicyLoadError(
            f"unknown standard policy pack {name!r}; available: {available}"
        )
    root = policy_pack_directory().resolve()
    selected = (root / record["path"]).resolve()
    if not selected.is_relative_to(root) or not selected.is_file():
        raise PolicyLoadError(
            f"unsafe or missing standard policy pack path for {name!r}"
        )
    return selected


def load_policy_file(path: str | Path) -> PolicyDocument:
    """Load and validate one JSON or YAML policy file."""

    policy_path = Path(path)
    try:
        source = policy_path.read_text(encoding="utf-8")
        if policy_path.suffix.lower() == ".json":
            value: Any = json.loads(source)
        else:
            value = yaml.safe_load(source)
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise PolicyLoadError(f"could not load {policy_path}: {error}") from error
    if not isinstance(value, dict):
        raise PolicyLoadError(f"policy root in {policy_path} must be an object")
    try:
        return PolicyDocument.from_dict(value)
    except (TypeError, ValueError, KeyError) as error:
        raise PolicyLoadError(f"invalid policy {policy_path}: {error}") from error


def load_effective_policy(
    path: str | Path,
    *,
    repository: str | None = None,
) -> PolicyDocument:
    """Load a policy and recursively resolve its declared exact parents."""

    cache: dict[Path, PolicyDocument] = {}

    def load(current: Path, stack: tuple[Path, ...]) -> PolicyDocument:
        resolved_path = current.expanduser().resolve()
        if resolved_path in stack:
            chain = " -> ".join(str(item) for item in (*stack, resolved_path))
            raise PolicyLoadError(f"policy inheritance cycle detected: {chain}")
        if resolved_path in cache:
            return cache[resolved_path]

        document = load_policy_file(resolved_path)
        inherited: dict[tuple[str, str], PolicyDocument] = {}
        for reference in document.extends:
            parent_path = (resolved_path.parent / reference.path).resolve()
            parent = load(parent_path, (*stack, resolved_path))
            expected = (reference.policy_id, reference.policy_version)
            actual = (parent.policy_id, parent.policy_version)
            if actual != expected:
                raise PolicyLoadError(
                    f"inherited policy {parent_path} is {parent.policy_id}@"
                    f"{parent.policy_version}, expected {reference.policy_id}@"
                    f"{reference.policy_version}"
                )
            inherited[expected] = parent
        try:
            effective = resolve_policy(
                document,
                inherited=inherited,
                repository=repository,
            )
        except PolicyResolutionError as error:
            raise PolicyLoadError(
                f"could not resolve policy {resolved_path}: {error}"
            ) from error
        cache[resolved_path] = effective
        return effective

    return load(_requested_policy_path(path), ())


__all__ = ["PolicyLoadError", "load_effective_policy", "load_policy_file"]
