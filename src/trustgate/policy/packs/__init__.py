"""Packaged standard Trust Gate policy catalogue."""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path
from typing import Any


def policy_pack_directory() -> Path:
    """Return the installed standard-pack resource directory."""

    return Path(__file__).resolve().parent


@lru_cache(maxsize=1)
def _manifest() -> dict[str, dict[str, Any]]:
    path = policy_pack_directory() / "manifest.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("version") != 1:
        raise ValueError("standard policy-pack manifest version must be 1")
    packs = value.get("packs")
    if not isinstance(packs, list) or len(packs) != 10:
        raise ValueError("standard policy-pack manifest must define ten packs")
    records: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(packs):
        if not isinstance(record, dict):
            raise ValueError(f"policy-pack manifest packs[{index}] must be an object")
        required = {"name", "policy_id", "policy_version", "path", "description"}
        if set(record) != required:
            raise ValueError(
                f"policy-pack manifest packs[{index}] must define {sorted(required)}"
            )
        name = record.get("name")
        if not isinstance(name, str) or not name or name in records:
            raise ValueError(f"invalid or duplicate policy-pack name at index {index}")
        if any(not isinstance(record[field], str) or not record[field] for field in required):
            raise ValueError(f"policy-pack manifest packs[{index}] values must be strings")
        records[name] = dict(record)
    return records


def available_policy_packs() -> dict[str, dict[str, Any]]:
    """Return a defensive copy of the ten installed standard-pack records."""

    return deepcopy(_manifest())


__all__ = ["available_policy_packs", "policy_pack_directory"]
