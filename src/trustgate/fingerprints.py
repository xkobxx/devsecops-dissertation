"""Versioned, line-stable finding fingerprints."""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
from typing import Any


FINGERPRINT_ALGORITHM_VERSION = "v2"

_ECOSYSTEM_ALIASES = {
    "pip": "pypi",
    "python": "pypi",
    "pypi": "pypi",
}


def normalise_repository_path(
    value: str | os.PathLike[str] | None,
    *,
    repository_root: str | os.PathLike[str] | None = None,
) -> str | None:
    """Return a portable repository-relative path when a root is available."""

    if value is None:
        return None
    path = os.fspath(value).replace("\\", "/")
    if not path:
        return ""
    root = (
        os.fspath(repository_root).replace("\\", "/").rstrip("/")
        if repository_root is not None
        else None
    )
    if root:
        root_comparison = root.casefold()
        path_comparison = path.casefold()
        if path_comparison == root_comparison:
            path = "."
        elif path_comparison.startswith(root_comparison + "/"):
            path = path[len(root) + 1 :]
    path = re.sub(r"^[A-Za-z]:/", "/", path)
    normalised = posixpath.normpath(path)
    while normalised.startswith("./"):
        normalised = normalised[2:]
    return normalised


def _string_list(value: Any) -> list[str]:
    values = value if isinstance(value, list) else [value]
    return sorted(
        {
            str(item).strip().upper()
            for item in values
            if item is not None and str(item).strip()
        }
    )


def _dependency_identity(finding: dict[str, Any]) -> dict[str, Any] | None:
    dependency = finding.get("dependency")
    if not isinstance(dependency, dict):
        return None
    name = str(dependency.get("name") or "").strip().lower()
    ecosystem = str(dependency.get("ecosystem") or "").strip().lower()
    ecosystem = _ECOSYSTEM_ALIASES.get(ecosystem, ecosystem)
    if ecosystem == "pypi":
        name = re.sub(r"[-_.]+", "-", name)
    cve = _string_list(finding.get("cve"))
    ghsa = _string_list(finding.get("ghsa"))
    osv = _string_list(finding.get("osv"))
    identifiers = cve or ghsa or osv
    if not identifiers:
        identifiers = _string_list(finding.get("rule_id"))
    return {
        "kind": "dependency",
        "category": "sca",
        "component": {
            "ecosystem": ecosystem,
            "name": name,
        },
        "advisory_identifiers": identifiers,
    }


def _correlation_identity(
    finding: dict[str, Any],
    *,
    repository_root: str | os.PathLike[str] | None,
) -> dict[str, Any]:
    dependency_identity = _dependency_identity(finding)
    if dependency_identity is not None:
        return dependency_identity
    return {
        "kind": str(finding.get("category") or "unknown").strip().lower(),
        "rule_id": str(finding.get("rule_id") or "").strip().lower(),
        "file": normalise_repository_path(
            finding.get("file"),
            repository_root=repository_root,
        ),
        "symbol": str(finding.get("symbol") or "").strip(),
        "source": str(finding.get("source") or "").strip(),
        "sink": str(finding.get("sink") or "").strip(),
        "cwe": _string_list(finding.get("cwe")),
    }


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def fingerprint_finding(
    finding: dict[str, Any],
    *,
    repository_root: str | os.PathLike[str] | None = None,
) -> tuple[str, str]:
    """Return scanner-specific finding ID and cross-scanner fingerprint."""

    if not isinstance(finding, dict):
        raise TypeError("finding must be an object")
    correlation_identity = _correlation_identity(
        finding,
        repository_root=repository_root,
    )
    correlation_digest = _digest(
        {
            "algorithm": FINGERPRINT_ALGORITHM_VERSION,
            "identity": correlation_identity,
        }
    )
    fingerprint = (
        f"{FINGERPRINT_ALGORITHM_VERSION}:sha256:{correlation_digest}"
    )
    scanner = str(
        finding.get("scanner") or finding.get("tool") or "unknown"
    ).strip().lower()
    finding_digest = _digest(
        {
            "algorithm": FINGERPRINT_ALGORITHM_VERSION,
            "scanner": scanner,
            "rule_id": str(finding.get("rule_id") or "").strip().lower(),
            "fingerprint": fingerprint,
        }
    )
    return f"finding-v2-{finding_digest[:24]}", fingerprint


__all__ = [
    "FINGERPRINT_ALGORITHM_VERSION",
    "fingerprint_finding",
    "normalise_repository_path",
]
