"""Python-first dependency reachability analysis."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import tomllib
from typing import Any, Iterable

from trustgate.repository import RepositoryContext

from .models import ReachabilityStatus


_IGNORED_DIRECTORIES = frozenset(
    {".git", ".hg", ".svn", ".tox", ".venv", "venv", "node_modules", "vendor"}
)
_DYNAMIC_LIMITATION = (
    "Dynamic behaviour remains unknown because static analysis cannot observe "
    "reflective imports, monkey patching, "
    "runtime dependency loading, generated code, or environment-specific paths."
)


def analyze_dependency_reachability(
    finding: dict[str, Any],
    *,
    repository_root: Path,
    vulnerable_symbols: Iterable[str] = (),
    deployed_packages: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Determine local dependency evidence without claiming non-exploitability."""

    dependency = finding.get("dependency")
    if not isinstance(dependency, dict) or not dependency.get("name"):
        return _not_analysed()

    root = Path(repository_root).resolve()
    name = _normalise_name(str(dependency["name"]))
    context = RepositoryContext.from_path(root)
    direct_matches = [
        item
        for item in context.dependencies
        if _normalise_name(item.name) == name
    ]
    locked = _locked_dependencies(root)
    explicit_direct = dependency.get("direct")
    if isinstance(explicit_direct, bool):
        relationship = "direct" if explicit_direct else "transitive"
    elif direct_matches:
        relationship = "direct"
    elif name in locked:
        relationship = "transitive"
    else:
        relationship = "unknown"

    package_installed = bool(
        direct_matches or name in locked or dependency.get("version")
    )
    scope = str(finding.get("dependency_scope") or "unknown")
    if scope == "unknown" and direct_matches:
        scopes = {item.scope.value for item in direct_matches}
        scope = "runtime" if "runtime" in scopes else "development"

    deployed_names = (
        None
        if deployed_packages is None
        else {_normalise_name(value) for value in deployed_packages}
    )
    included = None if deployed_names is None else name in deployed_names

    symbols = tuple(sorted({_normalise_symbol(value) for value in vulnerable_symbols}))
    source_evidence = _python_dependency_evidence(root, name, symbols)
    imported = source_evidence["imported"]
    called = source_evidence["called"] if symbols else None
    analysed_files = source_evidence["analysed_files"]
    parse_failures = source_evidence["parse_failures"]

    call_path: list[dict[str, Any]] = []
    manifest_source = (
        direct_matches[0].source
        if direct_matches
        else locked.get(name)
    )
    if manifest_source:
        call_path.append(
            _step(
                "manifest",
                manifest_source,
                None,
                name,
                f"Dependency {name} is declared or locked.",
            )
        )
    if source_evidence["import_step"]:
        call_path.append(source_evidence["import_step"])
    if source_evidence["call_step"]:
        call_path.append(source_evidence["call_step"])

    incomplete = bool(
        relationship == "unknown"
        or scope == "unknown"
        or included is None
        or called is None
        or parse_failures
    )
    call_path_exists = called is True
    if not package_installed:
        status = ReachabilityStatus.NO_PATH_FOUND
        explanation = (
            "The dependency was not observed in local manifests, lock files, or "
            "scanner version evidence; runtime presence remains unknown."
        )
    elif call_path_exists and not incomplete:
        status = ReachabilityStatus.CONFIRMED_REACHABLE
        explanation = "A static import-to-vulnerable-symbol call path was identified."
    elif incomplete:
        status = ReachabilityStatus.ANALYSIS_INCOMPLETE
        explanation = (
            "Some reachability inputs were unavailable; the result is incomplete."
        )
    elif imported:
        status = ReachabilityStatus.LIKELY_REACHABLE
        explanation = "The dependency is imported, but no confirmed vulnerable call exists."
    else:
        status = ReachabilityStatus.NO_PATH_FOUND
        explanation = (
            "No static import-to-symbol path was found in the analysed files; "
            "this result does not determine exploitability."
        )

    limitations = [_DYNAMIC_LIMITATION]
    if parse_failures:
        limitations.append(
            "Some Python files could not be parsed: " + ", ".join(parse_failures)
        )
    if symbols == ():
        limitations.append("No vulnerable-symbol metadata was supplied.")
    if deployed_names is None:
        limitations.append("No deployed-artifact package inventory was supplied.")

    return {
        "status": status.value,
        "package_installed": package_installed,
        "dependency_relationship": relationship,
        "imported": imported,
        "vulnerable_symbol_called": called,
        "dependency_scope": scope,
        "included_in_deployed_artifact": included,
        "call_path_exists": call_path_exists,
        "analysis_incomplete": incomplete,
        "dynamic_behaviour_unknown": True,
        "analysed_call_path": call_path,
        "analysed_files": analysed_files,
        "limitations": limitations,
        "explanation": explanation,
    }


def _not_analysed() -> dict[str, Any]:
    return {
        "status": ReachabilityStatus.NOT_ANALYSED.value,
        "package_installed": None,
        "dependency_relationship": "not-applicable",
        "imported": None,
        "vulnerable_symbol_called": None,
        "dependency_scope": "not-applicable",
        "included_in_deployed_artifact": None,
        "call_path_exists": None,
        "analysis_incomplete": True,
        "dynamic_behaviour_unknown": True,
        "analysed_call_path": [],
        "analysed_files": [],
        "limitations": [_DYNAMIC_LIMITATION, "The finding has no dependency metadata."],
        "explanation": "Dependency reachability was not analysed for this finding.",
    }


def _python_dependency_evidence(
    root: Path,
    dependency: str,
    symbols: tuple[str, ...],
) -> dict[str, Any]:
    imported = False
    called = False
    import_step = None
    call_step = None
    analysed_files: list[str] = []
    parse_failures: list[str] = []
    module_name = dependency.replace("-", "_").split(".", 1)[0]
    for path in _python_files(root):
        relative = path.relative_to(root).as_posix()
        analysed_files.append(relative)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (OSError, SyntaxError, UnicodeError):
            parse_failures.append(relative)
            continue
        aliases: set[str] = set()
        imported_symbols: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] == module_name:
                        imported = True
                        aliases.add(alias.asname or module_name)
                        import_step = import_step or _step(
                            "import", relative, node.lineno, alias.name,
                            f"Imports dependency {dependency}.",
                        )
            elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".", 1)[0] == module_name:
                imported = True
                for alias in node.names:
                    imported_symbols[alias.asname or alias.name] = alias.name
                import_step = import_step or _step(
                    "import", relative, node.lineno, node.module,
                    f"Imports symbols from dependency {dependency}.",
                )
        if symbols:
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                called_name = _call_name(node.func)
                matches_attribute = any(
                    called_name == f"{alias}.{symbol}"
                    or called_name.startswith(f"{alias}.{symbol}.")
                    for alias in aliases
                    for symbol in symbols
                )
                matches_import = any(
                    called_name == local and original in symbols
                    for local, original in imported_symbols.items()
                )
                if matches_attribute or matches_import:
                    called = True
                    call_step = _step(
                        "call", relative, node.lineno, called_name,
                        "Calls a configured vulnerable symbol.",
                    )
                    break
    return {
        "imported": imported,
        "called": called,
        "import_step": import_step,
        "call_step": call_step,
        "analysed_files": sorted(analysed_files),
        "parse_failures": sorted(parse_failures),
    }


def _python_files(root: Path) -> tuple[Path, ...]:
    files = []
    for current, directories, names in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories if name not in _IGNORED_DIRECTORIES
        )
        for name in sorted(names):
            path = Path(current) / name
            if name.endswith(".py") and not path.is_symlink():
                files.append(path)
    return tuple(files)


def _locked_dependencies(root: Path) -> dict[str, str]:
    locked: dict[str, str] = {}
    package_lock = root / "package-lock.json"
    if package_lock.is_file():
        try:
            data = json.loads(package_lock.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        if isinstance(data, dict):
            packages = data.get("packages", {})
            if isinstance(packages, dict):
                for key in packages:
                    if key.startswith("node_modules/"):
                        locked[_normalise_name(key.rsplit("node_modules/", 1)[1])] = "package-lock.json"
    for lock_name in ("uv.lock", "poetry.lock"):
        lock_path = root / lock_name
        if not lock_path.is_file():
            continue
        try:
            data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        packages = data.get("package", []) if isinstance(data, dict) else []
        for package in packages if isinstance(packages, list) else []:
            if isinstance(package, dict) and package.get("name"):
                locked[_normalise_name(str(package["name"]))] = lock_name
    return locked


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _step(
    kind: str,
    file: str | None,
    line: int | None,
    symbol: str | None,
    description: str,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "file": file,
        "line": line,
        "symbol": symbol,
        "description": description,
    }


def _normalise_name(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def _normalise_symbol(value: str) -> str:
    return value.strip().rsplit(".", 1)[-1]
