"""Explainable, deterministic scanner selection."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from trustgate.adapters import AdapterRegistry
from trustgate.repository import PackageContext, RepositoryContext

from .models import (
    DataHandling,
    PlanningConfigurationError,
    PlanningOverrides,
    ScanDecision,
    ScanPlan,
)

_OPT_IN_SCANNERS = frozenset({"trufflehog"})
_LANGUAGE_SUFFIXES = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".swift": "swift",
    ".ts": "typescript",
    ".tsx": "typescript",
}


def _validate_overrides(
    overrides: PlanningOverrides, scanner_names: frozenset[str]
) -> None:
    conflicts = overrides.enable_scanners & overrides.disable_scanners
    if conflicts:
        raise PlanningConfigurationError(
            "scanner cannot be both enabled and disabled: "
            + ", ".join(sorted(conflicts))
        )
    referenced = (
        overrides.enable_scanners
        | overrides.disable_scanners
        | frozenset(overrides.timeouts)
    )
    unknown = referenced - scanner_names
    if unknown:
        raise PlanningConfigurationError(
            "unknown scanner override: " + ", ".join(sorted(unknown))
        )
    invalid_timeouts = sorted(
        scanner
        for scanner, timeout in overrides.timeouts.items()
        if timeout <= 0
    )
    if invalid_timeouts:
        raise PlanningConfigurationError(
            "scanner timeouts must be greater than zero: "
            + ", ".join(invalid_timeouts)
        )


def _package_repository(
    repository: RepositoryContext, package: PackageContext
) -> RepositoryContext:
    prefix = "" if package.root == "." else f"{package.root}/"
    package_files = package.files

    def local_values(values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            value.removeprefix(prefix)
            for value in values
            if value in package_files
        )

    local_files = frozenset(
        file_name.removeprefix(prefix) for file_name in package.files
    )
    return RepositoryContext(
        root=(
            repository.root
            if package.root == "."
            else repository.root / package.root
        ),
        files=local_files,
        languages=package.languages,
        frameworks=package.frameworks,
        package_managers=package.package_managers,
        build_systems=package.build_systems,
        lock_files=local_values(repository.lock_files),
        container_files=local_values(repository.container_files),
        kubernetes_files=local_values(repository.kubernetes_files),
        terraform_files=local_values(repository.terraform_files),
        cloudformation_files=local_values(repository.cloudformation_files),
        openapi_specifications=local_values(repository.openapi_specifications),
        dependencies=package.dependencies,
        packages=(package,),
        exclude_generated=repository.exclude_generated,
        exclude_vendored=repository.exclude_vendored,
    )


def _candidate_contexts(
    repository: RepositoryContext,
) -> tuple[tuple[str, RepositoryContext], ...]:
    if not repository.packages:
        return ((".", repository),)
    package_contexts = tuple(
        (package.root, _package_repository(repository, package))
        for package in repository.packages
    )
    if any(package.root == "." for package in repository.packages):
        return package_contexts

    prefixes = tuple(f"{package.root}/" for package in repository.packages)
    root_files = frozenset(
        file_name
        for file_name in repository.files
        if not any(file_name.startswith(prefix) for prefix in prefixes)
    )
    root_languages = frozenset(
        language
        for file_name in root_files
        if (
            language
            := _LANGUAGE_SUFFIXES.get(Path(file_name).suffix.lower())
        )
    )

    def root_values(values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(value for value in values if value in root_files)

    root_context = RepositoryContext(
        root=repository.root,
        files=root_files,
        languages=root_languages,
        lock_files=root_values(repository.lock_files),
        container_files=root_values(repository.container_files),
        kubernetes_files=root_values(repository.kubernetes_files),
        terraform_files=root_values(repository.terraform_files),
        cloudformation_files=root_values(repository.cloudformation_files),
        openapi_specifications=root_values(repository.openapi_specifications),
        exclude_generated=repository.exclude_generated,
        exclude_vendored=repository.exclude_vendored,
    )
    return ((".", root_context), *package_contexts)


def _adapter_applicable(adapter: Any, context: RepositoryContext) -> bool:
    if adapter.metadata().name == "zap" and context.openapi_specifications:
        return True
    return adapter.is_applicable(context)


def _supported_file_matches(
    files: frozenset[str], patterns: tuple[str, ...]
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                file_name
                for file_name in files
                for pattern in patterns
                if fnmatch(file_name, pattern)
                or fnmatch(Path(file_name).name, pattern)
            }
        )
    )


def _automatic_reason(
    adapter: Any,
    contexts: tuple[tuple[str, RepositoryContext], ...],
    targets: tuple[str, ...],
) -> str:
    metadata = adapter.metadata()
    target_set = set(targets)
    languages: set[str] = set()
    matching_files: set[str] = set()
    for target, context in contexts:
        if target not in target_set:
            continue
        languages.update(set(metadata.supported_languages) & context.languages)
        matching_files.update(
            _supported_file_matches(context.files, metadata.supported_files)
        )
        if metadata.name == "zap":
            matching_files.update(context.openapi_specifications)
    signals: list[str] = []
    if languages:
        signals.append("detected language(s): " + ", ".join(sorted(languages)))
    if matching_files:
        preview = sorted(matching_files)[:3]
        suffix = "…" if len(matching_files) > len(preview) else ""
        signals.append("matching file(s): " + ", ".join(preview) + suffix)
    if signals:
        return "; ".join(signals)
    if getattr(adapter, "globally_applicable", False):
        return f"repository-wide {metadata.category} coverage"
    return "applicable repository signals detected"


def _expected_outputs(adapter: Any, targets: tuple[str, ...]) -> tuple[str, ...]:
    metadata = adapter.metadata()
    report_name = getattr(
        adapter,
        "native_report_filename",
        f"{metadata.name}_report.{metadata.report_format}",
    )
    outputs: list[str] = []
    for target in targets:
        prefix = "reports" if target == "." else f"reports/{target}"
        outputs.extend(
            (
                f"{prefix}/{report_name}",
                f"{prefix}/{metadata.name}_execution.json",
                f"{prefix}/{metadata.name}_findings.json",
            )
        )
    return tuple(outputs)


def _detected_technologies(repository: RepositoryContext) -> dict[str, Any]:
    return {
        "languages": sorted(repository.languages),
        "frameworks": sorted(repository.frameworks),
        "package_managers": sorted(repository.package_managers),
        "lock_files": list(repository.lock_files),
        "build_systems": sorted(repository.build_systems),
        "container_files": list(repository.container_files),
        "kubernetes_files": list(repository.kubernetes_files),
        "terraform_files": list(repository.terraform_files),
        "cloudformation_files": list(repository.cloudformation_files),
        "openapi_specifications": list(repository.openapi_specifications),
        "test_directories": list(repository.test_directories),
        "generated_files": list(repository.generated_files),
        "vendored_dependencies": list(repository.vendored_dependencies),
        "packages": [
            {
                "name": package.name,
                "root": package.root,
                "languages": sorted(package.languages),
                "frameworks": sorted(package.frameworks),
                "package_managers": sorted(package.package_managers),
            }
            for package in repository.packages
        ],
        "dependency_scopes": {
            "runtime": sum(
                dependency.scope.value == "runtime"
                for dependency in repository.dependencies
            ),
            "development": sum(
                dependency.scope.value == "development"
                for dependency in repository.dependencies
            ),
        },
        "exclusions": dict(sorted(repository.exclusion_reasons.items())),
    }


def build_scan_plan(
    repository: RepositoryContext,
    registry: AdapterRegistry,
    *,
    overrides: PlanningOverrides | None = None,
) -> ScanPlan:
    """Build a deterministic plan without executing any scanner."""

    resolved_overrides = overrides or PlanningOverrides()
    scanner_names = frozenset(registry.names())
    _validate_overrides(resolved_overrides, scanner_names)
    contexts = _candidate_contexts(repository)
    decisions: list[ScanDecision] = []

    for scanner in sorted(scanner_names):
        adapter = registry.get(scanner)
        metadata = adapter.metadata()
        globally_applicable = bool(
            getattr(adapter, "globally_applicable", False)
        )
        if globally_applicable:
            automatic_targets = (".",)
        else:
            automatic_targets = tuple(
                target
                for target, context in contexts
                if _adapter_applicable(adapter, context)
            )
        automatically_enabled = bool(automatic_targets)
        target_directories = automatic_targets
        reason = (
            _automatic_reason(adapter, contexts, automatic_targets)
            if automatically_enabled
            else "no supported language or file signal detected"
        )
        decision_source = "automatic"

        if scanner in _OPT_IN_SCANNERS and scanner not in resolved_overrides.enable_scanners:
            automatically_enabled = False
            target_directories = ()
            reason = "optional scanner is disabled by default; opt-in required"
        if scanner in resolved_overrides.enable_scanners:
            automatically_enabled = True
            target_directories = automatic_targets or (".",)
            reason = "explicitly enabled by scanner override"
            decision_source = "override"
        if scanner in resolved_overrides.disable_scanners:
            automatically_enabled = False
            target_directories = ()
            reason = "explicitly disabled by scanner override"
            decision_source = "override"

        timeout = float(
            resolved_overrides.timeouts.get(scanner, metadata.default_timeout)
        )
        if scanner in resolved_overrides.timeouts:
            decision_source = "override"
        data_leaves_runner = metadata.data_leaves_runner
        data_handling = DataHandling(
            data_leaves_runner=data_leaves_runner,
            behaviour=(
                "scanner may transmit repository data outside the runner"
                if data_leaves_runner
                else "local-only; repository data does not leave the runner"
            ),
        )
        decisions.append(
            ScanDecision(
                scanner=scanner,
                enabled=automatically_enabled,
                reason=reason,
                target_directories=target_directories,
                expected_outputs=(
                    _expected_outputs(adapter, target_directories)
                    if automatically_enabled
                    else ()
                ),
                timeout_seconds=timeout,
                data_handling=data_handling,
                decision_source=decision_source,
            )
        )

    return ScanPlan(
        target=str(repository.root),
        detected_technologies=_detected_technologies(repository),
        decisions=tuple(decisions),
        dry_run=resolved_overrides.dry_run,
    )


__all__ = ["build_scan_plan"]
