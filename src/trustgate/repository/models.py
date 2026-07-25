"""Deterministic, local-only repository technology discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from fnmatch import fnmatch
import json
import os
from pathlib import Path
import re
import tomllib
from types import MappingProxyType
from typing import Any, Mapping
import xml.etree.ElementTree as ElementTree


class DependencyScope(StrEnum):
    """Whether a dependency is needed in production or development."""

    RUNTIME = "runtime"
    DEVELOPMENT = "development"


@dataclass(frozen=True, slots=True)
class DependencyInfo:
    """A dependency discovered from a repository manifest."""

    name: str
    scope: DependencyScope
    ecosystem: str
    source: str
    package_root: str
    constraint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "scope": self.scope.value,
            "ecosystem": self.ecosystem,
            "source": self.source,
            "package_root": self.package_root,
            "constraint": self.constraint,
        }


@dataclass(frozen=True, slots=True)
class PackageContext:
    """A separately scannable package inside a repository."""

    name: str
    root: str
    manifests: tuple[str, ...]
    files: frozenset[str]
    languages: frozenset[str]
    frameworks: frozenset[str]
    package_managers: frozenset[str]
    build_systems: frozenset[str]
    dependencies: tuple[DependencyInfo, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "root": self.root,
            "manifests": list(self.manifests),
            "files": sorted(self.files),
            "languages": sorted(self.languages),
            "frameworks": sorted(self.frameworks),
            "package_managers": sorted(self.package_managers),
            "build_systems": sorted(self.build_systems),
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
        }


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
_VENDORED_DIRECTORIES = frozenset(
    {"node_modules", "vendor", ".venv", "venv", "site-packages"}
)
_ALWAYS_IGNORED_DIRECTORIES = frozenset({".git", ".hg", ".svn", ".tox"})
_GENERATED_DIRECTORIES = frozenset(
    {"build", "dist", "coverage", ".next", "out", "target", "generated"}
)
_TEST_DIRECTORIES = frozenset({"test", "tests", "spec", "specs", "__tests__"})
_PACKAGE_MANIFESTS = frozenset(
    {
        "package.json",
        "pyproject.toml",
        "setup.py",
        "go.mod",
        "Cargo.toml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile",
        "composer.json",
        "packages.config",
        "Pipfile",
    }
)
_LOCK_FILE_MANAGERS = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "poetry.lock": "poetry",
    "uv.lock": "uv",
    "Pipfile.lock": "pipenv",
    "go.sum": "go-modules",
    "Cargo.lock": "cargo",
    "Gemfile.lock": "bundler",
    "composer.lock": "composer",
    "packages.lock.json": "nuget",
}


def _relative(path: Path, root: Path) -> str:
    value = path.relative_to(root).as_posix()
    return value or "."


def _safe_text(path: Path) -> str:
    try:
        if path.stat().st_size > 2_000_000:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _is_generated(relative: str) -> bool:
    path = Path(relative)
    name = path.name.lower()
    parts = {part.lower() for part in path.parts[:-1]}
    return bool(
        parts & _GENERATED_DIRECTORIES
        or name.endswith((".min.js", ".min.css", ".map"))
        or ".generated." in name
        or name.endswith(("_pb2.py", ".designer.cs"))
    )


def _dependency_name(requirement: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
    return match.group(1).lower() if match else requirement.strip().lower()


def _dependency_constraint(requirement: str) -> str | None:
    name = _dependency_name(requirement)
    remainder = requirement.strip()[len(name) :].strip()
    return remainder or None


def _json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(_safe_text(path))
    except (json.JSONDecodeError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _toml(path: Path) -> Mapping[str, Any]:
    try:
        value = tomllib.loads(_safe_text(path))
    except (tomllib.TOMLDecodeError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _is_package_manifest(file_name: str) -> bool:
    name = Path(file_name).name
    lowered = name.lower()
    return bool(
        name in _PACKAGE_MANIFESTS
        or (
            lowered.startswith("requirements")
            and lowered.endswith((".txt", ".in"))
        )
        or lowered.endswith((".csproj", ".fsproj", ".vbproj"))
    )


def _manifest_dependencies(
    path: Path, relative: str, package_root: str
) -> tuple[DependencyInfo, ...]:
    dependencies: list[DependencyInfo] = []
    name = path.name
    if name == "package.json":
        data = _json(path)
        for field_name, scope in (
            ("dependencies", DependencyScope.RUNTIME),
            ("optionalDependencies", DependencyScope.RUNTIME),
            ("peerDependencies", DependencyScope.RUNTIME),
            ("devDependencies", DependencyScope.DEVELOPMENT),
        ):
            values = data.get(field_name, {})
            if isinstance(values, dict):
                for dependency, constraint in values.items():
                    dependencies.append(
                        DependencyInfo(
                            name=str(dependency).lower(),
                            scope=scope,
                            ecosystem="npm",
                            source=relative,
                            package_root=package_root,
                            constraint=str(constraint),
                        )
                    )
    elif name == "pyproject.toml":
        data = _toml(path)
        project = data.get("project", {})
        if isinstance(project, dict):
            values = project.get("dependencies", [])
            if isinstance(values, list):
                for value in values:
                    requirement = str(value)
                    dependencies.append(
                        DependencyInfo(
                            name=_dependency_name(requirement),
                            scope=DependencyScope.RUNTIME,
                            ecosystem="python",
                            source=relative,
                            package_root=package_root,
                            constraint=_dependency_constraint(requirement),
                        )
                    )
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for values in optional.values():
                    if not isinstance(values, list):
                        continue
                    for value in values:
                        requirement = str(value)
                        dependencies.append(
                            DependencyInfo(
                                name=_dependency_name(requirement),
                                scope=DependencyScope.DEVELOPMENT,
                                ecosystem="python",
                                source=relative,
                                package_root=package_root,
                                constraint=_dependency_constraint(requirement),
                            )
                        )
    elif name == "go.mod":
        text = _safe_text(path)
        in_require = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped == "require (":
                in_require = True
                continue
            if in_require and stripped == ")":
                in_require = False
                continue
            if stripped.startswith("require "):
                stripped = stripped.removeprefix("require ").strip()
            elif not in_require:
                continue
            parts = stripped.split()
            if parts and not parts[0].startswith("//"):
                dependencies.append(
                    DependencyInfo(
                        name=parts[0],
                        scope=DependencyScope.DEVELOPMENT
                        if "// indirect" in line
                        else DependencyScope.RUNTIME,
                        ecosystem="go",
                        source=relative,
                        package_root=package_root,
                        constraint=parts[1] if len(parts) > 1 else None,
                    )
                )
    elif name.lower().startswith("requirements") and name.lower().endswith(
        (".txt", ".in")
    ):
        scope = (
            DependencyScope.DEVELOPMENT
            if any(token in name.lower() for token in ("dev", "test"))
            else DependencyScope.RUNTIME
        )
        for line in _safe_text(path).splitlines():
            requirement = line.strip()
            if not requirement or requirement.startswith(("#", "-", "git+")):
                continue
            requirement = requirement.split(";", 1)[0].strip()
            dependencies.append(
                DependencyInfo(
                    name=_dependency_name(requirement),
                    scope=scope,
                    ecosystem="python",
                    source=relative,
                    package_root=package_root,
                    constraint=_dependency_constraint(requirement),
                )
            )
    elif name == "Cargo.toml":
        data = _toml(path)
        for field_name, scope in (
            ("dependencies", DependencyScope.RUNTIME),
            ("build-dependencies", DependencyScope.RUNTIME),
            ("dev-dependencies", DependencyScope.DEVELOPMENT),
        ):
            values = data.get(field_name, {})
            if not isinstance(values, dict):
                continue
            for dependency, constraint in values.items():
                if isinstance(constraint, dict):
                    raw_constraint = constraint.get("version")
                else:
                    raw_constraint = constraint
                dependencies.append(
                    DependencyInfo(
                        name=str(dependency).lower(),
                        scope=scope,
                        ecosystem="cargo",
                        source=relative,
                        package_root=package_root,
                        constraint=(
                            str(raw_constraint)
                            if raw_constraint is not None
                            else None
                        ),
                    )
                )
    elif name == "Gemfile":
        development_group = False
        for line in _safe_text(path).splitlines():
            stripped = line.strip()
            if stripped.startswith("group ") and (
                ":development" in stripped or ":test" in stripped
            ):
                development_group = True
                continue
            if development_group and stripped == "end":
                development_group = False
                continue
            match = re.match(
                r"""gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?""",
                stripped,
            )
            if match:
                dependencies.append(
                    DependencyInfo(
                        name=match.group(1).lower(),
                        scope=(
                            DependencyScope.DEVELOPMENT
                            if development_group
                            else DependencyScope.RUNTIME
                        ),
                        ecosystem="rubygems",
                        source=relative,
                        package_root=package_root,
                        constraint=match.group(2),
                    )
                )
    elif name == "pom.xml":
        try:
            root = ElementTree.fromstring(_safe_text(path))
        except ElementTree.ParseError:
            root = None
        if root is not None:
            namespace_match = re.match(r"\{([^}]+)\}", root.tag)
            prefix = (
                f"{{{namespace_match.group(1)}}}" if namespace_match else ""
            )
            for dependency in root.findall(f".//{prefix}dependency"):
                group = dependency.findtext(f"{prefix}groupId")
                artifact = dependency.findtext(f"{prefix}artifactId")
                if not group or not artifact:
                    continue
                dependency_scope = dependency.findtext(f"{prefix}scope")
                dependencies.append(
                    DependencyInfo(
                        name=f"{group}:{artifact}".lower(),
                        scope=(
                            DependencyScope.DEVELOPMENT
                            if dependency_scope == "test"
                            else DependencyScope.RUNTIME
                        ),
                        ecosystem="maven",
                        source=relative,
                        package_root=package_root,
                        constraint=dependency.findtext(f"{prefix}version"),
                    )
                )
    return tuple(
        sorted(
            dependencies,
            key=lambda item: (
                item.package_root,
                item.name,
                item.scope.value,
                item.source,
            ),
        )
    )


def _manifest_name(path: Path, fallback: str) -> str:
    if path.name == "package.json":
        value = _json(path).get("name")
        if isinstance(value, str) and value.strip():
            return value.strip()
    if path.name == "pyproject.toml":
        project = _toml(path).get("project", {})
        if isinstance(project, dict):
            value = project.get("name")
            if isinstance(value, str) and value.strip():
                return value.strip()
    if path.name == "go.mod":
        for line in _safe_text(path).splitlines():
            if line.strip().startswith("module "):
                return line.strip().split(maxsplit=1)[1].rsplit("/", 1)[-1]
    if path.name == "Cargo.toml":
        package = _toml(path).get("package", {})
        if isinstance(package, dict):
            value = package.get("name")
            if isinstance(value, str) and value.strip():
                return value.strip()
    if path.name == "pom.xml":
        try:
            root = ElementTree.fromstring(_safe_text(path))
        except ElementTree.ParseError:
            root = None
        if root is not None:
            namespace_match = re.match(r"\{([^}]+)\}", root.tag)
            prefix = (
                f"{{{namespace_match.group(1)}}}" if namespace_match else ""
            )
            value = root.findtext(f"{prefix}artifactId")
            if value and value.strip():
                return value.strip()
    return fallback


def _technology_sets(
    files: set[str], dependencies: tuple[DependencyInfo, ...]
) -> tuple[set[str], set[str], set[str], set[str]]:
    languages = {
        language
        for file_name in files
        if (language := _LANGUAGE_SUFFIXES.get(Path(file_name).suffix.lower()))
    }
    names = {Path(file_name).name for file_name in files}
    dependency_names = {dependency.name.lower() for dependency in dependencies}
    package_managers: set[str] = set()
    build_systems: set[str] = set()
    frameworks: set[str] = set()

    if "package.json" in names:
        languages.add("javascript")
        package_managers.add("npm")
        build_systems.add("npm")
    for lock_name, manager in _LOCK_FILE_MANAGERS.items():
        if lock_name in names:
            package_managers.add(manager)
    if {"pyproject.toml", "setup.py"} & names:
        package_managers.add("pip")
        build_systems.add("python")
    if any(
        name.lower().startswith("requirements")
        and name.lower().endswith((".txt", ".in"))
        for name in names
    ):
        package_managers.add("pip")
        build_systems.add("python")
    if "uv.lock" in names:
        package_managers.add("uv")
    if "go.mod" in names:
        package_managers.add("go-modules")
        build_systems.add("go")
    if "Cargo.toml" in names:
        package_managers.add("cargo")
        build_systems.add("cargo")
    if "pom.xml" in names:
        package_managers.add("maven")
        build_systems.add("maven")
    if {"build.gradle", "build.gradle.kts"} & names:
        package_managers.add("gradle")
        build_systems.add("gradle")
    if "Gemfile" in names:
        package_managers.add("bundler")
        build_systems.add("ruby")
    if "composer.json" in names:
        package_managers.add("composer")
        build_systems.add("php")
    if "Makefile" in names:
        build_systems.add("make")
    if "CMakeLists.txt" in names:
        build_systems.add("cmake")
    if {"WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel"} & names:
        build_systems.add("bazel")

    framework_dependencies = {
        "flask": "flask",
        "django": "django",
        "fastapi": "fastapi",
        "react": "react",
        "next": "nextjs",
        "express": "express",
        "@nestjs/core": "nestjs",
        "github.com/gin-gonic/gin": "gin",
        "github.com/labstack/echo": "echo",
        "github.com/gofiber/fiber": "fiber",
        "axum": "axum",
        "actix-web": "actix-web",
        "rocket": "rocket",
        "rails": "rails",
        "org.springframework.boot": "spring-boot",
        "laravel/framework": "laravel",
        "symfony/framework-bundle": "symfony",
        "vue": "vue",
        "@angular/core": "angular",
        "svelte": "svelte",
    }
    for dependency, framework in framework_dependencies.items():
        if dependency in dependency_names or any(
            name.startswith((f"{dependency}/", f"{dependency}:"))
            for name in dependency_names
        ):
            frameworks.add(framework)
    return languages, frameworks, package_managers, build_systems


@dataclass(frozen=True, slots=True)
class RepositoryContext:
    """Immutable inventory of repository technologies and scan boundaries."""

    root: Path
    files: frozenset[str] = field(default_factory=frozenset)
    languages: frozenset[str] = field(default_factory=frozenset)
    frameworks: frozenset[str] = field(default_factory=frozenset)
    package_managers: frozenset[str] = field(default_factory=frozenset)
    lock_files: tuple[str, ...] = ()
    build_systems: frozenset[str] = field(default_factory=frozenset)
    container_files: tuple[str, ...] = ()
    kubernetes_files: tuple[str, ...] = ()
    terraform_files: tuple[str, ...] = ()
    cloudformation_files: tuple[str, ...] = ()
    openapi_specifications: tuple[str, ...] = ()
    test_directories: tuple[str, ...] = ()
    generated_files: tuple[str, ...] = ()
    vendored_dependencies: tuple[str, ...] = ()
    packages: tuple[PackageContext, ...] = ()
    dependencies: tuple[DependencyInfo, ...] = ()
    exclusion_reasons: Mapping[str, str] = field(default_factory=dict)
    exclude_generated: bool = True
    exclude_vendored: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "exclusion_reasons", MappingProxyType(dict(self.exclusion_reasons))
        )

    @classmethod
    def from_path(
        cls,
        root: Path,
        *,
        exclude_generated: bool = True,
        exclude_vendored: bool = True,
    ) -> RepositoryContext:
        resolved_root = root.resolve()
        all_files: set[str] = set()
        vendored: set[str] = set()
        exclusion_reasons: dict[str, str] = {}

        for current, directories, names in os.walk(resolved_root):
            current_path = Path(current)
            directories[:] = sorted(
                directory
                for directory in directories
                if directory not in _ALWAYS_IGNORED_DIRECTORIES
            )
            for directory in list(directories):
                if directory not in _VENDORED_DIRECTORIES:
                    continue
                vendor_path = current_path / directory
                relative_vendor = _relative(vendor_path, resolved_root)
                vendored.add(relative_vendor)
                if exclude_vendored:
                    exclusion_reasons[relative_vendor] = (
                        "vendored dependency directory"
                    )
                    directories.remove(directory)
            for name in sorted(names):
                path = current_path / name
                if not path.is_file():
                    continue
                relative_name = _relative(path, resolved_root)
                all_files.add(relative_name)

        generated = {file_name for file_name in all_files if _is_generated(file_name)}
        scannable = set(all_files)
        if exclude_generated:
            scannable.difference_update(generated)
            for file_name in generated:
                exclusion_reasons[file_name] = "generated file"

        lock_files = tuple(
            sorted(
                file_name
                for file_name in all_files
                if Path(file_name).name in _LOCK_FILE_MANAGERS
            )
        )
        container_files = tuple(
            sorted(
                file_name
                for file_name in scannable
                if Path(file_name).name.startswith("Dockerfile")
                or Path(file_name).name
                in {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"}
            )
        )
        terraform_files = tuple(
            sorted(
                file_name
                for file_name in scannable
                if file_name.endswith((".tf", ".tf.json"))
            )
        )
        kubernetes_files: list[str] = []
        cloudformation_files: list[str] = []
        openapi_specifications: list[str] = []
        for file_name in sorted(scannable):
            suffix = Path(file_name).suffix.lower()
            if suffix not in {".yaml", ".yml", ".json"}:
                continue
            text = _safe_text(resolved_root / file_name)
            if "apiVersion:" in text and re.search(r"(?m)^kind:\s*\S+", text):
                kubernetes_files.append(file_name)
            if (
                "AWSTemplateFormatVersion" in text
                or ("Resources:" in text and "AWS::" in text)
            ):
                cloudformation_files.append(file_name)
            if re.search(r'(?m)^\s*(openapi|swagger)\s*:', text) or re.search(
                r'"(openapi|swagger)"\s*:', text
            ):
                openapi_specifications.append(file_name)

        test_directories = tuple(
            sorted(
                {
                    Path(*Path(file_name).parts[: index + 1]).as_posix()
                    for file_name in scannable
                    for index, part in enumerate(Path(file_name).parts[:-1])
                    if part.lower() in _TEST_DIRECTORIES
                }
            )
        )
        manifest_files = sorted(
            file_name
            for file_name in scannable
            if _is_package_manifest(file_name)
        )
        manifests_by_root: dict[str, list[str]] = {}
        for manifest in manifest_files:
            parent = Path(manifest).parent.as_posix()
            package_root = "." if parent == "." else parent
            manifests_by_root.setdefault(package_root, []).append(manifest)

        dependencies: list[DependencyInfo] = []
        for package_root, manifests in sorted(manifests_by_root.items()):
            for manifest in manifests:
                dependencies.extend(
                    _manifest_dependencies(
                        resolved_root / manifest, manifest, package_root
                    )
                )
        dependency_tuple = tuple(
            sorted(
                dependencies,
                key=lambda item: (
                    item.package_root,
                    item.name,
                    item.scope.value,
                    item.source,
                ),
            )
        )
        (
            languages,
            frameworks,
            repository_package_managers,
            build_systems,
        ) = _technology_sets(
            scannable, dependency_tuple
        )

        package_roots = sorted(
            manifests_by_root, key=lambda value: (value != ".", value)
        )
        packages: list[PackageContext] = []
        for package_root in package_roots:
            prefix = "" if package_root == "." else f"{package_root}/"
            child_prefixes = tuple(
                f"{candidate}/"
                for candidate in package_roots
                if candidate != package_root
                and candidate != "."
                and (
                    package_root == "."
                    or candidate.startswith(f"{package_root}/")
                )
            )
            package_files = {
                file_name
                for file_name in scannable
                if file_name.startswith(prefix)
                and not any(file_name.startswith(child) for child in child_prefixes)
            }
            package_dependencies = tuple(
                dependency
                for dependency in dependency_tuple
                if dependency.package_root == package_root
            )
            (
                package_languages,
                package_frameworks,
                package_manager_set,
                package_build_systems,
            ) = _technology_sets(package_files, package_dependencies)
            primary_manifest = resolved_root / manifests_by_root[package_root][0]
            fallback = (
                resolved_root.name
                if package_root == "."
                else Path(package_root).name
            )
            packages.append(
                PackageContext(
                    name=_manifest_name(primary_manifest, fallback),
                    root=package_root,
                    manifests=tuple(sorted(manifests_by_root[package_root])),
                    files=frozenset(package_files),
                    languages=frozenset(package_languages),
                    frameworks=frozenset(package_frameworks),
                    package_managers=frozenset(package_manager_set),
                    build_systems=frozenset(package_build_systems),
                    dependencies=package_dependencies,
                )
            )

        return cls(
            root=resolved_root,
            files=frozenset(scannable),
            languages=frozenset(languages),
            frameworks=frozenset(frameworks),
            package_managers=frozenset(repository_package_managers),
            lock_files=lock_files,
            build_systems=frozenset(build_systems),
            container_files=container_files,
            kubernetes_files=tuple(kubernetes_files),
            terraform_files=terraform_files,
            cloudformation_files=tuple(cloudformation_files),
            openapi_specifications=tuple(openapi_specifications),
            test_directories=test_directories,
            generated_files=tuple(sorted(generated)),
            vendored_dependencies=tuple(sorted(vendored)),
            packages=tuple(packages),
            dependencies=dependency_tuple,
            exclusion_reasons=exclusion_reasons,
            exclude_generated=exclude_generated,
            exclude_vendored=exclude_vendored,
        )

    def matches(self, patterns: tuple[str, ...]) -> bool:
        """Return whether any scannable path matches a supported-file glob."""

        return any(
            fnmatch(path, pattern) or fnmatch(Path(path).name, pattern)
            for path in self.files
            for pattern in patterns
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic JSON-compatible representation."""

        return {
            "root": str(self.root),
            "files": sorted(self.files),
            "languages": sorted(self.languages),
            "frameworks": sorted(self.frameworks),
            "package_managers": sorted(self.package_managers),
            "lock_files": list(self.lock_files),
            "build_systems": sorted(self.build_systems),
            "container_files": list(self.container_files),
            "kubernetes_files": list(self.kubernetes_files),
            "terraform_files": list(self.terraform_files),
            "cloudformation_files": list(self.cloudformation_files),
            "openapi_specifications": list(self.openapi_specifications),
            "test_directories": list(self.test_directories),
            "generated_files": list(self.generated_files),
            "vendored_dependencies": list(self.vendored_dependencies),
            "packages": [package.to_dict() for package in self.packages],
            "dependencies": [
                dependency.to_dict() for dependency in self.dependencies
            ],
            "exclusion_reasons": dict(sorted(self.exclusion_reasons.items())),
            "exclude_generated": self.exclude_generated,
            "exclude_vendored": self.exclude_vendored,
        }


__all__ = [
    "DependencyInfo",
    "DependencyScope",
    "PackageContext",
    "RepositoryContext",
]
