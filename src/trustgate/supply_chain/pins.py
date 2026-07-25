"""Validate immutable dependency references used by repository automation."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import tomllib
from collections.abc import Iterable

ACTION_PATTERN = re.compile(r"\buses:\s*([^\s#]+)(?:\s+#\s*(\S+))?")
ACTION_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
CONTAINER_DIGEST_PATTERN = re.compile(r"@sha256:[0-9a-f]{64}$")
COMPOSE_IMAGE_PATTERN = re.compile(r"^\s*image:\s*([^\s#]+)")
DOCKER_RUN_IMAGE_PATTERN = re.compile(
    r"\b((?:[a-z0-9.-]+(?::[0-9]+)?/)?"
    r"[a-z0-9._-]+/[a-z0-9._/-]+"
    r"(?::[A-Za-z0-9._-]+)?"
    r"(?:@sha256:[0-9a-f]{64})?)\b"
)
EXACT_REQUIREMENT_PATTERN = re.compile(
    r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^=<>!~;\s]+"
    r"(?:\s*;\s*.+)?$"
)
LOCK_REQUIREMENT_PATTERN = re.compile(
    r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==\S+\s*\\?$"
)


def _automation_files(root: Path) -> Iterable[Path]:
    action = root / "action.yml"
    if action.is_file():
        yield action

    workflows = root / ".github" / "workflows"
    if workflows.is_dir():
        yield from (
            path
            for path in sorted(workflows.glob("*.yml"))
            if not path.name.startswith("._")
        )
        yield from (
            path
            for path in sorted(workflows.glob("*.yaml"))
            if not path.name.startswith("._")
        )

    compose = root / "docker-compose.yml"
    if compose.is_file():
        yield compose


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _logical_lines(path: Path) -> Iterable[tuple[int, str]]:
    start_line = 1
    pending = ""

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = raw_line.rstrip()
        if not pending:
            start_line = line_number
        pending += stripped[:-1].rstrip() + " " if stripped.endswith("\\") else stripped
        if not stripped.endswith("\\"):
            yield start_line, pending
            pending = ""

    if pending:
        yield start_line, pending


def _validate_exact_requirement(
    requirement: str,
    *,
    location: str,
    errors: list[str],
) -> None:
    if not EXACT_REQUIREMENT_PATTERN.fullmatch(requirement):
        errors.append(
            f"{location}: Python dependency is not pinned to an exact version: "
            f"{requirement}"
        )


def _validate_python_dependencies(root: Path, errors: list[str]) -> None:
    requirements_directory = root / "requirements"
    if requirements_directory.is_dir():
        for path in sorted(requirements_directory.glob("*.in")):
            if path.name.startswith("._"):
                continue
            display_path = _display_path(path, root)
            for line_number, raw_line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                requirement = raw_line.split("#", 1)[0].strip()
                if not requirement:
                    continue
                _validate_exact_requirement(
                    requirement,
                    location=f"{display_path}:{line_number}",
                    errors=errors,
                )

        for path in sorted(requirements_directory.glob("*.lock")):
            if path.name.startswith("._"):
                continue
            display_path = _display_path(path, root)
            current: tuple[int, str] | None = None
            has_hash = False
            for line_number, raw_line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                stripped = raw_line.strip()
                if LOCK_REQUIREMENT_PATTERN.fullmatch(stripped):
                    if current and not has_hash:
                        errors.append(
                            f"{display_path}:{current[0]}: locked dependency is "
                            f"missing hashes: {current[1]}"
                        )
                    current = (line_number, stripped.removesuffix("\\").rstrip())
                    has_hash = False
                elif current and "--hash=sha256:" in stripped:
                    has_hash = True
            if current and not has_hash:
                errors.append(
                    f"{display_path}:{current[0]}: locked dependency is "
                    f"missing hashes: {current[1]}"
                )

    pyproject_path = root / "pyproject.toml"
    if pyproject_path.is_file():
        with pyproject_path.open("rb") as stream:
            pyproject = tomllib.load(stream)
        build_requirements = pyproject.get("build-system", {}).get("requires", [])
        project = pyproject.get("project", {})
        project_requirements = project.get("dependencies", [])
        optional_groups = project.get("optional-dependencies", {})

        for requirement in build_requirements:
            _validate_exact_requirement(
                requirement,
                location="pyproject.toml:[build-system].requires",
                errors=errors,
            )
        for requirement in project_requirements:
            _validate_exact_requirement(
                requirement,
                location="pyproject.toml:[project].dependencies",
                errors=errors,
            )
        for group, requirements in optional_groups.items():
            for requirement in requirements:
                _validate_exact_requirement(
                    requirement,
                    location=(
                        "pyproject.toml:[project.optional-dependencies]."
                        f"{group}"
                    ),
                    errors=errors,
                )


def validate_repository(root: Path) -> list[str]:
    """Return errors for floating Actions and container image references."""

    root = root.resolve()
    errors: list[str] = []

    for path in _automation_files(root):
        display_path = _display_path(path, root)
        for line_number, line in _logical_lines(path):
            if line.lstrip().startswith("#"):
                continue

            action_match = ACTION_PATTERN.search(line)
            if action_match:
                reference, version_comment = action_match.groups()
                if reference.startswith(("./", "../", "docker://")):
                    continue
                _, separator, revision = reference.rpartition("@")
                if not separator or not ACTION_SHA_PATTERN.fullmatch(revision):
                    errors.append(
                        f"{display_path}:{line_number}: Action is not pinned "
                        f"to a commit SHA: {reference}"
                    )
                elif not version_comment:
                    errors.append(
                        f"{display_path}:{line_number}: pinned Action is missing "
                        f"a human-readable version comment: {reference}"
                    )

            image_match = COMPOSE_IMAGE_PATTERN.search(line)
            if image_match:
                reference = image_match.group(1)
                if not CONTAINER_DIGEST_PATTERN.search(reference):
                    errors.append(
                        f"{display_path}:{line_number}: container is not pinned "
                        f"to a digest: {reference}"
                    )

            if "docker run" in line:
                docker_arguments = line.split("docker run", 1)[1]
                candidates = DOCKER_RUN_IMAGE_PATTERN.findall(docker_arguments)
                if candidates:
                    reference = candidates[0]
                    if not CONTAINER_DIGEST_PATTERN.search(reference):
                        errors.append(
                            f"{display_path}:{line_number}: container is not pinned "
                            f"to a digest: {reference}"
                        )

    _validate_python_dependencies(root, errors)
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate immutable Action and container references."
    )
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path.cwd(),
        help="Repository root (default: current directory)",
    )
    args = parser.parse_args(argv)

    errors = validate_repository(args.root)
    if errors:
        for error in errors:
            print(error)
        return 1

    print("Dependency references are immutable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
