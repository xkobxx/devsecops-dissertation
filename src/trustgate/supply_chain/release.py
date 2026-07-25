"""Build and sign deterministic Trust Gate release artifacts."""

from __future__ import annotations

import ast
from collections.abc import Iterable, Sequence
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import uuid


SEMANTIC_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
LOCKED_REQUIREMENT = re.compile(
    r"^([A-Za-z0-9_.-]+)==([^=<>!~;\s]+)(?:\s*\\)?$"
)


class ReleaseError(RuntimeError):
    """Raised when release inputs or generated artifacts are unsafe."""


def _git(repository: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", "") or str(error)
        raise ReleaseError(f"git {' '.join(arguments)} failed: {detail.strip()}") from error
    return result.stdout.strip()


def _package_version(init_source: str) -> str:
    try:
        module = ast.parse(init_source)
    except SyntaxError as error:
        raise ReleaseError("trustgate __init__.py is not valid Python") from error

    for statement in module.body:
        if not isinstance(statement, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in statement.targets
        ):
            continue
        if isinstance(statement.value, ast.Constant) and isinstance(
            statement.value.value, str
        ):
            return statement.value.value
    raise ReleaseError("trustgate __init__.py does not define a string __version__")


def _version_at_ref(repository: Path, commit: str) -> str:
    try:
        pyproject = tomllib.loads(_git(repository, "show", f"{commit}:pyproject.toml"))
        project_version = pyproject["project"]["version"]
    except (KeyError, tomllib.TOMLDecodeError) as error:
        raise ReleaseError("pyproject.toml does not define project.version") from error

    package_version = _package_version(
        _git(repository, "show", f"{commit}:src/trustgate/__init__.py")
    )
    if project_version != package_version:
        raise ReleaseError(
            "release version mismatch: pyproject.toml has "
            f"{project_version!r}, package has {package_version!r}"
        )
    if not isinstance(project_version, str) or not SEMANTIC_VERSION.fullmatch(
        project_version
    ):
        raise ReleaseError(f"release version is not semantic: {project_version!r}")
    return project_version


def _release_identity(
    repository: Path,
    ref: str,
    expected_tag: str | None,
) -> tuple[str, str, str]:
    commit = _git(repository, "rev-parse", "--verify", f"{ref}^{{commit}}")
    version = _version_at_ref(repository, commit)
    release_tag = f"v{version}"
    if expected_tag is not None and expected_tag != release_tag:
        raise ReleaseError(
            f"release tag {expected_tag} does not match package version {version}"
        )
    if expected_tag is not None:
        tag_commit = _git(
            repository,
            "rev-parse",
            "--verify",
            f"{expected_tag}^{{commit}}",
        )
        if tag_commit != commit:
            raise ReleaseError(
                f"release tag {expected_tag} does not point to commit {commit}"
            )
    return commit, version, release_tag


def _ensure_new_artifact(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise ReleaseError(f"refusing to overwrite release artifact: {path}")


def build_release_archives(
    *,
    repository: Path,
    output_directory: Path,
    ref: str,
    expected_tag: str | None = None,
) -> list[Path]:
    """Create reproducible tar.gz and zip archives from one Git commit."""

    repository = repository.resolve()
    if not (repository / ".git").exists():
        raise ReleaseError(f"not a Git repository: {repository}")

    commit, version, _ = _release_identity(repository, ref, expected_tag)

    output_directory = output_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    prefix = f"trustgate-{version}/"
    artifacts = [
        output_directory / f"trustgate-{version}.tar.gz",
        output_directory / f"trustgate-{version}.zip",
    ]
    for artifact in artifacts:
        _ensure_new_artifact(artifact)

    formats = (("tar.gz", artifacts[0]), ("zip", artifacts[1]))
    for archive_format, artifact in formats:
        try:
            subprocess.run(
                [
                    "git",
                    "archive",
                    f"--format={archive_format}",
                    f"--prefix={prefix}",
                    f"--output={artifact}",
                    commit,
                ],
                cwd=repository,
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            detail = getattr(error, "stderr", "") or str(error)
            raise ReleaseError(
                f"could not build {archive_format} release archive: {detail.strip()}"
            ) from error
        if not artifact.is_file() or artifact.stat().st_size == 0:
            raise ReleaseError(f"release archive was not created: {artifact}")

    return artifacts


def _normalise_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _locked_requirements(source: str, *, label: str) -> dict[str, str]:
    requirements: dict[str, str] = {}
    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        requirement = raw_line.split("#", 1)[0].strip()
        if not requirement or requirement.startswith("--hash="):
            continue
        match = LOCKED_REQUIREMENT.fullmatch(requirement)
        if not match:
            raise ReleaseError(
                f"{label}:{line_number} is not an exact requirement: {requirement}"
            )
        name, version = match.groups()
        normalised = _normalise_package_name(name)
        previous = requirements.get(normalised)
        if previous is not None and previous != version:
            raise ReleaseError(f"{label} contains conflicting versions for {name}")
        requirements[normalised] = version
    if not requirements:
        raise ReleaseError(f"{label} contains no locked dependencies")
    return requirements


def _component(name: str, version: str) -> dict[str, str]:
    purl = f"pkg:pypi/{name}@{version}"
    return {
        "type": "library",
        "bom-ref": purl,
        "name": name,
        "version": version,
        "purl": purl,
    }


def generate_cyclonedx_sbom(
    *,
    repository: Path,
    output: Path,
    ref: str,
    expected_tag: str,
) -> Path:
    """Generate a deterministic CycloneDX inventory from the tagged lockfile."""

    repository = repository.resolve()
    if not (repository / ".git").exists():
        raise ReleaseError(f"not a Git repository: {repository}")
    commit, version, release_tag = _release_identity(
        repository,
        ref,
        expected_tag,
    )
    locked = _locked_requirements(
        _git(repository, "show", f"{commit}:requirements/runtime.lock"),
        label="requirements/runtime.lock",
    )
    direct = _locked_requirements(
        _git(repository, "show", f"{commit}:requirements/runtime.in"),
        label="requirements/runtime.in",
    )
    for name, direct_version in direct.items():
        locked_version = locked.get(name)
        if locked_version is None:
            raise ReleaseError(
                f"direct dependency {name} is missing from runtime.lock"
            )
        if locked_version != direct_version:
            raise ReleaseError(
                f"direct dependency {name} is {direct_version} in runtime.in "
                f"but {locked_version} in runtime.lock"
            )

    root_ref = f"pkg:pypi/trustgate@{version}"
    components = [
        _component(name, dependency_version)
        for name, dependency_version in sorted(locked.items())
    ]
    timestamp = _git(repository, "show", "-s", "--format=%cI", commit)
    serial = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"https://github.com/xkobxx/devsecops-dissertation@{commit}",
    )
    sbom = {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "trustgate",
                "version": version,
                "purl": root_ref,
                "licenses": [{"license": {"id": "MIT"}}],
                "externalReferences": [
                    {
                        "type": "vcs",
                        "url": (
                            "https://github.com/xkobxx/"
                            f"devsecops-dissertation/tree/{commit}"
                        ),
                    }
                ],
            },
            "properties": [
                {"name": "trustgate:git:commit", "value": commit},
                {"name": "trustgate:git:tag", "value": release_tag},
                {
                    "name": "trustgate:dependency-source",
                    "value": "requirements/runtime.lock",
                },
            ],
        },
        "components": components,
        "dependencies": [
            {
                "ref": root_ref,
                "dependsOn": [
                    f"pkg:pypi/{name}@{direct[name]}" for name in sorted(direct)
                ],
            },
            *[
                {"ref": component["bom-ref"], "dependsOn": []}
                for component in components
            ],
        ],
    }

    if output.is_symlink():
        raise ReleaseError(f"refusing to overwrite release artifact: {output}")
    output = output.resolve()
    _ensure_new_artifact(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=output.parent,
        prefix=f".{output.name}.",
        delete=False,
    ) as temporary:
        json.dump(sbom, temporary, indent=2, sort_keys=True)
        temporary.write("\n")
        temporary_path = Path(temporary.name)
    temporary_path.replace(output)
    return output


def _checked_artifacts(artifacts: Iterable[Path]) -> list[Path]:
    checked: list[Path] = []
    names: set[str] = set()
    for artifact in artifacts:
        if artifact.is_symlink():
            raise ReleaseError(f"release artifact is not a regular file: {artifact}")
        artifact = artifact.resolve()
        if not artifact.is_file():
            raise ReleaseError(f"release artifact is not a regular file: {artifact}")
        if artifact.name in names:
            raise ReleaseError(f"duplicate release artifact name: {artifact.name}")
        names.add(artifact.name)
        checked.append(artifact)
    if not checked:
        raise ReleaseError("at least one release artifact is required")
    return checked


def generate_checksums(artifacts: Iterable[Path], manifest: Path) -> Path:
    """Write a deterministic SHA-256 manifest for the supplied artifacts."""

    checked = sorted(_checked_artifacts(artifacts), key=lambda path: path.name)
    manifest = manifest.resolve()
    if manifest.name in {artifact.name for artifact in checked}:
        raise ReleaseError("checksum manifest cannot checksum itself")
    _ensure_new_artifact(manifest)
    manifest.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    for artifact in checked:
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        lines.append(f"{digest}  {artifact.name}\n")

    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=manifest.parent,
        prefix=f".{manifest.name}.",
        delete=False,
    ) as temporary:
        temporary.writelines(lines)
        temporary_path = Path(temporary.name)
    temporary_path.replace(manifest)
    return manifest


def sign_release_artifacts(
    artifacts: Sequence[Path],
    *,
    cosign: str = "cosign",
) -> list[Path]:
    """Create one keyless Sigstore bundle beside every release artifact."""

    checked = _checked_artifacts(artifacts)
    bundles: list[Path] = []
    for artifact in checked:
        bundle = artifact.with_name(f"{artifact.name}.sigstore.json")
        _ensure_new_artifact(bundle)
        try:
            subprocess.run(
                [
                    cosign,
                    "sign-blob",
                    "--yes",
                    "--bundle",
                    str(bundle),
                    str(artifact),
                ],
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise ReleaseError(f"could not sign release artifact: {artifact}") from error
        if not bundle.is_file() or bundle.stat().st_size == 0:
            raise ReleaseError(f"cosign did not create a signature bundle: {bundle}")
        bundles.append(bundle)
    return bundles


__all__ = [
    "ReleaseError",
    "build_release_archives",
    "generate_cyclonedx_sbom",
    "generate_checksums",
    "sign_release_artifacts",
]
