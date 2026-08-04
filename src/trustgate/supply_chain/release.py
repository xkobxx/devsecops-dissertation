"""Build and sign deterministic Trust Gate release artifacts."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import tempfile
import tomllib
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

SEMANTIC_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
LOCKED_REQUIREMENT = re.compile(r"^([A-Za-z0-9_.-]+)==([^=<>!~;\s]+)(?:\s*\\)?$")
LOCKED_HASH = re.compile(r"^--hash=sha256:([0-9a-f]{64})(?:\s*\\)?$")


class ReleaseError(RuntimeError):
    """Raised when release inputs or generated artifacts are unsafe."""


@dataclass(frozen=True, slots=True)
class _LockedPackage:
    name: str
    version: str
    hashes: tuple[str, ...]
    parents: tuple[str, ...]


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
        raise ReleaseError(
            f"git {' '.join(arguments)} failed: {detail.strip()}"
        ) from error
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


def _locked_packages(source: str, *, label: str) -> dict[str, _LockedPackage]:
    packages: dict[str, _LockedPackage] = {}
    current_name: str | None = None
    current_version = ""
    current_hashes: set[str] = set()
    current_parents: set[str] = set()
    in_via_block = False

    def finish() -> None:
        nonlocal current_name, current_version, current_hashes, current_parents
        if current_name is None:
            return
        if not current_hashes:
            raise ReleaseError(
                f"{label} dependency {current_name} has no SHA-256 hashes"
            )
        if current_name in packages:
            raise ReleaseError(f"{label} contains duplicate dependency {current_name}")
        packages[current_name] = _LockedPackage(
            name=current_name,
            version=current_version,
            hashes=tuple(sorted(current_hashes)),
            parents=tuple(sorted(current_parents)),
        )
        current_name = None
        current_version = ""
        current_hashes = set()
        current_parents = set()

    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        stripped = raw_line.strip()
        requirement = LOCKED_REQUIREMENT.fullmatch(stripped)
        if requirement is not None:
            finish()
            name, current_version = requirement.groups()
            current_name = _normalise_package_name(name)
            in_via_block = False
            continue
        if current_name is None:
            continue
        digest = LOCKED_HASH.fullmatch(stripped)
        if digest is not None:
            current_hashes.add(digest.group(1))
            in_via_block = False
            continue
        if stripped.startswith("# via"):
            parent = stripped.removeprefix("# via").strip()
            if parent and not parent.startswith("-r "):
                current_parents.add(_normalise_package_name(parent))
            in_via_block = True
            continue
        if in_via_block and stripped.startswith("#"):
            parent = stripped.removeprefix("#").strip()
            if parent and not parent.startswith("-r "):
                current_parents.add(_normalise_package_name(parent))
            continue
        if stripped and not stripped.startswith("#"):
            raise ReleaseError(
                f"{label}:{line_number} is not locked dependency metadata: {stripped}"
            )
    finish()
    if not packages:
        raise ReleaseError(f"{label} contains no locked dependencies")
    unknown_parents = sorted(
        {
            parent
            for package in packages.values()
            for parent in package.parents
            if parent not in packages
        }
    )
    if unknown_parents:
        raise ReleaseError(
            f"{label} references missing parent dependencies: "
            + ", ".join(unknown_parents)
        )
    return packages


def _license_inventory(
    source: str,
    packages: dict[str, _LockedPackage],
    *,
    label: str,
) -> dict[str, str]:
    try:
        document = json.loads(source)
    except json.JSONDecodeError as error:
        raise ReleaseError(f"{label} is not valid JSON") from error
    if not isinstance(document, dict) or document.get("schema_version") != "1.0.0":
        raise ReleaseError(f"{label} must use schema_version 1.0.0")
    entries = document.get("packages")
    if not isinstance(entries, dict):
        raise ReleaseError(f"{label} packages must be an object")
    licenses: dict[str, str] = {}
    for raw_name, entry in entries.items():
        name = _normalise_package_name(str(raw_name))
        if not isinstance(entry, dict):
            raise ReleaseError(f"{label} entry for {name} must be an object")
        package = packages.get(name)
        if package is None:
            raise ReleaseError(
                f"{label} contains dependency not present in lock: {name}"
            )
        if entry.get("version") != package.version:
            raise ReleaseError(f"{label} version does not match lock for {name}")
        expression = entry.get("license")
        if (
            not isinstance(expression, str)
            or not expression.strip()
            or any(ord(character) < 32 for character in expression)
        ):
            raise ReleaseError(f"{label} has no valid licence for {name}")
        licenses[name] = expression.strip()
    missing = sorted(set(packages) - set(licenses))
    if missing:
        raise ReleaseError(
            f"{label} is missing dependency licences: " + ", ".join(missing)
        )
    return licenses


def _component(
    package: _LockedPackage,
    *,
    direct: bool,
    license_expression: str,
) -> dict[str, object]:
    purl = f"pkg:pypi/{package.name}@{package.version}"
    return {
        "type": "library",
        "bom-ref": purl,
        "name": package.name,
        "version": package.version,
        "purl": purl,
        "licenses": [{"expression": license_expression}],
        "hashes": [{"alg": "SHA-256", "content": digest} for digest in package.hashes],
        "properties": [
            {
                "name": "trustgate:dependency:type",
                "value": "direct" if direct else "transitive",
            }
        ],
    }


@dataclass(frozen=True, slots=True)
class _SbomContext:
    commit: str
    version: str
    release_tag: str
    timestamp: str
    locked: dict[str, _LockedPackage]
    direct: dict[str, str]
    licenses: dict[str, str]


def _sbom_context(
    *,
    repository: Path,
    ref: str,
    expected_tag: str | None,
) -> _SbomContext:
    repository = repository.resolve()
    if not (repository / ".git").exists():
        raise ReleaseError(f"not a Git repository: {repository}")
    commit, version, release_tag = _release_identity(
        repository,
        ref,
        expected_tag,
    )
    locked = _locked_packages(
        _git(repository, "show", f"{commit}:requirements/runtime.lock"),
        label="requirements/runtime.lock",
    )
    direct = _locked_requirements(
        _git(repository, "show", f"{commit}:requirements/runtime.in"),
        label="requirements/runtime.in",
    )
    for name, direct_version in direct.items():
        locked_package = locked.get(name)
        if locked_package is None:
            raise ReleaseError(f"direct dependency {name} is missing from runtime.lock")
        if locked_package.version != direct_version:
            raise ReleaseError(
                f"direct dependency {name} is {direct_version} in runtime.in "
                f"but {locked_package.version} in runtime.lock"
            )
    licenses = _license_inventory(
        _git(repository, "show", f"{commit}:requirements/runtime.licenses.json"),
        locked,
        label="requirements/runtime.licenses.json",
    )
    return _SbomContext(
        commit=commit,
        version=version,
        release_tag=release_tag,
        timestamp=_git(repository, "show", "-s", "--format=%cI", commit),
        locked=locked,
        direct=direct,
        licenses=licenses,
    )


def _write_json_artifact(document: dict[str, object], output: Path) -> Path:
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
        json.dump(document, temporary, indent=2, sort_keys=True)
        temporary.write("\n")
        temporary_path = Path(temporary.name)
    temporary_path.replace(output)
    return output


def generate_cyclonedx_sbom(
    *,
    repository: Path,
    output: Path,
    ref: str,
    expected_tag: str | None = None,
) -> Path:
    """Generate a deterministic CycloneDX inventory from the tagged lockfile."""

    repository = repository.resolve()
    context = _sbom_context(repository=repository, ref=ref, expected_tag=expected_tag)

    root_ref = f"pkg:pypi/trustgate@{context.version}"
    components = [
        _component(
            package,
            direct=name in context.direct,
            license_expression=context.licenses[name],
        )
        for name, package in sorted(context.locked.items())
    ]
    serial = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"https://github.com/xkobxx/devsecops-dissertation@{context.commit}",
    )
    sbom = {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": context.timestamp,
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "trustgate",
                "version": context.version,
                "purl": root_ref,
                "licenses": [{"license": {"id": "MIT"}}],
                "externalReferences": [
                    {
                        "type": "vcs",
                        "url": (
                            "https://github.com/xkobxx/"
                            f"devsecops-dissertation/tree/{context.commit}"
                        ),
                    }
                ],
            },
            "properties": [
                {"name": "trustgate:git:commit", "value": context.commit},
                {"name": "trustgate:git:tag", "value": context.release_tag},
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
                    f"pkg:pypi/{name}@{context.direct[name]}"
                    for name in sorted(context.direct)
                ],
            },
            *[
                {
                    "ref": component["bom-ref"],
                    "dependsOn": [
                        f"pkg:pypi/{child.name}@{child.version}"
                        for child in sorted(
                            (
                                candidate
                                for candidate in context.locked.values()
                                if component["name"] in candidate.parents
                            ),
                            key=lambda candidate: candidate.name,
                        )
                    ],
                }
                for component in components
            ],
        ],
    }

    return _write_json_artifact(sbom, output)


def _spdx_package_id(name: str) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9.-]+", "-", name).strip("-.")
    return f"SPDXRef-Package-{safe_name}"


def generate_spdx_sbom(
    *,
    repository: Path,
    output: Path,
    ref: str,
    expected_tag: str | None = None,
) -> Path:
    """Generate a deterministic SPDX 2.3 inventory from the tagged lockfile."""

    context = _sbom_context(
        repository=repository.resolve(), ref=ref, expected_tag=expected_tag
    )
    root_id = _spdx_package_id("trustgate")
    package_ids = {name: _spdx_package_id(name) for name in sorted(context.locked)}
    created = (
        datetime.fromisoformat(context.timestamp)
        .astimezone(UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    namespace_id = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"https://github.com/xkobxx/devsecops-dissertation/spdx/{context.commit}",
    )
    packages: list[dict[str, object]] = [
        {
            "SPDXID": root_id,
            "name": "trustgate",
            "versionInfo": context.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "MIT",
            "licenseDeclared": "MIT",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:pypi/trustgate@{context.version}",
                }
            ],
        }
    ]
    for name, package in sorted(context.locked.items()):
        license_expression = context.licenses[name]
        packages.append(
            {
                "SPDXID": package_ids[name],
                "name": name,
                "versionInfo": package.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": license_expression,
                "licenseDeclared": license_expression,
                "copyrightText": "NOASSERTION",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": digest}
                    for digest in package.hashes
                ],
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:pypi/{name}@{package.version}",
                    }
                ],
                "comment": (
                    "Trust Gate dependency type: "
                    + ("direct" if name in context.direct else "transitive")
                ),
            }
        )

    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        },
        *[
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_ids[name],
            }
            for name in sorted(context.direct)
        ],
    ]
    for child_name, package in sorted(context.locked.items()):
        for parent_name in package.parents:
            relationships.append(
                {
                    "spdxElementId": package_ids[parent_name],
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": package_ids[child_name],
                }
            )
    relationships[1:] = sorted(
        relationships[1:],
        key=lambda relationship: (
            relationship["spdxElementId"],
            relationship["relatedSpdxElement"],
        ),
    )
    document: dict[str, object] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"trustgate-{context.release_tag}",
        "documentNamespace": (
            f"https://spdx.org/spdxdocs/trustgate-{context.release_tag}-{namespace_id}"
        ),
        "creationInfo": {
            "created": created,
            "creators": [f"Tool: TrustGate-{context.version}"],
        },
        "documentDescribes": [root_id],
        "packages": packages,
        "relationships": relationships,
        "annotations": [
            {
                "annotationDate": created,
                "annotationType": "OTHER",
                "annotator": f"Tool: TrustGate-{context.version}",
                "comment": (
                    f"Git commit {context.commit}; release tag "
                    f"{context.release_tag}; dependency source "
                    "requirements/runtime.lock"
                ),
            }
        ],
    }
    return _write_json_artifact(document, output)


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
            raise ReleaseError(
                f"could not sign release artifact: {artifact}"
            ) from error
        if not bundle.is_file() or bundle.stat().st_size == 0:
            raise ReleaseError(f"cosign did not create a signature bundle: {bundle}")
        bundles.append(bundle)
    return bundles


__all__ = [
    "ReleaseError",
    "build_release_archives",
    "generate_checksums",
    "generate_cyclonedx_sbom",
    "generate_spdx_sbom",
    "sign_release_artifacts",
]
