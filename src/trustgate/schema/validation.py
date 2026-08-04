"""Load and enforce Trust Gate's versioned JSON Schema contracts."""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path
import sysconfig
import tempfile
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


CURRENT_SCHEMA_VERSION = "1.0.0"
SCHEMA_NAMES = (
    "baseline",
    "baseline-diff",
    "baseline-gate",
    "decision",
    "finding",
    "scan-run",
    "suppression",
    "policy",
    "policy-result",
)


class SchemaVersionError(ValueError):
    """Raised when a schema name or version is not registered."""


class SchemaValidationError(ValueError):
    """Raised when a document does not satisfy its registered schema."""

    def __init__(
        self,
        schema_name: str,
        errors: tuple[str, ...],
    ) -> None:
        self.schema_name = schema_name
        self.errors = errors
        details = "; ".join(errors)
        super().__init__(f"{schema_name} validation failed: {details}")


def _schema_directory() -> Path:
    source_directory = Path(__file__).resolve().parents[3] / "schemas"
    installed_directory = (
        Path(sysconfig.get_path("data")) / "share" / "trustgate" / "schemas"
    )
    for candidate in (source_directory, installed_directory):
        if (candidate / "registry.json").is_file():
            return candidate
    raise SchemaVersionError(
        "Trust Gate schema registry was not found in the source tree or installation"
    )


@lru_cache(maxsize=1)
def _manifest() -> dict[str, Any]:
    path = _schema_directory() / "registry.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SchemaVersionError(f"could not load schema registry: {error}") from error

    if not isinstance(manifest, dict):
        raise SchemaVersionError("schema registry root must be an object")
    if manifest.get("registry_version") != CURRENT_SCHEMA_VERSION:
        raise SchemaVersionError(
            "schema registry version does not match the runtime version"
        )
    if manifest.get("current_version") != CURRENT_SCHEMA_VERSION:
        raise SchemaVersionError(
            "schema registry current_version does not match the runtime version"
        )
    schemas = manifest.get("schemas")
    if not isinstance(schemas, dict) or set(schemas) != set(SCHEMA_NAMES):
        raise SchemaVersionError(
            "schema registry must define baseline, baseline-diff, baseline-gate, "
            "decision, finding, scan-run, suppression, policy, and policy-result"
        )
    return manifest


def available_schema_versions() -> dict[str, tuple[str, ...]]:
    """Return all locally registered versions for each canonical document."""

    schemas = _manifest()["schemas"]
    return {
        name: tuple(sorted(versions))
        for name, versions in schemas.items()
    }


def _schema_record(schema_name: str, version: str) -> dict[str, str]:
    schemas = _manifest()["schemas"]
    versions = schemas.get(schema_name)
    if not isinstance(versions, dict):
        raise SchemaVersionError(f"unknown schema {schema_name!r}")
    record = versions.get(version)
    if not isinstance(record, dict):
        available = ", ".join(sorted(versions))
        raise SchemaVersionError(
            f"unsupported {schema_name} schema version {version!r}; "
            f"available: {available}"
        )
    if not isinstance(record.get("file"), str) or not isinstance(
        record.get("id"), str
    ):
        raise SchemaVersionError(
            f"invalid registry record for {schema_name} {version}"
        )
    return record


@lru_cache(maxsize=None)
def _load_schema_cached(schema_name: str, version: str) -> dict[str, Any]:
    record = _schema_record(schema_name, version)
    directory = _schema_directory().resolve()
    path = (directory / record["file"]).resolve()
    if path.parent != directory:
        raise SchemaVersionError(
            f"unsafe schema path registered for {schema_name} {version}"
        )
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SchemaVersionError(
            f"could not load {schema_name} schema {version}: {error}"
        ) from error
    if not isinstance(schema, dict):
        raise SchemaVersionError(f"{schema_name} schema root must be an object")
    if schema.get("$id") != record["id"]:
        raise SchemaVersionError(
            f"{schema_name} schema ID does not match registry record"
        )
    declared_version = (
        schema.get("properties", {})
        .get("schema_version", {})
        .get("const")
    )
    if declared_version != version:
        raise SchemaVersionError(
            f"{schema_name} schema does not enforce registered version {version}"
        )
    Draft202012Validator.check_schema(schema)
    return schema


def load_schema(
    schema_name: str,
    *,
    version: str = CURRENT_SCHEMA_VERSION,
) -> dict[str, Any]:
    """Load a defensive copy of one registered schema."""

    return deepcopy(_load_schema_cached(schema_name, version))


@lru_cache(maxsize=None)
def _validator(schema_name: str, version: str) -> Draft202012Validator:
    schemas = [
        _load_schema_cached(name, registered_version)
        for name, versions in available_schema_versions().items()
        for registered_version in versions
    ]
    registry = Registry().with_resources(
        [
            (schema["$id"], Resource.from_contents(schema))
            for schema in schemas
        ]
    )
    return Draft202012Validator(
        _load_schema_cached(schema_name, version),
        registry=registry,
        format_checker=FormatChecker(),
    )


def validate_instance(
    schema_name: str,
    instance: Any,
    *,
    version: str | None = None,
) -> None:
    """Validate a canonical document or raise a path-aware error."""

    selected_version = version
    if selected_version is None and isinstance(instance, dict):
        declared_version = instance.get("schema_version")
        if isinstance(declared_version, str):
            selected_version = declared_version
    if selected_version is None:
        selected_version = CURRENT_SCHEMA_VERSION

    validator = _validator(schema_name, selected_version)
    validation_errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: error.json_path,
    )
    if validation_errors:
        errors = tuple(
            f"{error.json_path}: {error.message}"
            for error in validation_errors
        )
        raise SchemaValidationError(schema_name, errors)


def write_validated_json(
    output: str | Path,
    document: Any,
    *,
    schema_name: str,
) -> Path:
    """Validate and atomically publish one canonical JSON document."""

    validate_instance(schema_name, document)
    output_path = Path(output)
    if output_path.is_symlink():
        raise OSError(f"refusing to replace symlinked output: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            delete=False,
        ) as temporary:
            json.dump(document, temporary, indent=2, sort_keys=True)
            temporary.write("\n")
            temporary_path = Path(temporary.name)
        temporary_path.replace(output_path)
    except BaseException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise
    return output_path
