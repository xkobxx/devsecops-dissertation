"""Versioned JSON Schema validation and migration APIs."""

from .documents import build_policy_result, build_scan_run
from .migrations import (
    SchemaMigrationError,
    migrate_finding,
    migrate_fingerprint,
    migrate_scan_run,
)
from .validation import (
    CURRENT_SCHEMA_VERSION,
    SchemaValidationError,
    SchemaVersionError,
    available_schema_versions,
    load_schema,
    validate_instance,
    write_validated_json,
)

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "SchemaMigrationError",
    "SchemaValidationError",
    "SchemaVersionError",
    "available_schema_versions",
    "build_policy_result",
    "build_scan_run",
    "load_schema",
    "migrate_finding",
    "migrate_fingerprint",
    "migrate_scan_run",
    "validate_instance",
    "write_validated_json",
]
