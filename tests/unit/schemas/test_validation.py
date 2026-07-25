"""Tests for runtime schema loading, validation, and safe publication."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.schema import (
    CURRENT_SCHEMA_VERSION,
    SchemaValidationError,
    SchemaVersionError,
    available_schema_versions,
    load_schema,
    validate_instance,
    write_validated_json,
)

from .test_schema_contracts import valid_finding


class SchemaValidationTests(unittest.TestCase):
    def test_registry_exposes_every_current_schema_version(self) -> None:
        self.assertEqual(CURRENT_SCHEMA_VERSION, "1.0.0")
        self.assertEqual(
            available_schema_versions(),
            {
                "finding": ("1.0.0",),
                "scan-run": ("1.0.0",),
                "policy-result": ("1.0.0",),
            },
        )

    def test_loader_rejects_unknown_schema_names_and_versions(self) -> None:
        with self.assertRaisesRegex(SchemaVersionError, "unknown schema"):
            load_schema("not-a-schema")

        with self.assertRaisesRegex(SchemaVersionError, "unsupported finding"):
            load_schema("finding", version="99.0.0")

    def test_validation_error_contains_instance_path(self) -> None:
        invalid = valid_finding()
        invalid["normalised_severity"] = "catastrophic"

        with self.assertRaises(SchemaValidationError) as raised:
            validate_instance("finding", invalid)

        self.assertIn("$.normalised_severity", str(raised.exception))
        self.assertEqual(raised.exception.schema_name, "finding")
        self.assertTrue(raised.exception.errors)

    def test_declared_instance_version_selects_the_schema(self) -> None:
        invalid_version = valid_finding()
        invalid_version["schema_version"] = "2.0.0"

        with self.assertRaisesRegex(SchemaVersionError, "unsupported finding"):
            validate_instance("finding", invalid_version)

    def test_atomic_writer_validates_before_replacing_output(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "finding.json"
            output.write_text('{"preserved": true}\n', encoding="utf-8")
            invalid = deepcopy(valid_finding())
            invalid.pop("rule_id")

            with self.assertRaises(SchemaValidationError):
                write_validated_json(output, invalid, schema_name="finding")

            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8")),
                {"preserved": True},
            )

            write_validated_json(
                output,
                valid_finding(),
                schema_name="finding",
            )
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8"))["schema_version"],
                CURRENT_SCHEMA_VERSION,
            )


if __name__ == "__main__":
    unittest.main()
