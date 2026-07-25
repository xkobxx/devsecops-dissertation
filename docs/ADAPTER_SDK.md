# TrustGate adapter SDK

TrustGate adapters keep scanner discovery, execution, health validation, native
report parsing, severity normalization, and finding fingerprinting outside the
aggregation core. An adapter can ship with TrustGate or as an independently
installed Python package.

## Lifecycle contract

Every adapter subclasses `trustgate.adapters.ScannerAdapter` and implements:

1. `metadata()` — immutable identity, support, privacy, and runtime details.
2. `is_applicable(repository_context)` — a side-effect-free repository check.
3. `prepare(context)` — optional adapter-local setup; the default is a no-op.
4. `execute(target, context)` — scanner invocation returning `ScannerResult`.
5. `health_check(result)` — verifies the execution outcome; the default
   requires `CLEAN` or `FINDINGS`.
6. `parse(report, context)` — native report to finding mappings.
7. `normalize(finding, context)` — canonical field normalization.
8. `fingerprint(finding, context)` — stable finding and correlation IDs.
9. `cleanup(context)` — optional cleanup; the default is a no-op.

`AdapterContext` resolves `AdapterConfig.timeout_seconds` against the adapter's
default and carries an immutable `RepositoryContext`. Configuration supports
`enabled`, `required`, a positive timeout, and adapter-specific `options`.

`AdapterMetadata` requires:

- name and adapter contract version;
- category and capabilities;
- supported languages and file patterns;
- required local runtime commands;
- default timeout;
- licence;
- whether repository data leaves the runner;
- native report format.

## Minimal adapter

```python
from pathlib import Path

from trustgate.adapters import (
    AdapterCapability,
    AdapterContext,
    AdapterMetadata,
    RepositoryContext,
    ScannerAdapter,
)
from trustgate.scanners.execution import execute_scanner


class ExampleAdapter(ScannerAdapter):
    def metadata(self) -> AdapterMetadata:
        return AdapterMetadata(
            name="example",
            version="1.0.0",
            category="sast",
            supported_languages=("python",),
            supported_files=("*.py",),
            required_runtime=("example-scanner",),
            default_timeout=300.0,
            licence="Apache-2.0",
            data_leaves_runner=False,
            report_format="json",
            capabilities=(AdapterCapability.SAST,),
        )

    def is_applicable(self, repository_context: RepositoryContext) -> bool:
        return "python" in repository_context.languages

    def execute(self, target: Path, context: AdapterContext):
        report = context.reports_dir / "example_report.json"
        return execute_scanner(
            scanner="example",
            command=(
                "example-scanner",
                "--json",
                "--output",
                str(report),
                str(target),
            ),
            report_path=report,
            metadata_path=context.reports_dir / "example_execution.json",
            logs_dir=context.reports_dir / "logs",
            timeout_seconds=context.timeout_seconds,
            finding_exit_codes={1},
        )

    def parse(self, report: Path, context: AdapterContext):
        # Parse and yield canonical candidate mappings. Preserve the native
        # report as raw evidence and never convert malformed input to [].
        ...
```

Use argument arrays, never a shell command string. A findings exit code is only
healthy when the expected report exists. Timeouts, crashes, missing reports,
and malformed reports must remain visible.

## Registration and discovery

Register directly when composing an application:

```python
from trustgate.adapters import AdapterRegistry

registry = AdapterRegistry()
registry.register(ExampleAdapter)
adapter = registry.get("example")
```

Third-party packages declare the `trustgate.adapters` entry-point group:

```toml
[project.entry-points."trustgate.adapters"]
example = "example_trustgate:ExampleAdapter"
```

TrustGate discovers these entry points without aggregator changes. One broken
entry point is recorded in `registry.discovery_errors` and does not hide healthy
adapters. Names must be unique.

## Parsing and failure isolation

Use `parse_with_isolation(adapter, report, context)` when processing independent
reports. It returns `AdapterParseResult` with `SUCCESS`, `FAILED`, or `SKIPPED`;
a failed parser has no findings, so partially mutated output cannot leak into
another scanner's results.

Parsers must:

- validate the native report's root and required collection shapes;
- raise on malformed reports instead of returning a clean result;
- preserve original identifiers, severity, description, and raw evidence;
- map severity with an explainable source-specific rule;
- emit findings that validate against `schemas/finding.schema.json`;
- normalize repository paths before fingerprinting;
- redact sensitive values only in the optional published view.

## Common test suite

Every adapter is run through the checks in
`tests/unit/adapters/test_catalog.py` and parser contract tests in
`tests/unit/adapters/test_builtin_parsers.py`. A third-party adapter should add
the same cases:

- complete, valid metadata;
- applicable and non-applicable repositories;
- command construction without a shell;
- success, findings, failure, and timeout execution outcomes;
- valid, empty, error, and malformed native reports;
- schema validation for every emitted finding;
- stable fingerprints;
- parser and discovery isolation.

Run the focused suite with:

```bash
python -m unittest discover -s tests/unit/adapters -p "test_*.py"
```

## CLI

Inspect applicability:

```bash
trustgate adapter-list --target . --json
```

Run one applicable built-in adapter through prepare, execute, health check,
parse, normalize, fingerprint, and cleanup:

```bash
trustgate adapter-run \
  --scanner gosec \
  --target . \
  --reports-dir reports \
  --timeout 300
```

Unsupported repositories are reported as `SKIPPED` before scanner execution.
Use repeated `--option KEY=JSON_VALUE` arguments for scanner-specific settings.
`--optional` makes an unhealthy scanner non-blocking while preserving its
health evidence.
