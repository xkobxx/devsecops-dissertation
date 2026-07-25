# Repository detection and scan planning

TrustGate inventories a checkout locally before any scanner starts. The
inventory is immutable and deterministic, and the resulting plan explains every
automatic or operator-supplied scanner decision.

## Inspect a plan

Human-readable output is the default:

```bash
trustgate plan --target .
```

Machine-readable output uses the same complete plan model:

```bash
trustgate plan --target . --format json
trustgate plan --target . --json
```

`trustgate plan` never executes scanners. `--dry-run` records that intent in the
plan, and `trustgate adapter-run --scanner NAME --dry-run` previews one explicit
adapter invocation without creating reports or launching its runtime.

Every plan reports:

- detected languages, frameworks, package managers, lock files, build systems,
  container/IaC/API files, tests, generated content, and vendored content;
- monorepo packages and runtime/development dependency counts;
- enabled and skipped scanners, with the reason and decision source;
- target directories and expected native, health, and finding outputs;
- the effective timeout for every scanner;
- whether repository data may leave the runner.

JSON output is ordered deterministically by scanner and package path. It uses
scan-plan schema version `1.0`.

## Detection and scan boundaries

`RepositoryContext.from_path()` discovers source languages by suffix and uses
manifests, lock files, and dependency declarations to infer ecosystems and
frameworks. Supported package contexts include npm, Python/pip/uv, Go modules,
Cargo, Maven/Gradle, Bundler, Composer, and NuGet indicators. Dependency scopes
are read from ecosystem-specific runtime and development sections.

A directory containing a recognised manifest becomes a package context.
Nested packages receive separate file, language, framework, package-manager,
build-system, and dependency inventories. Repository-root infrastructure remains
its own scan target even when a monorepo has no root manifest. Repository-wide
scanners run once at `.` rather than once per package.

Generated paths such as `dist`, `build`, `coverage`, `.next`, `target`, generated
source names, minified assets, and source maps are detected and excluded from
scanner contexts by default. Vendored dependency directories such as
`node_modules`, `vendor`, virtual environments, and `site-packages` are pruned
from traversal by default. The context retains each exclusion and its reason.

Include these paths only when the risk and runtime cost are understood:

```bash
trustgate plan --include-generated --include-vendored
```

## Override automatic decisions

Explicit choices take precedence and are visible as `decision_source:
"override"`:

```bash
trustgate plan \
  --enable-scanner trufflehog \
  --disable-scanner bandit \
  --timeout gitleaks=180 \
  --timeout semgrep=600
```

Each option may be repeated. TrustGate rejects:

- a scanner named in both enable and disable lists;
- unknown scanner names;
- malformed timeout assignments;
- zero or negative timeouts.

TruffleHog is opt-in by default. Other built-ins are selected from their
repository-wide, language, or supported-file applicability rules. An explicit
enable can intentionally select a scanner without an automatically detected
signal; the plan records that override rather than presenting it as automatic.

## Privacy

Detection reads only local repository metadata and small text configuration
files. It does not make network requests. Scanner metadata supplies the
data-handling declaration shown in the plan. The current built-in adapters all
declare local-only handling; third-party adapters must declare their behavior in
`AdapterMetadata.data_leaves_runner`.

## API

Use the same contracts programmatically:

```python
from pathlib import Path

from trustgate.adapters.builtin.catalog import builtin_registry
from trustgate.planning import PlanningOverrides, build_scan_plan
from trustgate.repository import RepositoryContext

repository = RepositoryContext.from_path(Path("."))
plan = build_scan_plan(
    repository,
    builtin_registry(),
    overrides=PlanningOverrides(
        disable_scanners=frozenset({"bandit"}),
        timeouts={"semgrep": 600.0},
        dry_run=True,
    ),
)
document = plan.to_dict()
```

Repository and plan serialization return JSON-compatible, stable structures
suitable for review, tests, and later execution orchestration.
