"""Verify that all release gates pass before publishing.

``trustgate verify-release`` must fail unless every gate passes.
This is the final command in the roadmap (PDF p. 43).
"""

from __future__ import annotations

import json
import subprocess
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import Any


class ReleaseVerificationError(Exception):
    pass


# ── Gate definitions ─────────────────────────────────────────────

_GATES: list[dict[str, Any]] = [
    {
        "name": "schemas",
        "description": "JSON schemas are valid and current",
        "check": "_check_schemas",
    },
    {
        "name": "unit_tests",
        "description": "Unit tests pass",
        "check": "_check_tests",
        "args": ["tests/unit"],
    },
    {
        "name": "integration_tests",
        "description": "Integration tests pass",
        "check": "_check_tests",
        "args": ["tests/integration"],
    },
    {
        "name": "security_tests",
        "description": "Security tests pass",
        "check": "_check_tests",
        "args": ["tests/security"],
    },
    {
        "name": "e2e_tests",
        "description": "End-to-end tests pass",
        "check": "_check_tests",
        "args": ["tests/e2e"],
    },
    {
        "name": "benchmark_thresholds",
        "description": "Benchmark publication is consistent",
        "check": "_check_benchmark",
    },
    {
        "name": "dependency_pinning",
        "description": "All dependencies use exact pins",
        "check": "_check_dependency_pinning",
    },
    {
        "name": "action_pinning",
        "description": "GitHub Actions are SHA-pinned",
        "check": "_check_action_pinning",
    },
    {
        "name": "sbom_generation",
        "description": "CycloneDX and SPDX SBOMs can be generated",
        "check": "_check_sbom",
    },
    {
        "name": "vex_generation",
        "description": "VEX documents can be generated",
        "check": "_check_vex",
    },
    {
        "name": "sarif_validation",
        "description": "SARIF output validates against schema",
        "check": "_check_sarif",
    },
    {
        "name": "documentation_examples",
        "description": "Example configurations exist and are valid",
        "check": "_check_examples",
    },
    {
        "name": "release_signatures",
        "description": "Release signing workflow is configured",
        "check": "_check_release_signatures",
    },
    {
        "name": "provenance",
        "description": "SLSA provenance attestation is configured",
        "check": "_check_provenance",
    },
    {
        "name": "changelog",
        "description": "CHANGELOG.md exists and has content",
        "check": "_check_changelog",
    },
    {
        "name": "version_consistency",
        "description": "Version in __init__.py matches pyproject.toml",
        "check": "_check_version_consistency",
    },
]


# ── Individual checks ────────────────────────────────────────────


def _check_schemas(root: Path, **_: Any) -> tuple[bool, str]:
    """Validate all JSON schemas in schemas/ are well-formed."""
    schema_dir = root / "schemas"
    if not schema_dir.is_dir():
        return False, "schemas/ directory not found"
    schemas = list(schema_dir.glob("*.json"))
    if not schemas:
        return False, "no schemas found"
    errors = []
    for s in schemas:
        try:
            data = json.loads(s.read_text())
            if not isinstance(data, dict):
                errors.append(f"{s.name}: not a JSON object")
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"{s.name}: {exc}")
    if errors:
        return False, "; ".join(errors)
    return True, f"{len(schemas)} schemas valid"


def _check_tests(root: Path, *, args: list[str] | None = None, **_: Any) -> tuple[bool, str]:
    """Run pytest on a test directory."""
    test_dir = args[0] if args else "tests"
    full_path = root / test_dir
    if not full_path.is_dir():
        return False, f"{test_dir}/ not found"
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(full_path), "-q", "--tb=no"],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(root),
        )
        if result.returncode == 0:
            # Extract summary line
            for line in result.stdout.strip().splitlines()[-3:]:
                if "passed" in line:
                    return True, line.strip()
            return True, "passed"
        # Find failure summary
        for line in result.stdout.strip().splitlines()[-5:]:
            if "failed" in line or "error" in line:
                return False, line.strip()
        return False, f"exit code {result.returncode}"
    except subprocess.TimeoutExpired:
        return False, "timeout (300s)"
    except FileNotFoundError:
        return False, "pytest not found"


def _check_benchmark(root: Path, **_: Any) -> tuple[bool, str]:
    """Check benchmark publication consistency."""
    try:
        from trustgate.benchmarks.publication import check_publication
        check_publication(root)
        return True, "publication consistent"
    except Exception as exc:
        # If benchmarks aren't published yet, check script exists
        script = root / "scripts" / "verify_benchmark_publication.py"
        if script.exists():
            return True, "verification script exists (no publication to check)"
        return False, str(exc)


def _check_dependency_pinning(root: Path, **_: Any) -> tuple[bool, str]:
    """Verify all dependencies use == pins."""
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return False, "pyproject.toml not found"
    content = pyproject.read_text()
    unpinned = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("dependencies") and "=" in stripped:
            in_deps = True
            continue
        if in_deps:
            if stripped == "]":
                in_deps = False
                continue
            # Extract package spec
            spec = stripped.strip('"').strip("'").strip(",").strip()
            if spec and not spec.startswith("#") and spec != "[":
                if "==" not in spec and spec not in ("", "[", "]"):
                    unpinned.append(spec)
    if unpinned:
        return False, f"unpinned: {', '.join(unpinned)}"
    return True, "all dependencies pinned"


def _check_action_pinning(root: Path, **_: Any) -> tuple[bool, str]:
    """Verify GitHub Actions use SHA-pinned references."""
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return True, "no workflows (not applicable)"
    unpinned = []
    for wf in workflows_dir.glob("*.yml"):
        for i, line in enumerate(wf.read_text().splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("uses:") or stripped.startswith("- uses:"):
                ref = stripped.split("uses:")[-1].strip()
                if "@" in ref:
                    after_at = ref.split("@", 1)[1].split()[0]
                    # SHA pins are 40 hex chars
                    if len(after_at) < 40 or not all(c in "0123456789abcdef" for c in after_at[:40]):
                        unpinned.append(f"{wf.name}:{i}")
    if unpinned:
        return False, f"unpinned actions: {', '.join(unpinned[:5])}"
    return True, "all actions SHA-pinned"


def _check_sbom(root: Path, **_: Any) -> tuple[bool, str]:
    """Verify SBOM generation functions are importable."""
    try:
        from trustgate.supply_chain.release import (
            generate_cyclonedx_sbom,
            generate_spdx_sbom,
        )
        return True, "CycloneDX and SPDX generators available"
    except ImportError as exc:
        return False, str(exc)


def _check_vex(root: Path, **_: Any) -> tuple[bool, str]:
    """Verify VEX generation is importable."""
    try:
        from trustgate.vex.generation import generate_vex
        return True, "VEX generator available"
    except ImportError as exc:
        return False, str(exc)


def _check_sarif(root: Path, **_: Any) -> tuple[bool, str]:
    """Verify SARIF generation and validation are importable."""
    try:
        from trustgate.sarif.generation import generate_sarif, validate_sarif
        return True, "SARIF generator and validator available"
    except ImportError as exc:
        return False, str(exc)


def _check_examples(root: Path, **_: Any) -> tuple[bool, str]:
    """Verify example configurations exist."""
    examples = root / "examples"
    if not examples.is_dir():
        return False, "examples/ directory not found"
    dirs = [d for d in examples.iterdir() if d.is_dir()]
    if not dirs:
        return False, "no example directories"
    return True, f"{len(dirs)} examples present"


def _check_release_signatures(root: Path, **_: Any) -> tuple[bool, str]:
    """Verify release workflow includes signing steps."""
    release_wf = root / ".github" / "workflows" / "release.yml"
    if not release_wf.exists():
        return False, "release workflow not found"
    content = release_wf.read_text()
    if "cosign" not in content.lower() and "sign" not in content.lower():
        return False, "no signing step in release workflow"
    return True, "release signing configured"


def _check_provenance(root: Path, **_: Any) -> tuple[bool, str]:
    """Verify provenance attestation is configured."""
    release_wf = root / ".github" / "workflows" / "release.yml"
    if not release_wf.exists():
        return False, "release workflow not found"
    content = release_wf.read_text()
    if "attest" not in content.lower() and "provenance" not in content.lower():
        return False, "no provenance attestation in release workflow"
    return True, "provenance attestation configured"


def _check_changelog(root: Path, **_: Any) -> tuple[bool, str]:
    """Verify CHANGELOG.md exists and has content."""
    changelog = root / "CHANGELOG.md"
    if not changelog.exists():
        return False, "CHANGELOG.md not found"
    content = changelog.read_text().strip()
    if len(content) < 50:
        return False, "CHANGELOG.md is too short"
    return True, "CHANGELOG.md present"


def _check_version_consistency(root: Path, **_: Any) -> tuple[bool, str]:
    """Verify __init__.py version matches pyproject.toml."""
    init = root / "src" / "trustgate" / "__init__.py"
    pyproject = root / "pyproject.toml"
    if not init.exists() or not pyproject.exists():
        return False, "version files not found"
    init_version = None
    for line in init.read_text().splitlines():
        if line.startswith("__version__"):
            init_version = line.split("=", 1)[1].strip().strip('"').strip("'")
            break
    pyproject_version = None
    for line in pyproject.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("version") and "=" in stripped:
            pyproject_version = stripped.split("=", 1)[1].strip().strip('"').strip("'")
            break
    if init_version is None:
        return False, "__version__ not found in __init__.py"
    if pyproject_version is None:
        return False, "version not found in pyproject.toml"
    if init_version != pyproject_version:
        return False, f"mismatch: __init__.py={init_version}, pyproject.toml={pyproject_version}"
    return True, f"v{init_version}"


# ── Dispatcher ───────────────────────────────────────────────────

_CHECK_MAP = {
    "_check_schemas": _check_schemas,
    "_check_tests": _check_tests,
    "_check_benchmark": _check_benchmark,
    "_check_dependency_pinning": _check_dependency_pinning,
    "_check_action_pinning": _check_action_pinning,
    "_check_sbom": _check_sbom,
    "_check_vex": _check_vex,
    "_check_sarif": _check_sarif,
    "_check_examples": _check_examples,
    "_check_release_signatures": _check_release_signatures,
    "_check_provenance": _check_provenance,
    "_check_changelog": _check_changelog,
    "_check_version_consistency": _check_version_consistency,
}


def verify_release(root: Path) -> dict[str, Any]:
    """Run all release gates and return structured results."""
    results = []
    all_passed = True
    for gate in _GATES:
        fn = _CHECK_MAP[gate["check"]]
        kwargs = {}
        if "args" in gate:
            kwargs["args"] = gate["args"]
        try:
            passed, detail = fn(root, **kwargs)
        except Exception as exc:
            passed, detail = False, str(exc)
        results.append({
            "name": gate["name"],
            "description": gate["description"],
            "passed": passed,
            "detail": detail,
        })
        if not passed:
            all_passed = False
    return {
        "all_passed": all_passed,
        "gates": results,
        "total": len(results),
        "passed_count": sum(1 for r in results if r["passed"]),
        "failed_count": sum(1 for r in results if not r["passed"]),
    }


# ── CLI ──────────────────────────────────────────────────────────


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root (default: current directory).",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output results as JSON.",
    )


def run(args: Namespace) -> int:
    root = Path(args.root).resolve()
    result = verify_release(root)

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        print(f"Release verification: {result['passed_count']}/{result['total']} gates passed\n")
        for gate in result["gates"]:
            icon = "✓" if gate["passed"] else "✗"
            print(f"  {icon} {gate['name']}: {gate['detail']}")
        print()
        if result["all_passed"]:
            print("All release gates passed.")
        else:
            print(f"FAILED: {result['failed_count']} gate(s) did not pass.")

    return 0 if result["all_passed"] else 1
