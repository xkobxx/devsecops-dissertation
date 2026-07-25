import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.adapters.builtin.catalog import builtin_registry
from trustgate.planning import (
    PlanningConfigurationError,
    PlanningOverrides,
    build_scan_plan,
)
from trustgate.repository import RepositoryContext


class ScanPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self._write(
            "package.json",
            json.dumps(
                {
                    "name": "platform",
                    "dependencies": {"react": "19.0.0"},
                }
            ),
        )
        self._write("package-lock.json", "{}")
        self._write("apps/web/package.json", '{"name": "web"}')
        self._write("apps/web/app.tsx", "export const App = () => null\n")
        self._write(
            "apps/api/pyproject.toml",
            '[project]\nname = "api"\ndependencies = ["flask>=3"]\n',
        )
        self._write("apps/api/app.py", "from flask import Flask\n")
        self._write("services/go/go.mod", "module example.test/service\n")
        self._write("services/go/main.go", "package main\n")
        self._write("infra/main.tf", 'resource "null_resource" "example" {}\n')
        self._write(
            "openapi.yaml",
            "openapi: 3.1.0\ninfo:\n  title: API\n  version: 1.0.0\n",
        )
        self._write("Dockerfile", "FROM scratch\n")

    def _write(self, name: str, content: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _plan(self, overrides: PlanningOverrides | None = None):
        return build_scan_plan(
            RepositoryContext.from_path(self.root),
            builtin_registry(),
            overrides=overrides,
        )

    def test_selects_scanners_per_package_with_explainable_reasons(self) -> None:
        plan = self._plan()
        decisions = {decision.scanner: decision for decision in plan.decisions}

        self.assertTrue(decisions["bandit"].enabled)
        self.assertEqual(decisions["bandit"].target_directories, ("apps/api",))
        self.assertIn("python", decisions["bandit"].reason)
        self.assertTrue(decisions["gosec"].enabled)
        self.assertEqual(decisions["gosec"].target_directories, ("services/go",))
        self.assertTrue(decisions["eslint-security"].enabled)
        self.assertIn("apps/web", decisions["eslint-security"].target_directories)
        self.assertTrue(decisions["checkov"].enabled)
        self.assertTrue(decisions["hadolint"].enabled)
        self.assertTrue(decisions["zap"].enabled)
        self.assertFalse(decisions["brakeman"].enabled)
        self.assertIn("no supported", decisions["brakeman"].reason)

    def test_repository_wide_scanners_run_once_and_optional_scanner_is_opt_in(self) -> None:
        plan = self._plan()
        decisions = {decision.scanner: decision for decision in plan.decisions}

        for scanner in ("gitleaks", "grype", "syft", "trivy"):
            self.assertEqual(decisions[scanner].target_directories, (".",))
        self.assertFalse(decisions["trufflehog"].enabled)
        self.assertIn("opt-in", decisions["trufflehog"].reason)

    def test_plan_exposes_every_pre_execution_decision_field(self) -> None:
        plan = self._plan()
        document = plan.to_dict()
        first = document["decisions"][0]

        self.assertEqual(document["schema_version"], "1.0")
        self.assertIn("detected_technologies", document)
        self.assertIn("enabled_scanners", document)
        self.assertIn("skipped_scanners", document)
        self.assertIn("reason", first)
        self.assertIn("target_directories", first)
        self.assertIn("expected_outputs", first)
        self.assertGreater(first["timeout_seconds"], 0)
        self.assertEqual(
            first["data_handling"]["behaviour"],
            "local-only; repository data does not leave the runner",
        )
        self.assertFalse(first["data_handling"]["data_leaves_runner"])
        self.assertEqual(document, self._plan().to_dict())

    def test_overrides_take_precedence_and_are_auditable(self) -> None:
        plan = self._plan(
            PlanningOverrides(
                enable_scanners=frozenset({"trufflehog"}),
                disable_scanners=frozenset({"bandit"}),
                timeouts={"gosec": 42.0},
            )
        )
        decisions = {decision.scanner: decision for decision in plan.decisions}

        self.assertTrue(decisions["trufflehog"].enabled)
        self.assertIn("explicitly enabled", decisions["trufflehog"].reason)
        self.assertFalse(decisions["bandit"].enabled)
        self.assertIn("explicitly disabled", decisions["bandit"].reason)
        self.assertEqual(decisions["gosec"].timeout_seconds, 42.0)
        self.assertEqual(decisions["gosec"].decision_source, "override")

    def test_rejects_conflicting_unknown_and_invalid_overrides(self) -> None:
        cases = (
            PlanningOverrides(
                enable_scanners=frozenset({"bandit"}),
                disable_scanners=frozenset({"bandit"}),
            ),
            PlanningOverrides(enable_scanners=frozenset({"not-a-scanner"})),
            PlanningOverrides(timeouts={"bandit": 0}),
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(PlanningConfigurationError):
                    self._plan(overrides)

    def test_dry_run_is_recorded_without_changing_selection(self) -> None:
        normal = self._plan()
        dry_run = self._plan(PlanningOverrides(dry_run=True))

        self.assertFalse(normal.dry_run)
        self.assertTrue(dry_run.dry_run)
        self.assertEqual(normal.enabled_scanners, dry_run.enabled_scanners)

    def test_root_infrastructure_is_planned_when_monorepo_has_no_root_manifest(self) -> None:
        isolated = Path(self.directory.name) / "isolated"
        isolated.mkdir()
        (isolated / "packages/api").mkdir(parents=True)
        (isolated / "packages/api/pyproject.toml").write_text(
            '[project]\nname = "api"\n',
            encoding="utf-8",
        )
        (isolated / "packages/api/app.py").write_text(
            "print('api')\n", encoding="utf-8"
        )
        (isolated / "infra").mkdir()
        (isolated / "infra/main.tf").write_text(
            'resource "null_resource" "example" {}\n',
            encoding="utf-8",
        )

        plan = build_scan_plan(
            RepositoryContext.from_path(isolated),
            builtin_registry(),
        )
        decisions = {decision.scanner: decision for decision in plan.decisions}

        self.assertEqual(decisions["bandit"].target_directories, ("packages/api",))
        self.assertEqual(decisions["checkov"].target_directories, (".",))

    def test_detected_openapi_specification_selects_zap_regardless_of_filename(self) -> None:
        self._write(
            "api/specification.yaml",
            "openapi: 3.1.0\ninfo:\n  title: API\n  version: 1\n",
        )
        (self.root / "openapi.yaml").unlink()

        plan = self._plan()
        decision = next(
            item for item in plan.decisions if item.scanner == "zap"
        )

        self.assertTrue(decision.enabled)
        self.assertEqual(decision.target_directories, (".",))
        self.assertIn("specification.yaml", decision.reason)


if __name__ == "__main__":
    unittest.main()
