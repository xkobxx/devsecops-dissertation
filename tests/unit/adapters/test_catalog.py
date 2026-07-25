from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.adapters import AdapterContext, AdapterConfig, RepositoryContext
from trustgate.adapters.builtin.catalog import (
    BUILTIN_ADAPTER_NAMES,
    builtin_registry,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class BuiltinAdapterCatalogTests(unittest.TestCase):
    def _repository(self, files: tuple[str, ...]) -> RepositoryContext:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for name in files:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n", encoding="utf-8")
        return RepositoryContext.from_path(root)

    def test_all_roadmap_scanners_are_registered(self) -> None:
        registry = builtin_registry()

        self.assertEqual(registry.names(), BUILTIN_ADAPTER_NAMES)
        self.assertEqual(len(registry.names()), 17)

    def test_every_builtin_passes_common_metadata_contract(self) -> None:
        registry = builtin_registry()
        for name in registry.names():
            with self.subTest(adapter=name):
                adapter = registry.get(name)
                metadata = adapter.metadata()
                self.assertEqual(metadata.name, name)
                self.assertTrue(metadata.version)
                self.assertTrue(metadata.category)
                self.assertGreater(metadata.default_timeout, 0)
                self.assertTrue(metadata.licence)
                self.assertTrue(metadata.report_format)
                self.assertTrue(metadata.capabilities)

    def test_language_specific_adapters_are_only_applicable_when_supported(self) -> None:
        registry = builtin_registry()
        python_repository = self._repository(("app.py", "requirements.txt"))
        go_repository = self._repository(("main.go", "go.mod"))
        rails_repository = self._repository(
            ("Gemfile", "config/application.rb", "app/models/user.rb")
        )
        java_repository = self._repository(("pom.xml", "src/main/java/App.java"))
        javascript_repository = self._repository(("package.json", "src/app.ts"))

        self.assertTrue(registry.get("bandit").is_applicable(python_repository))
        self.assertFalse(registry.get("bandit").is_applicable(go_repository))
        self.assertTrue(registry.get("gosec").is_applicable(go_repository))
        self.assertFalse(registry.get("gosec").is_applicable(python_repository))
        self.assertTrue(registry.get("brakeman").is_applicable(rails_repository))
        self.assertFalse(registry.get("brakeman").is_applicable(python_repository))
        self.assertTrue(registry.get("spotbugs").is_applicable(java_repository))
        self.assertTrue(registry.get("eslint-security").is_applicable(javascript_repository))

    def test_file_specific_adapters_skip_unsupported_repositories(self) -> None:
        registry = builtin_registry()
        plain = self._repository(("README.md",))
        docker = self._repository(("Dockerfile",))
        terraform = self._repository(("infra/main.tf",))
        openapi = self._repository(("openapi.yaml",))

        self.assertFalse(registry.get("hadolint").is_applicable(plain))
        self.assertTrue(registry.get("hadolint").is_applicable(docker))
        self.assertFalse(registry.get("checkov").is_applicable(plain))
        self.assertTrue(registry.get("checkov").is_applicable(terraform))
        self.assertFalse(registry.get("zap").is_applicable(plain))
        self.assertTrue(registry.get("zap").is_applicable(openapi))

    def test_context_can_be_created_for_every_builtin(self) -> None:
        repository = self._repository(("app.py",))
        registry = builtin_registry()
        for name in registry.names():
            adapter = registry.get(name)
            context = AdapterContext.create(
                repository=repository,
                reports_dir=repository.root / "reports",
                config=AdapterConfig(),
                metadata=adapter.metadata(),
            )
            self.assertEqual(context.metadata.name, name)

    def test_sdk_and_every_builtin_applicability_are_documented(self) -> None:
        sdk = (REPOSITORY_ROOT / "docs" / "ADAPTER_SDK.md").read_text(
            encoding="utf-8"
        )
        compatibility = (
            REPOSITORY_ROOT / "docs" / "SCANNER_COMPATIBILITY.md"
        ).read_text(encoding="utf-8")

        self.assertIn("trustgate.adapters", sdk)
        self.assertIn('trustgate.adapters"', sdk)
        for name in BUILTIN_ADAPTER_NAMES:
            with self.subTest(adapter=name):
                self.assertIn(f"`{name}`", compatibility)


if __name__ == "__main__":
    unittest.main()
