from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.adapters import (
    AdapterCapability,
    AdapterConfig,
    AdapterContext,
    AdapterMetadata,
    RepositoryContext,
    ScannerAdapter,
)


class ExampleAdapter(ScannerAdapter):
    def metadata(self) -> AdapterMetadata:
        return AdapterMetadata(
            name="example",
            version="1.2.3",
            category="sast",
            supported_languages=("python",),
            supported_files=("*.py",),
            required_runtime=("example",),
            default_timeout=30.0,
            licence="Apache-2.0",
            data_leaves_runner=False,
            report_format="json",
            capabilities=(AdapterCapability.SAST,),
        )

    def is_applicable(self, repository_context: RepositoryContext) -> bool:
        return "python" in repository_context.languages

    def execute(self, target: Path, context: AdapterContext):
        raise NotImplementedError

    def parse(self, report: Path, context: AdapterContext):
        return []


class AdapterSdkTests(unittest.TestCase):
    def test_metadata_exposes_every_roadmap_field(self) -> None:
        metadata = ExampleAdapter().metadata()

        self.assertEqual(metadata.name, "example")
        self.assertEqual(metadata.version, "1.2.3")
        self.assertEqual(metadata.category, "sast")
        self.assertEqual(metadata.supported_languages, ("python",))
        self.assertEqual(metadata.supported_files, ("*.py",))
        self.assertEqual(metadata.required_runtime, ("example",))
        self.assertEqual(metadata.default_timeout, 30.0)
        self.assertEqual(metadata.licence, "Apache-2.0")
        self.assertFalse(metadata.data_leaves_runner)
        self.assertEqual(metadata.report_format, "json")
        self.assertEqual(metadata.capabilities, (AdapterCapability.SAST,))

    def test_repository_context_supports_adapter_applicability(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "service.py").write_text("print('hello')\n", encoding="utf-8")

            context = RepositoryContext.from_path(root)

        self.assertIn("service.py", context.files)
        self.assertIn("python", context.languages)
        self.assertTrue(ExampleAdapter().is_applicable(context))

    def test_config_uses_metadata_timeout_and_rejects_invalid_timeout(self) -> None:
        adapter = ExampleAdapter()
        context = AdapterContext.create(
            repository=RepositoryContext(root=Path(".")),
            reports_dir=Path("reports"),
            config=AdapterConfig(),
            metadata=adapter.metadata(),
        )

        self.assertEqual(context.timeout_seconds, 30.0)
        with self.assertRaisesRegex(ValueError, "greater than zero"):
            AdapterConfig(timeout_seconds=0)

    def test_base_prepare_and_cleanup_are_safe_defaults(self) -> None:
        adapter = ExampleAdapter()
        context = AdapterContext.create(
            repository=RepositoryContext(root=Path(".")),
            reports_dir=Path("reports"),
            config=AdapterConfig(),
            metadata=adapter.metadata(),
        )

        self.assertIs(adapter.prepare(context), context)
        self.assertIsNone(adapter.cleanup(context))


if __name__ == "__main__":
    unittest.main()
