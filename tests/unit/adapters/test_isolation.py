from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.adapters import (
    AdapterCapability,
    AdapterConfig,
    AdapterContext,
    AdapterMetadata,
    AdapterParseStatus,
    RepositoryContext,
    ScannerAdapter,
    parse_with_isolation,
)


class HealthyAdapter(ScannerAdapter):
    def metadata(self) -> AdapterMetadata:
        return AdapterMetadata(
            name="healthy",
            version="1",
            category="sast",
            supported_languages=(),
            supported_files=(),
            required_runtime=(),
            default_timeout=10.0,
            licence="MIT",
            data_leaves_runner=False,
            report_format="json",
            capabilities=(AdapterCapability.SAST,),
        )

    def is_applicable(self, repository_context):
        return True

    def execute(self, target, context):
        raise NotImplementedError

    def parse(self, report, context):
        return [{"scanner": "healthy", "rule_id": "RULE-1"}]


class BrokenAdapter(HealthyAdapter):
    def metadata(self) -> AdapterMetadata:
        return super().metadata().with_name("broken")

    def parse(self, report, context):
        raise ValueError("malformed scanner report")


class AdapterIsolationTests(unittest.TestCase):
    def test_broken_adapter_does_not_corrupt_healthy_results(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            report.write_text("{}\n", encoding="utf-8")
            repository = RepositoryContext(root=root)
            healthy = HealthyAdapter()
            broken = BrokenAdapter()
            healthy_context = AdapterContext.create(
                repository=repository,
                reports_dir=root,
                config=AdapterConfig(),
                metadata=healthy.metadata(),
            )
            broken_context = AdapterContext.create(
                repository=repository,
                reports_dir=root,
                config=AdapterConfig(),
                metadata=broken.metadata(),
            )

            healthy_result = parse_with_isolation(
                healthy, report, healthy_context
            )
            broken_result = parse_with_isolation(
                broken, report, broken_context
            )

        self.assertEqual(healthy_result.status, AdapterParseStatus.SUCCESS)
        self.assertEqual(healthy_result.findings[0]["rule_id"], "RULE-1")
        self.assertEqual(broken_result.status, AdapterParseStatus.FAILED)
        self.assertEqual(broken_result.findings, ())
        self.assertIn("malformed scanner report", broken_result.error)


if __name__ == "__main__":
    unittest.main()
