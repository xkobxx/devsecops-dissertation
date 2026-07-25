import unittest

from trustgate.adapters import (
    AdapterCapability,
    AdapterMetadata,
    AdapterRegistry,
    ScannerAdapter,
)


class RegistryAdapter(ScannerAdapter):
    def metadata(self) -> AdapterMetadata:
        return AdapterMetadata(
            name="registry-example",
            version="1",
            category="sca",
            supported_languages=(),
            supported_files=("requirements*.txt",),
            required_runtime=("registry-example",),
            default_timeout=60.0,
            licence="MIT",
            data_leaves_runner=False,
            report_format="json",
            capabilities=(AdapterCapability.SCA,),
        )

    def is_applicable(self, repository_context):
        return True

    def execute(self, target, context):
        raise NotImplementedError

    def parse(self, report, context):
        return []


class FakeEntryPoint:
    name = "registry-example"

    @staticmethod
    def load():
        return RegistryAdapter


class BrokenEntryPoint:
    name = "broken"

    @staticmethod
    def load():
        raise RuntimeError("plugin import failed")


class AdapterRegistryTests(unittest.TestCase):
    def test_registers_and_resolves_adapter_without_aggregator_changes(self) -> None:
        registry = AdapterRegistry()

        registry.register(RegistryAdapter)

        self.assertIsInstance(registry.get("registry-example"), RegistryAdapter)
        self.assertEqual(registry.names(), ("registry-example",))

    def test_duplicate_registration_is_rejected(self) -> None:
        registry = AdapterRegistry()
        registry.register(RegistryAdapter)

        with self.assertRaisesRegex(ValueError, "already registered"):
            registry.register(RegistryAdapter)

    def test_discovers_adapter_entry_points(self) -> None:
        registry = AdapterRegistry()

        discovered = registry.discover(entry_points=(FakeEntryPoint(),))

        self.assertEqual(discovered, ("registry-example",))
        self.assertIsInstance(registry.get("registry-example"), RegistryAdapter)

    def test_broken_entry_point_does_not_hide_healthy_adapter(self) -> None:
        registry = AdapterRegistry()

        discovered = registry.discover(
            entry_points=(BrokenEntryPoint(), FakeEntryPoint())
        )

        self.assertEqual(discovered, ("registry-example",))
        self.assertIn("broken", registry.discovery_errors)
        self.assertIn("plugin import failed", registry.discovery_errors["broken"])


if __name__ == "__main__":
    unittest.main()
