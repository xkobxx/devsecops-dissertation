from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.supply_chain.pins import validate_repository


class DependencyPinValidationTests(unittest.TestCase):
    def test_reports_floating_action_and_container_references(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / ".github" / "workflows" / "ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                """
steps:
  - uses: actions/checkout@v4
  - uses: ./local-action
  - run: docker run ghcr.io/example/scanner:latest
""".strip(),
                encoding="utf-8",
            )
            (root / "docker-compose.yml").write_text(
                "services:\n  app:\n    image: example/app:main\n",
                encoding="utf-8",
            )

            errors = validate_repository(root)

        self.assertTrue(any("actions/checkout@v4" in error for error in errors))
        self.assertTrue(any("ghcr.io/example/scanner:latest" in error for error in errors))
        self.assertTrue(any("example/app:main" in error for error in errors))
        self.assertFalse(any("./local-action" in error for error in errors))

    def test_accepts_sha_pinned_actions_and_digest_pinned_containers(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / ".github" / "workflows" / "ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                """
steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
  - run: docker run ghcr.io/example/scanner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""".strip(),
                encoding="utf-8",
            )
            (root / "docker-compose.yml").write_text(
                "services:\n  app:\n    image: example/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
                encoding="utf-8",
            )

            self.assertEqual(validate_repository(root), [])

    def test_reports_unbounded_or_unhashed_python_dependencies(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "requirements"
            requirements.mkdir()
            (requirements / "runtime.in").write_text(
                "cryptography>=49\n",
                encoding="utf-8",
            )
            (requirements / "runtime.lock").write_text(
                "cryptography==49.0.0\n",
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text(
                """
[build-system]
requires = ["setuptools>=82"]

[project]
dependencies = ["cryptography"]
""".strip(),
                encoding="utf-8",
            )

            errors = validate_repository(root)

        self.assertTrue(any("cryptography>=49" in error for error in errors))
        self.assertTrue(any("missing hashes" in error for error in errors))
        self.assertTrue(any("setuptools>=82" in error for error in errors))
        self.assertTrue(any("cryptography" in error for error in errors))

    def test_repository_dependency_references_are_immutable(self) -> None:
        root = Path(__file__).resolve().parents[2]

        self.assertEqual(validate_repository(root), [])

    def test_development_lock_includes_linux_sqlalchemy_runtime(self) -> None:
        root = Path(__file__).resolve().parents[2]
        development_input = (root / "requirements" / "development.in").read_text(
            encoding="utf-8"
        )
        development_lock = (root / "requirements" / "development.lock").read_text(
            encoding="utf-8"
        )

        self.assertIn("greenlet==3.5.4", development_input)
        self.assertIn("greenlet==3.5.4", development_lock)


if __name__ == "__main__":
    unittest.main()
