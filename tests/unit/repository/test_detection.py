import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from trustgate.repository import DependencyScope, RepositoryContext


class RepositoryDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def _write(self, name: str, content: str = "") -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _polyglot_monorepo(self) -> RepositoryContext:
        self._write(
            "package.json",
            json.dumps(
                {
                    "name": "platform",
                    "private": True,
                    "workspaces": ["apps/*"],
                    "dependencies": {"react": "19.0.0"},
                    "devDependencies": {"eslint": "9.0.0"},
                }
            ),
        )
        self._write("package-lock.json", "{}")
        self._write("apps/web/package.json", json.dumps({"name": "web"}))
        self._write("apps/web/src/app.tsx", "export const App = () => null\n")
        self._write(
            "apps/api/pyproject.toml",
            """
[project]
name = "api"
dependencies = ["flask>=3", "sqlalchemy>=2"]

[project.optional-dependencies]
dev = ["pytest>=8"]
""",
        )
        self._write("apps/api/uv.lock", "version = 1\n")
        self._write("apps/api/app.py", "from flask import Flask\n")
        self._write("apps/api/tests/test_app.py", "def test_app(): pass\n")
        self._write("services/go/go.mod", "module example.test/service\n\nrequire github.com/gin-gonic/gin v1.10.0\n")
        self._write("services/go/main.go", "package main\n")
        self._write("infra/main.tf", 'resource "aws_s3_bucket" "data" {}\n')
        self._write(
            "deploy/k8s/deployment.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n",
        )
        self._write(
            "deploy/cloudformation.yaml",
            "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n",
        )
        self._write(
            "api/openapi.yaml",
            "openapi: 3.1.0\ninfo:\n  title: Platform\n  version: 1.0.0\n",
        )
        self._write("Dockerfile", "FROM python:3.13-slim\n")
        self._write("compose.yaml", "services:\n  api:\n    build: .\n")
        self._write("Makefile", "test:\n\tpython -m unittest\n")
        self._write("dist/generated.min.js", "eval('generated')\n")
        self._write("src/client.generated.ts", "export const generated = true\n")
        self._write("vendor/example/insecure.py", "eval(input())\n")
        self._write("node_modules/example/index.js", "eval(input())\n")
        return RepositoryContext.from_path(self.root)

    def test_detects_every_phase_5_repository_signal(self) -> None:
        context = self._polyglot_monorepo()

        self.assertEqual(
            context.languages,
            frozenset({"go", "javascript", "python", "typescript"}),
        )
        self.assertTrue({"flask", "react", "gin"}.issubset(context.frameworks))
        self.assertTrue({"npm", "uv", "go-modules"}.issubset(context.package_managers))
        self.assertEqual(
            set(context.lock_files),
            {"apps/api/uv.lock", "package-lock.json"},
        )
        self.assertTrue({"make", "npm", "python", "go"}.issubset(context.build_systems))
        self.assertEqual(
            set(context.container_files),
            {"Dockerfile", "compose.yaml"},
        )
        self.assertEqual(
            context.kubernetes_files,
            ("deploy/k8s/deployment.yaml",),
        )
        self.assertEqual(context.terraform_files, ("infra/main.tf",))
        self.assertEqual(
            context.cloudformation_files,
            ("deploy/cloudformation.yaml",),
        )
        self.assertEqual(context.openapi_specifications, ("api/openapi.yaml",))
        self.assertEqual(context.test_directories, ("apps/api/tests",))
        self.assertIn("dist/generated.min.js", context.generated_files)
        self.assertIn("src/client.generated.ts", context.generated_files)
        self.assertIn("vendor", context.vendored_dependencies)
        self.assertIn("node_modules", context.vendored_dependencies)

    def test_generated_and_vendored_content_is_safely_excluded_by_default(self) -> None:
        context = self._polyglot_monorepo()

        self.assertNotIn("dist/generated.min.js", context.files)
        self.assertNotIn("src/client.generated.ts", context.files)
        self.assertFalse(any(path.startswith("vendor/") for path in context.files))
        self.assertFalse(
            any(path.startswith("node_modules/") for path in context.files)
        )
        self.assertNotIn("ruby", context.languages)
        self.assertEqual(
            context.exclusion_reasons["vendor"],
            "vendored dependency directory",
        )
        self.assertEqual(
            context.exclusion_reasons["dist/generated.min.js"],
            "generated file",
        )

    def test_explicit_inclusion_can_restore_generated_and_vendored_files(self) -> None:
        self._polyglot_monorepo()

        context = RepositoryContext.from_path(
            self.root,
            exclude_generated=False,
            exclude_vendored=False,
        )

        self.assertIn("dist/generated.min.js", context.files)
        self.assertIn("vendor/example/insecure.py", context.files)
        self.assertIn("node_modules/example/index.js", context.files)

    def test_detects_monorepo_packages_and_dependency_scopes(self) -> None:
        context = self._polyglot_monorepo()
        packages = {package.root: package for package in context.packages}

        self.assertEqual(
            set(packages),
            {".", "apps/api", "apps/web", "services/go"},
        )
        self.assertEqual(packages["apps/api"].name, "api")
        self.assertEqual(packages["apps/web"].name, "web")
        self.assertIn("python", packages["apps/api"].languages)
        self.assertIn("typescript", packages["apps/web"].languages)
        self.assertIn("go", packages["services/go"].languages)

        dependencies = {
            (dependency.name, dependency.scope, dependency.package_root)
            for dependency in context.dependencies
        }
        self.assertIn(("react", DependencyScope.RUNTIME, "."), dependencies)
        self.assertIn(("eslint", DependencyScope.DEVELOPMENT, "."), dependencies)
        self.assertIn(
            ("flask", DependencyScope.RUNTIME, "apps/api"),
            dependencies,
        )
        self.assertIn(
            ("pytest", DependencyScope.DEVELOPMENT, "apps/api"),
            dependencies,
        )
        self.assertIn(
            ("github.com/gin-gonic/gin", DependencyScope.RUNTIME, "services/go"),
            dependencies,
        )

    def test_context_serialisation_is_deterministic(self) -> None:
        context = self._polyglot_monorepo()

        first = context.to_dict()
        second = RepositoryContext.from_path(self.root).to_dict()

        self.assertEqual(first, second)
        self.assertEqual(first["root"], str(self.root.resolve()))
        self.assertEqual(
            [package["root"] for package in first["packages"]],
            [".", "apps/api", "apps/web", "services/go"],
        )

    def test_detects_dependency_scopes_across_common_ecosystems(self) -> None:
        self._write(
            "python/requirements.txt",
            "django==5.2\n",
        )
        self._write(
            "python/requirements-dev.txt",
            "pytest==8.4\n",
        )
        self._write("python/app.py", "import django\n")
        self._write(
            "rust/Cargo.toml",
            """
[package]
name = "worker"
version = "0.1.0"
[dependencies]
axum = "0.8"
[dev-dependencies]
criterion = "0.5"
""",
        )
        self._write("rust/src/main.rs", "fn main() {}\n")
        self._write(
            "ruby/Gemfile",
            """
source "https://rubygems.org"
gem "rails", "8.0"
group :development, :test do
  gem "rspec"
end
""",
        )
        self._write("ruby/app.rb", "puts 'hello'\n")
        self._write(
            "java/pom.xml",
            """
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>api</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>3.5.0</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
""",
        )
        self._write("java/src/Main.java", "class Main {}\n")

        context = RepositoryContext.from_path(self.root)
        dependencies = {
            (item.name, item.scope, item.package_root)
            for item in context.dependencies
        }

        self.assertTrue(
            {"pip", "cargo", "bundler", "maven"}.issubset(
                context.package_managers
            )
        )
        self.assertTrue(
            {"django", "axum", "rails", "spring-boot"}.issubset(
                context.frameworks
            )
        )
        self.assertIn(
            ("django", DependencyScope.RUNTIME, "python"), dependencies
        )
        self.assertIn(
            ("pytest", DependencyScope.DEVELOPMENT, "python"), dependencies
        )
        self.assertIn(("axum", DependencyScope.RUNTIME, "rust"), dependencies)
        self.assertIn(
            ("criterion", DependencyScope.DEVELOPMENT, "rust"), dependencies
        )
        self.assertIn(("rails", DependencyScope.RUNTIME, "ruby"), dependencies)
        self.assertIn(
            ("rspec", DependencyScope.DEVELOPMENT, "ruby"), dependencies
        )
        self.assertIn(
            (
                "org.springframework.boot:spring-boot-starter-web",
                DependencyScope.RUNTIME,
                "java",
            ),
            dependencies,
        )
        self.assertIn(
            (
                "org.junit.jupiter:junit-jupiter",
                DependencyScope.DEVELOPMENT,
                "java",
            ),
            dependencies,
        )


if __name__ == "__main__":
    unittest.main()
