from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from trustgate.reachability.dependency import analyze_dependency_reachability
from trustgate.reachability.models import ReachabilityStatus

from tests.unit.schemas.test_schema_contracts import valid_finding


def dependency_finding(*, ecosystem: str = "PyPI") -> dict[str, object]:
    finding = valid_finding()
    finding.update(
        {
            "category": "dependency",
            "file": "requirements.txt",
            "dependency": {
                "name": "demo",
                "version": "1.0.0",
                "ecosystem": ecosystem,
                "purl": f"pkg:{ecosystem.lower()}/demo@1.0.0",
                "direct": None,
            },
            "dependency_scope": "unknown",
            "symbol": None,
            "reachability": "unknown",
        }
    )
    return finding


class DependencyReachabilityTests(unittest.TestCase):
    def test_confirms_installed_imported_called_runtime_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("demo==1.0.0\n")
            (root / "app.py").write_text(
                "import demo\n\ndef handler():\n    return demo.danger()\n"
            )

            result = analyze_dependency_reachability(
                dependency_finding(),
                repository_root=root,
                vulnerable_symbols=("danger",),
                deployed_packages=("demo",),
            )

        self.assertEqual(result["status"], ReachabilityStatus.CONFIRMED_REACHABLE)
        self.assertTrue(result["package_installed"])
        self.assertEqual(result["dependency_relationship"], "direct")
        self.assertTrue(result["imported"])
        self.assertTrue(result["vulnerable_symbol_called"])
        self.assertEqual(result["dependency_scope"], "runtime")
        self.assertTrue(result["included_in_deployed_artifact"])
        self.assertTrue(result["call_path_exists"])
        self.assertFalse(result["analysis_incomplete"])
        self.assertEqual(
            [step["kind"] for step in result["analysed_call_path"]],
            ["manifest", "import", "call"],
        )

    def test_lock_only_dependency_is_transitive_and_development_is_not_deployed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "dependencies": {"parent": "1.0.0"},
                        "devDependencies": {"demo": "1.0.0"},
                    }
                )
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "packages": {
                            "": {"dependencies": {"parent": "1.0.0"}},
                            "node_modules/demo": {"version": "1.0.0"},
                        }
                    }
                )
            )

            development = analyze_dependency_reachability(
                dependency_finding(ecosystem="npm"),
                repository_root=root,
                deployed_packages=("parent",),
            )

            transitive_finding = dependency_finding(ecosystem="npm")
            transitive_finding["dependency"]["name"] = "nested"
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "packages": {
                            "": {"dependencies": {"parent": "1.0.0"}},
                            "node_modules/nested": {"version": "1.0.0"},
                        }
                    }
                )
            )
            transitive = analyze_dependency_reachability(
                transitive_finding,
                repository_root=root,
                deployed_packages=("parent",),
            )

        self.assertEqual(development["dependency_scope"], "development")
        self.assertFalse(development["included_in_deployed_artifact"])
        self.assertEqual(transitive["dependency_relationship"], "transitive")
        self.assertTrue(transitive["package_installed"])

    def test_no_path_found_is_uncertain_and_never_not_exploitable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("demo==1.0.0\n")
            (root / "app.py").write_text("print('no dependency import')\n")

            result = analyze_dependency_reachability(
                dependency_finding(),
                repository_root=root,
                vulnerable_symbols=("danger",),
                deployed_packages=("demo",),
            )

        self.assertEqual(result["status"], ReachabilityStatus.NO_PATH_FOUND)
        self.assertFalse(result["call_path_exists"])
        self.assertTrue(result["dynamic_behaviour_unknown"])
        self.assertNotIn("not exploitable", result["explanation"].lower())
        self.assertTrue(result["analysed_files"])
        self.assertTrue(result["limitations"])

    def test_missing_symbol_or_deployment_evidence_is_explicitly_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("demo==1.0.0\n")
            (root / "app.py").write_text("import demo\n")

            result = analyze_dependency_reachability(
                dependency_finding(),
                repository_root=root,
            )

        self.assertEqual(result["status"], ReachabilityStatus.ANALYSIS_INCOMPLETE)
        self.assertTrue(result["analysis_incomplete"])
        self.assertIsNone(result["vulnerable_symbol_called"])
        self.assertIsNone(result["included_in_deployed_artifact"])
        self.assertTrue(
            any("dynamic" in item.lower() for item in result["limitations"])
        )

    def test_non_dependency_finding_is_not_analysed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = analyze_dependency_reachability(
                valid_finding(),
                repository_root=Path(directory),
            )

        self.assertEqual(result["status"], ReachabilityStatus.NOT_ANALYSED)
        self.assertTrue(result["analysis_incomplete"])


if __name__ == "__main__":
    unittest.main()
