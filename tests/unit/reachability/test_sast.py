from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from trustgate.reachability.sast import (
    analyze_python_source_to_sink,
    apply_source_to_sink_analysis,
)

from tests.unit.schemas.test_schema_contracts import valid_finding


class SourceToSinkAnalysisTests(unittest.TestCase):
    def test_identifies_sources_sanitizers_sinks_and_intra_file_trace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "from flask import request\n"
                "from markupsafe import escape\n\n"
                "@app.route('/search')\n"
                "def search():\n"
                "    query = request.args.get('q')\n"
                "    cursor.execute(query)\n\n"
                "@app.route('/safe')\n"
                "def safe():\n"
                "    query = request.args.get('q')\n"
                "    cleaned = escape(query)\n"
                "    cursor.execute(cleaned)\n"
            )

            report = analyze_python_source_to_sink(root)

        self.assertEqual(report["support"], "supported")
        self.assertTrue(report["identified_sources"])
        self.assertTrue(report["identified_sanitizers"])
        self.assertTrue(report["identified_sinks"])
        self.assertEqual(len(report["paths"]), 1)
        path = report["paths"][0]
        self.assertTrue(path["intra_file"])
        self.assertFalse(path["cross_file"])
        self.assertEqual(path["framework_route"]["endpoint"], "/search")
        self.assertFalse(path["authentication_required"])
        self.assertEqual(path["authorization_checks"], [])
        self.assertEqual(path["path_confidence"], 0.95)
        self.assertEqual(path["source"]["symbol"], "request.args['q']")
        self.assertEqual(
            [step["kind"] for step in path["data_flow"]],
            ["source", "propagation", "sink"],
        )

    def test_traces_cross_file_flow_routing_authentication_and_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "from flask import request\n"
                "from service import process\n\n"
                "@app.post('/admin/run')\n"
                "@login_required\n"
                "@roles_required('admin')\n"
                "def run_command():\n"
                "    return process(request.form['command'])\n"
            )
            (root / "service.py").write_text(
                "import os\n\n"
                "def process(value):\n"
                "    return os.system(value)\n"
            )

            report = analyze_python_source_to_sink(root)

        self.assertEqual(len(report["paths"]), 1)
        path = report["paths"][0]
        self.assertTrue(path["cross_file"])
        self.assertFalse(path["intra_file"])
        self.assertEqual(path["framework_route"]["endpoint"], "/admin/run")
        self.assertEqual(path["framework_route"]["methods"], ["POST"])
        self.assertTrue(path["authentication_required"])
        self.assertEqual(path["authorization_checks"], ["roles_required"])
        self.assertEqual(path["path_confidence"], 0.8)
        self.assertEqual(
            {step["file"] for step in path["data_flow"]},
            {"app.py", "service.py"},
        )

    def test_supported_finding_receives_explainable_trace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "from flask import request\n\n"
                "def search():\n"
                "    value = request.args['q']\n"
                "    cursor.execute(value)\n"
            )
            finding = valid_finding()
            finding.update(
                {
                    "file": "app.py",
                    "start_line": 5,
                    "end_line": 5,
                    "source": "request.args",
                    "sink": "cursor.execute",
                    "data_flow": [],
                }
            )

            analyzed = apply_source_to_sink_analysis([finding], root)[0]

        metadata = analyzed["source_to_sink_analysis"]
        self.assertEqual(metadata["support"], "supported")
        self.assertEqual(metadata["status"], "path-found")
        self.assertTrue(analyzed["data_flow"])
        self.assertEqual(analyzed["reachability"], "reachable")

    def test_unsupported_language_is_marked_explicitly(self) -> None:
        finding = valid_finding()
        finding["file"] = "src/main.go"
        with tempfile.TemporaryDirectory() as directory:
            analyzed = apply_source_to_sink_analysis(
                [finding], Path(directory)
            )[0]

        metadata = analyzed["source_to_sink_analysis"]
        self.assertEqual(metadata["support"], "unsupported")
        self.assertEqual(metadata["status"], "not-analysed")
        self.assertTrue(metadata["analysis_incomplete"])
        self.assertIn("Python", metadata["limitations"][0])

    def test_does_not_attach_an_unrelated_path_from_the_same_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "from flask import request\n\n"
                "def search():\n"
                "    value = request.args['q']\n"
                "    cursor.execute(value)\n"
            )
            finding = valid_finding()
            finding.update(
                {
                    "file": "app.py",
                    "start_line": 20,
                    "end_line": 20,
                    "source": "uploaded_file",
                    "sink": "hashlib.md5",
                }
            )

            analyzed = apply_source_to_sink_analysis([finding], root)[0]

        self.assertEqual(
            analyzed["source_to_sink_analysis"]["status"], "no-path-found"
        )
        self.assertEqual(analyzed["data_flow"], [])

    def test_parse_failure_is_visible_as_incomplete_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "broken.py").write_text("def broken(:\n")

            report = analyze_python_source_to_sink(root)

        self.assertEqual(report["support"], "incomplete")
        self.assertTrue(report["analysis_incomplete"])
        self.assertEqual(report["parse_failures"], ["broken.py"])
        self.assertTrue(report["limitations"])


if __name__ == "__main__":
    unittest.main()
