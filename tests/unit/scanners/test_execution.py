import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

from datetime import datetime, timezone

from trustgate.scanners.execution import execute_scanner, record_external_scanner
from trustgate.scanners.models import ParserStatus, ScannerState


class ScannerExecutionTests(unittest.TestCase):
    def test_success_records_timing_version_report_and_separate_logs(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            report = workspace / "reports" / "scanner.json"
            metadata = workspace / "reports" / "scanner_execution.json"
            logs = workspace / "logs"
            script = (
                "from pathlib import Path; import sys; "
                "Path(sys.argv[1]).parent.mkdir(parents=True, exist_ok=True); "
                "Path(sys.argv[1]).write_text('{}'); "
                "print('scanner stdout'); "
                "print('scanner stderr', file=sys.stderr)"
            )

            result = execute_scanner(
                scanner="bandit",
                command=[sys.executable, "-c", script, str(report)],
                report_path=report,
                metadata_path=metadata,
                logs_dir=logs,
                timeout_seconds=5,
                finding_exit_codes={1},
                version="1.9.4",
            )

            self.assertEqual(result.state, ScannerState.CLEAN)
            self.assertEqual(result.exit_code, 0)
            self.assertFalse(result.timed_out)
            self.assertTrue(result.report_produced)
            self.assertEqual(result.parser_status, ParserStatus.NOT_RUN)
            self.assertEqual(result.version, "1.9.4")
            self.assertGreaterEqual(result.ended_at, result.started_at)
            self.assertEqual(Path(result.stdout_path).read_text(), "scanner stdout\n")
            self.assertEqual(Path(result.stderr_path).read_text(), "scanner stderr\n")
            self.assertEqual(json.loads(metadata.read_text())["state"], "CLEAN")

    def test_findings_exit_code_is_healthy_findings_not_a_crash(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            report = workspace / "scanner.json"
            script = (
                "from pathlib import Path; import sys; "
                "Path(sys.argv[1]).write_text('{}'); raise SystemExit(1)"
            )

            result = execute_scanner(
                scanner="bandit",
                command=[sys.executable, "-c", script, str(report)],
                report_path=report,
                metadata_path=workspace / "execution.json",
                logs_dir=workspace / "logs",
                timeout_seconds=5,
                finding_exit_codes={1},
                version="1.9.4",
            )

            self.assertEqual(result.state, ScannerState.FINDINGS)
            self.assertEqual(result.exit_code, 1)
            self.assertTrue(result.healthy)

    def test_stdout_can_be_persisted_as_the_native_report(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            report = workspace / "grype.json"

            result = execute_scanner(
                scanner="grype",
                command=[sys.executable, "-c", "print('{\"matches\": []}')"],
                report_path=report,
                metadata_path=workspace / "execution.json",
                logs_dir=workspace / "logs",
                timeout_seconds=5,
                finding_exit_codes=set(),
                version="1.0.0",
                report_from_stdout=True,
            )

            self.assertEqual(result.state, ScannerState.CLEAN)
            self.assertEqual(json.loads(report.read_text()), {"matches": []})

    def test_crash_is_failed_even_if_it_writes_a_report(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            report = workspace / "scanner.json"
            script = (
                "from pathlib import Path; import sys; "
                "Path(sys.argv[1]).write_text('{}'); raise SystemExit(2)"
            )

            result = execute_scanner(
                scanner="bandit",
                command=[sys.executable, "-c", script, str(report)],
                report_path=report,
                metadata_path=workspace / "execution.json",
                logs_dir=workspace / "logs",
                timeout_seconds=5,
                finding_exit_codes={1},
                version="1.9.4",
            )

            self.assertEqual(result.state, ScannerState.FAILED_SCANNER)
            self.assertEqual(result.exit_code, 2)
            self.assertTrue(result.report_produced)
            self.assertFalse(result.healthy)

    def test_timeout_is_recorded_and_cannot_be_clean(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)

            result = execute_scanner(
                scanner="semgrep",
                command=[sys.executable, "-c", "import time; time.sleep(2)"],
                report_path=workspace / "scanner.json",
                metadata_path=workspace / "execution.json",
                logs_dir=workspace / "logs",
                timeout_seconds=0.05,
                finding_exit_codes=set(),
                version="1.165.0",
            )

            self.assertEqual(result.state, ScannerState.FAILED_SCANNER)
            self.assertTrue(result.timed_out)
            self.assertIsNone(result.exit_code)
            self.assertFalse(result.report_produced)
            self.assertIn("timed out", result.error.lower())

    def test_external_action_failure_is_recorded_even_with_a_report(self) -> None:
        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            report = workspace / "trivy.json"
            report.write_text('{"Results":[]}')
            started_at = datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc)

            result = record_external_scanner(
                scanner="trivy",
                outcome="failure",
                report_path=report,
                metadata_path=workspace / "trivy_execution.json",
                started_at=started_at,
                version="0.69.3",
            )

            self.assertEqual(result.state, ScannerState.FAILED_SCANNER)
            self.assertEqual(result.exit_code, 2)
            self.assertEqual(result.started_at, started_at)
            self.assertTrue(result.report_produced)
            self.assertEqual(result.version, "0.69.3")


if __name__ == "__main__":
    unittest.main()
