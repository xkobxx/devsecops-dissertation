from datetime import datetime, timezone
import unittest

from trustgate.scanners.models import ParserStatus, ScannerResult, ScannerState


class ScannerResultTests(unittest.TestCase):
    def test_serializes_complete_scanner_health_evidence(self) -> None:
        started = datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc)
        ended = datetime(2026, 7, 24, 10, 0, 2, tzinfo=timezone.utc)
        result = ScannerResult(
            scanner="Bandit",
            state=ScannerState.FINDINGS,
            started_at=started,
            ended_at=ended,
            exit_code=1,
            timed_out=False,
            report_path="reports/bandit_report.json",
            report_produced=True,
            parser_status=ParserStatus.SUCCESS,
            version="1.9.4",
            stdout_path="logs/bandit.stdout.log",
            stderr_path="logs/bandit.stderr.log",
            finding_count=2,
        )

        serialized = result.to_dict()

        self.assertEqual(serialized["state"], "FINDINGS")
        self.assertEqual(serialized["parser_status"], "SUCCESS")
        self.assertEqual(serialized["duration_seconds"], 2.0)
        self.assertEqual(serialized["finding_count"], 2)
        self.assertEqual(ScannerResult.from_dict(serialized), result)

    def test_failed_scanner_is_never_healthy(self) -> None:
        now = datetime.now(timezone.utc)
        result = ScannerResult(
            scanner="Semgrep",
            state=ScannerState.FAILED_SCANNER,
            started_at=now,
            ended_at=now,
            exit_code=2,
            timed_out=False,
            report_path="reports/semgrep_report.json",
            report_produced=False,
            parser_status=ParserStatus.NOT_RUN,
        )

        self.assertFalse(result.healthy)


if __name__ == "__main__":
    unittest.main()
