from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

try:
    from trustgate.dast import (
        DastConfig,
        DastConfigurationError,
        DastMode,
        ScanMode,
        TargetEnvironment,
        build_dast_plan,
    )
except ImportError:
    DastConfig = None
    DastConfigurationError = ValueError
    DastMode = None
    ScanMode = None
    TargetEnvironment = None
    build_dast_plan = None


class DastConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertIsNotNone(DastConfig, "Phase 9 DAST configuration is missing")

    def _config(self, **overrides):
        values = {
            "target_url": "https://preview.example.test",
            "mode": DastMode.BASELINE,
            "scan_mode": ScanMode.SAFE,
            "environment": TargetEnvironment.PREVIEW,
            "scope_allowlist": ("preview.example.test",),
            "rate_limit_per_second": 5,
            "request_limit": 500,
            "max_duration_seconds": 300,
            "public_target_acknowledged": True,
        }
        values.update(overrides)
        return DastConfig(**values)

    def test_baseline_safe_plan_is_passive_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan = build_dast_plan(self._config(), workspace=Path(directory))

        job_types = [job["type"] for job in plan.automation["jobs"]]
        self.assertIn("spider", job_types)
        self.assertIn("passiveScan-wait", job_types)
        self.assertNotIn("activeScan", job_types)
        self.assertIn("report", job_types)
        self.assertEqual(plan.rate_limit_per_second, 5)
        self.assertEqual(plan.request_limit, 500)
        self.assertEqual(plan.timeout_seconds, 300)
        self.assertIn("MAX_REQUESTS = 500", plan.sender_gate_script)
        self.assertIn("MIN_INTERVAL_MS = 200", plan.sender_gate_script)
        self.assertIn('Java.type("java.lang.System")', plan.sender_gate_script)
        exit_job = next(
            job for job in plan.automation["jobs"] if job["type"] == "exitStatus"
        )
        self.assertEqual(exit_job["parameters"]["errorLevel"], "High")
        self.assertEqual(exit_job["parameters"]["warnLevel"], "Medium")

    def test_api_mode_requires_workspace_spec_and_imports_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            spec = workspace / "openapi.yaml"
            spec.write_text("openapi: 3.0.0\n")
            plan = build_dast_plan(
                self._config(mode=DastMode.API, openapi_path="openapi.yaml"),
                workspace=workspace,
            )

            openapi_job = next(
                job for job in plan.automation["jobs"] if job["type"] == "openapi"
            )

        self.assertEqual(openapi_job["parameters"]["apiFile"], "openapi.yaml")
        self.assertNotIn("activeScan", [job["type"] for job in plan.automation["jobs"]])

    def test_api_mode_rejects_missing_or_outside_specification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            outside = root / "openapi.yaml"
            outside.write_text("openapi: 3.0.0\n")
            for value in (None, "missing.yaml", "../openapi.yaml"):
                with self.subTest(value=value):
                    with self.assertRaises(DastConfigurationError):
                        build_dast_plan(
                            self._config(mode=DastMode.API, openapi_path=value),
                            workspace=workspace,
                        )

    def test_target_must_match_a_non_global_scope_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            for allowlist in ((), ("*",), ("api.example.test",)):
                with self.subTest(allowlist=allowlist):
                    with self.assertRaisesRegex(
                        DastConfigurationError, "allowlist|allowlisted"
                    ):
                        build_dast_plan(
                            self._config(scope_allowlist=allowlist),
                            workspace=workspace,
                        )

    def test_explicit_local_mode_accepts_a_private_localhost_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan = build_dast_plan(
                self._config(
                    target_url="http://localhost:5000",
                    environment=TargetEnvironment.LOCAL,
                    scope_allowlist=("localhost",),
                    public_target_acknowledged=False,
                    allow_private_target=True,
                ),
                workspace=Path(directory),
            )

        self.assertEqual(plan.target_host, "localhost")
        self.assertEqual(plan.config.environment, TargetEnvironment.LOCAL)

    def test_active_scan_requires_explicit_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            with self.assertRaisesRegex(DastConfigurationError, "active"):
                build_dast_plan(
                    self._config(scan_mode=ScanMode.ACTIVE), workspace=workspace
                )

            plan = build_dast_plan(
                self._config(
                    scan_mode=ScanMode.ACTIVE,
                    active_scan_acknowledged=True,
                ),
                workspace=workspace,
            )

        self.assertIn("activeScan", [job["type"] for job in plan.automation["jobs"]])

    def test_production_and_public_targets_require_separate_acknowledgements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            with self.assertRaisesRegex(DastConfigurationError, "public"):
                build_dast_plan(
                    self._config(public_target_acknowledged=False),
                    workspace=workspace,
                )
            with self.assertRaisesRegex(DastConfigurationError, "production"):
                build_dast_plan(
                    self._config(
                        environment=TargetEnvironment.PRODUCTION,
                        production_scan_acknowledged=False,
                    ),
                    workspace=workspace,
                )

    def test_authenticated_plan_references_environment_without_secret_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan = build_dast_plan(
                self._config(auth_type="bearer"), workspace=Path(directory)
            )

        rendered = str(plan.automation)
        self.assertIn("TRUSTGATE_DAST_AUTH_SECRET", rendered)
        self.assertNotIn("super-secret-token", rendered)
        self.assertEqual(plan.redacted_configuration["auth_secret"], "[REDACTED]")
        self.assertNotIn("auth_secret", repr(plan.config))

    def test_limits_are_positive_and_capped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            cases = (
                {"rate_limit_per_second": 0},
                {"rate_limit_per_second": 101},
                {"request_limit": 0},
                {"request_limit": 100_001},
                {"max_duration_seconds": 0},
                {"max_duration_seconds": 3_601},
            )
            for overrides in cases:
                with self.subTest(overrides=overrides):
                    with self.assertRaises(DastConfigurationError):
                        build_dast_plan(
                            self._config(**overrides), workspace=workspace
                        )


if __name__ == "__main__":
    unittest.main()
