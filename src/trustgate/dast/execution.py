"""Publish and execute secret-safe DAST plans."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Mapping, Sequence
import re

from trustgate.scanners.execution import execute_scanner
from trustgate.scanners.models import ScannerResult

from .models import DastConfigurationError, DastPlan


_IMMUTABLE_IMAGE = re.compile(
    r"^[A-Za-z0-9._/:~-]+@sha256:[0-9a-f]{64}$"
)
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def build_zap_container_command(
    image: str,
    *,
    workspace: Path,
    auth_secret_environment: str | None = None,
) -> tuple[str, ...]:
    """Return a digest-pinned Docker prefix without embedding credentials."""

    if not _IMMUTABLE_IMAGE.fullmatch(image):
        raise DastConfigurationError(
            "ZAP container image must use an immutable sha256 digest."
        )
    root = Path(workspace).resolve()
    if not root.is_dir():
        raise DastConfigurationError("DAST container workspace must be a directory.")
    command = [
        "docker",
        "run",
        "--rm",
        "--volume",
        f"{root}:/zap/wrk:rw",
    ]
    if auth_secret_environment is not None:
        if not _ENVIRONMENT_NAME.fullmatch(auth_secret_environment):
            raise DastConfigurationError(
                "DAST authentication secret environment name is invalid."
            )
        command.extend(["--env", auth_secret_environment])
    command.extend([image, "zap.sh"])
    return tuple(command)


def write_dast_plan(plan: DastPlan, output_path: Path) -> Path:
    """Atomically publish JSON-compatible YAML for the ZAP framework."""

    destination = Path(output_path).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(plan.automation, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return destination


def execute_dast_plan(
    plan: DastPlan,
    *,
    plan_path: Path,
    report_path: Path,
    metadata_path: Path,
    logs_dir: Path,
    zap_executable: str = "zap.sh",
    command_prefix: Sequence[str] | None = None,
    runtime_plan_path: str | Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> ScannerResult:
    """Run ZAP with a hard timeout and redact authentication material."""

    process_environment = dict(os.environ if environment is None else environment)
    redactions: tuple[str, ...] = ()
    if plan.authenticated:
        name = plan.config.auth_secret_environment
        secret = process_environment.get(name)
        if not secret:
            raise DastConfigurationError(
                f"Authenticated DAST requires the {name} environment variable."
            )
        redactions = (secret,)
    return execute_scanner(
        scanner="zap",
        command=[
            *(command_prefix or (zap_executable,)),
            "-cmd",
            "-autorun",
            str(runtime_plan_path or Path(plan_path).resolve()),
        ],
        report_path=report_path,
        metadata_path=metadata_path,
        logs_dir=logs_dir,
        timeout_seconds=plan.timeout_seconds,
        finding_exit_codes={1, 2},
        environment=process_environment,
        redactions=redactions,
    )


__all__ = [
    "build_zap_container_command",
    "execute_dast_plan",
    "write_dast_plan",
]
