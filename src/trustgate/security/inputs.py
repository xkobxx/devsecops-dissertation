"""Validate untrusted GitHub Action and DAST inputs before use."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
import ipaddress
import os
from pathlib import Path, PurePath
import re
import sys
from urllib.parse import urlsplit


FAIL_ON_VALUES = ("critical", "high", "medium", "low", "none")
SCANNER_FAILURE_POLICIES = ("fail", "warn", "ignore")
SCANNER_NAMES = ("bandit", "semgrep", "pip-audit", "trivy", "gitleaks")
BOOLEAN_VALUES = ("false", "true")
SEVERITY_BASES = ("normalised", "original")
MAX_TIMEOUT_SECONDS = Decimal("3600")
MAX_LICENSE_LENGTH = 8192
MAX_PATH_LENGTH = 1024
MAX_URL_LENGTH = 2048
SAFE_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
UNSAFE_PATH_CHARACTERS = frozenset("$`;|&<>(){}[]!*?\"'\\")


class InputValidationError(ValueError):
    """Raised when untrusted workflow configuration is unsafe."""


def _require_environment(environment: Mapping[str, str], name: str) -> str:
    try:
        return environment[name]
    except KeyError as error:
        raise InputValidationError(
            f"Invalid workflow environment: {name} is required."
        ) from error


def _validate_bounded_text(
    value: str,
    *,
    label: str,
    maximum_length: int,
) -> str:
    if len(value) > maximum_length:
        raise InputValidationError(
            f"Invalid {label}: maximum length is {maximum_length} characters."
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise InputValidationError(f"Invalid {label}: control characters are forbidden.")
    return value


def _contains_unsafe_path_syntax(value: str) -> bool:
    return any(character in UNSAFE_PATH_CHARACTERS for character in value)


def validate_workspace_path(
    workspace: Path,
    value: str,
    *,
    label: str = "Target path",
    require_file: bool = False,
) -> str:
    """Return a canonical relative path that cannot escape the workspace."""

    value = _validate_bounded_text(
        value,
        label=label,
        maximum_length=MAX_PATH_LENGTH,
    )
    if not value:
        raise InputValidationError(f"Invalid {label}: value cannot be empty.")
    if _contains_unsafe_path_syntax(value):
        raise InputValidationError(f"Invalid {label}: unsafe path syntax is forbidden.")

    candidate_path = Path(value)
    parts = PurePath(value).parts
    if candidate_path.is_absolute() or ".." in parts:
        raise InputValidationError(f"Invalid {label}: path must remain within workspace.")
    if any(part.startswith("-") for part in parts if part not in {".", ""}):
        raise InputValidationError(
            f"Invalid {label}: path segments cannot begin with '-'."
        )

    try:
        workspace_path = workspace.resolve(strict=True)
    except OSError as error:
        raise InputValidationError(
            f"Invalid workspace: {type(error).__name__}: {error}"
        ) from error
    if not workspace_path.is_dir():
        raise InputValidationError("Invalid workspace: expected a directory.")

    try:
        resolved = (workspace_path / candidate_path).resolve(strict=True)
    except OSError as error:
        raise InputValidationError(
            f"Invalid {label}: path does not exist in workspace."
        ) from error
    try:
        relative = resolved.relative_to(workspace_path)
    except ValueError as error:
        raise InputValidationError(
            f"Invalid {label}: resolved path escapes the workspace."
        ) from error

    if require_file and not resolved.is_file():
        raise InputValidationError(f"Invalid {label}: expected a workspace file.")
    return "." if relative == Path(".") else relative.as_posix()


def _validate_choice(value: str, *, label: str, choices: Sequence[str]) -> str:
    if value not in choices:
        allowed = ", ".join(choices)
        raise InputValidationError(
            f"Invalid {label} {value!r}; expected one of: {allowed}."
        )
    return value


def _validate_optional_scanners(value: str) -> str:
    if not value.strip():
        return ""
    scanners = [scanner.strip() for scanner in value.split(",")]
    if (
        any(not scanner or scanner not in SCANNER_NAMES for scanner in scanners)
        or len(scanners) != len(set(scanners))
    ):
        raise InputValidationError(
            "Invalid optional-scanners value; use unique documented scanner names."
        )
    return ",".join(scanners)


def _validate_timeout(value: str) -> str:
    try:
        timeout = Decimal(value)
    except InvalidOperation as error:
        raise InputValidationError(
            "Invalid scanner-timeout-seconds value."
        ) from error
    if not timeout.is_finite() or timeout <= 0 or timeout > MAX_TIMEOUT_SECONDS:
        raise InputValidationError(
            "Invalid scanner-timeout-seconds; expected a finite value "
            f"greater than 0 and no greater than {MAX_TIMEOUT_SECONDS}."
        )
    if timeout == timeout.to_integral_value():
        return str(int(timeout))
    return format(timeout.normalize(), "f")


def _validate_license_input(value: str) -> None:
    _validate_bounded_text(
        value,
        label="licence key input",
        maximum_length=MAX_LICENSE_LENGTH,
    )


def validate_artifact_name(value: str) -> str:
    """Accept a conservative portable artifact-name subset."""

    if not SAFE_ARTIFACT_NAME.fullmatch(value):
        raise InputValidationError(
            "Invalid artifact name; use 1-128 ASCII letters, numbers, dots, "
            "underscores or hyphens, beginning with a letter or number."
        )
    return value


def validate_dast_url(value: str, *, allow_private: bool = False) -> str:
    """Validate an HTTP(S) DAST target and reject common SSRF destinations."""

    value = _validate_bounded_text(
        value,
        label="DAST URL",
        maximum_length=MAX_URL_LENGTH,
    )
    if any(character.isspace() for character in value):
        raise InputValidationError("Invalid DAST URL: whitespace must be encoded.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise InputValidationError(f"Invalid DAST URL: {error}") from error

    allowed_schemes = {"https", "http"} if allow_private else {"https"}
    if parsed.scheme.lower() not in allowed_schemes:
        raise InputValidationError(
            "Invalid DAST URL: HTTPS is required unless private testing is explicit."
        )
    if not parsed.hostname:
        raise InputValidationError("Invalid DAST URL: hostname is required.")
    if parsed.username is not None or parsed.password is not None:
        raise InputValidationError("Invalid DAST URL: credentials are forbidden.")
    if parsed.fragment:
        raise InputValidationError("Invalid DAST URL: fragments are forbidden.")
    if port is not None and not 1 <= port <= 65535:
        raise InputValidationError("Invalid DAST URL: port is outside 1-65535.")

    hostname = parsed.hostname.rstrip(".").lower()
    if not allow_private:
        if (
            hostname == "localhost"
            or hostname.endswith(".localhost")
            or hostname.endswith(".local")
        ):
            raise InputValidationError("Invalid DAST URL: private host is forbidden.")
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            if "." not in hostname:
                raise InputValidationError(
                    "Invalid DAST URL: a public fully qualified hostname is required."
                )
        else:
            if not address.is_global:
                raise InputValidationError(
                    "Invalid DAST URL: private or reserved address is forbidden."
                )
    return value


def validate_action_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """Validate every composite Action input and return canonical outputs."""

    workspace = Path(_require_environment(environment, "GITHUB_WORKSPACE"))
    target = validate_workspace_path(
        workspace,
        _require_environment(environment, "TRUSTGATE_TARGET"),
    )
    fail_on = _validate_choice(
        _require_environment(environment, "TRUSTGATE_FAIL_ON"),
        label="fail-on",
        choices=FAIL_ON_VALUES,
    )
    failure_policy = _validate_choice(
        _require_environment(environment, "TRUSTGATE_SCANNER_FAILURE_POLICY"),
        label="scanner-failure-policy",
        choices=SCANNER_FAILURE_POLICIES,
    )
    severity_basis = _validate_choice(
        _require_environment(environment, "TRUSTGATE_SEVERITY_BASIS"),
        label="severity-basis",
        choices=SEVERITY_BASES,
    )
    optional_scanners = _validate_optional_scanners(
        _require_environment(environment, "TRUSTGATE_OPTIONAL_SCANNERS")
    )
    timeout = _validate_timeout(
        _require_environment(environment, "TRUSTGATE_SCANNER_TIMEOUT")
    )
    redact_sensitive_content = _validate_choice(
        _require_environment(
            environment,
            "TRUSTGATE_REDACT_SENSITIVE_CONTENT",
        ),
        label="redact-sensitive-content",
        choices=BOOLEAN_VALUES,
    )
    artifact_name = validate_artifact_name(
        _require_environment(environment, "TRUSTGATE_ARTIFACT_NAME")
    )
    _validate_license_input(
        _require_environment(environment, "TRUSTGATE_LICENSE_KEY")
    )
    return {
        "target": target,
        "fail-on": fail_on,
        "scanner-failure-policy": failure_policy,
        "severity-basis": severity_basis,
        "optional-scanners": optional_scanners,
        "scanner-timeout-seconds": timeout,
        "redact-sensitive-content": redact_sensitive_content,
        "artifact-name": artifact_name,
    }


def _write_outputs(path: Path, outputs: Mapping[str, str]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for name, value in outputs.items():
            handle.write(f"{name}={value}\n")


def _run_action(environment: Mapping[str, str]) -> int:
    outputs = validate_action_environment(environment)
    _write_outputs(Path(_require_environment(environment, "GITHUB_OUTPUT")), outputs)
    print("Trust Gate Action inputs are valid.")
    return 0


def _run_dast(environment: Mapping[str, str], *, allow_private: bool) -> int:
    workspace = Path(_require_environment(environment, "GITHUB_WORKSPACE"))
    validate_dast_url(
        _require_environment(environment, "TRUSTGATE_DAST_URL"),
        allow_private=allow_private,
    )
    validate_workspace_path(
        workspace,
        _require_environment(environment, "TRUSTGATE_DAST_RULES_FILE"),
        label="DAST rules file",
        require_file=True,
    )
    print("DAST URL and rules file are valid.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate untrusted Trust Gate workflow inputs."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("action", help="Validate composite Action environment inputs.")
    dast = commands.add_parser("dast", help="Validate DAST URL and rules-file inputs.")
    dast.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow HTTP and private targets for an explicitly local test.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "action":
            return _run_action(os.environ)
        return _run_dast(os.environ, allow_private=args.allow_private)
    except InputValidationError as error:
        print(f"Input validation failed: {error}", file=sys.stderr)
        return 2


__all__ = [
    "InputValidationError",
    "build_parser",
    "main",
    "validate_action_environment",
    "validate_artifact_name",
    "validate_dast_url",
    "validate_workspace_path",
]
