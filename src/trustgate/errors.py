"""Structured error messages for Trust Gate.

Every error message explains:
1. What failed
2. Why it likely failed
3. Whether security coverage is incomplete
4. Whether the gate is trustworthy
5. How to resolve it
6. Where logs are stored

Users should never need to inspect source code to understand failures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TrustGateError:
    """Structured error with actionable context."""

    what_failed: str
    why: str
    coverage_impact: str | None = None
    gate_trustworthy: bool | None = None
    how_to_resolve: str = ""
    log_location: str | None = None
    exit_code: int = 1
    details: dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        """Render a human-readable error message."""
        lines = [
            f"Error: {self.what_failed}",
            f"  Why: {self.why}",
        ]
        if self.coverage_impact:
            lines.append(f"  Coverage: {self.coverage_impact}")
        if self.gate_trustworthy is not None:
            trust = "yes" if self.gate_trustworthy else "NO — gate result may be unreliable"
            lines.append(f"  Gate trustworthy: {trust}")
        if self.how_to_resolve:
            lines.append(f"  Fix: {self.how_to_resolve}")
        if self.log_location:
            lines.append(f"  Logs: {self.log_location}")
        return "\n".join(lines)


# --- Common error factories ---


def scanner_not_found(scanner: str, *, log_location: str | None = None) -> TrustGateError:
    return TrustGateError(
        what_failed=f"Scanner '{scanner}' not found",
        why=f"The scanner binary '{scanner}' is not installed or not on PATH.",
        coverage_impact=f"Findings from {scanner} are missing — coverage is incomplete.",
        gate_trustworthy=False,
        how_to_resolve=f"Install {scanner} or check your PATH. Run 'trustgate adapter-list' to see available scanners.",
        log_location=log_location,
    )


def scanner_failed(
    scanner: str, *, exit_code: int = 1, log_location: str | None = None,
) -> TrustGateError:
    return TrustGateError(
        what_failed=f"Scanner '{scanner}' exited with code {exit_code}",
        why=f"{scanner} encountered an error during scanning.",
        coverage_impact=f"Findings from {scanner} may be incomplete.",
        gate_trustworthy=False,
        how_to_resolve=f"Check {scanner} logs for details. Ensure the target code is accessible.",
        log_location=log_location,
        exit_code=exit_code,
    )


def sarif_parse_error(
    path: str, *, reason: str = "", log_location: str | None = None,
) -> TrustGateError:
    return TrustGateError(
        what_failed=f"Failed to parse SARIF file: {path}",
        why=reason or "The file is not valid SARIF 2.1.0 JSON.",
        coverage_impact="Findings from this report are not included in the gate decision.",
        gate_trustworthy=False,
        how_to_resolve="Validate the file with 'trustgate sarif --validate'. Check that the scanner produced valid SARIF output.",
        log_location=log_location,
    )


def policy_evaluation_error(
    policy: str, *, reason: str = "", log_location: str | None = None,
) -> TrustGateError:
    return TrustGateError(
        what_failed=f"Policy evaluation failed: {policy}",
        why=reason or "The policy file could not be loaded or contains invalid rules.",
        coverage_impact=None,
        gate_trustworthy=False,
        how_to_resolve="Validate the policy with 'trustgate policy --validate'. Check YAML syntax and rule names.",
        log_location=log_location,
    )


def baseline_missing(
    branch: str = "main", *, log_location: str | None = None,
) -> TrustGateError:
    return TrustGateError(
        what_failed=f"No baseline found for branch '{branch}'",
        why="A baseline comparison was requested but no baseline file exists.",
        coverage_impact="New-only finding detection is unavailable.",
        gate_trustworthy=None,
        how_to_resolve=f"Create a baseline with 'trustgate baseline --create --branch {branch}'.",
        log_location=log_location,
    )


def no_findings_produced(*, log_location: str | None = None) -> TrustGateError:
    return TrustGateError(
        what_failed="No findings were produced by any scanner",
        why="Either no scanners ran successfully, or scanners found zero issues.",
        coverage_impact="If scanners failed silently, security coverage may be zero.",
        gate_trustworthy=None,
        how_to_resolve="Check scanner output. Run 'trustgate plan' to verify scanner selection. Use --verbose for detailed output.",
        log_location=log_location,
        exit_code=0,
    )


def configuration_error(
    setting: str, *, reason: str = "", log_location: str | None = None,
) -> TrustGateError:
    return TrustGateError(
        what_failed=f"Invalid configuration: {setting}",
        why=reason or f"The setting '{setting}' has an invalid value.",
        coverage_impact=None,
        gate_trustworthy=False,
        how_to_resolve="Check the configuration reference: docs/CONFIGURATION_REFERENCE.md",
        log_location=log_location,
    )


def network_unavailable(
    operation: str, *, log_location: str | None = None,
) -> TrustGateError:
    return TrustGateError(
        what_failed=f"Network operation failed: {operation}",
        why="A network request failed. This may be expected in local/offline mode.",
        coverage_impact="Threat intelligence enrichment or metadata upload may be unavailable.",
        gate_trustworthy=True,
        how_to_resolve="If running offline, use '--offline-threat-data' for cached threat intelligence. Check deployment mode with 'trustgate --version'.",
        log_location=log_location,
    )
