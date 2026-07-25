"""Backward-compatible wrapper for Trust Gate report aggregation."""

from pathlib import Path
import sys


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from trustgate.aggregation import (  # noqa: E402
    SEVERITY_RANK,
    main,
    parse_args,
    parse_bandit,
    parse_gitleaks,
    parse_pip_audit,
    parse_semgrep,
    parse_trivy,
)


__all__ = [
    "SEVERITY_RANK",
    "main",
    "parse_args",
    "parse_bandit",
    "parse_gitleaks",
    "parse_pip_audit",
    "parse_semgrep",
    "parse_trivy",
]


if __name__ == "__main__":
    raise SystemExit(main())
