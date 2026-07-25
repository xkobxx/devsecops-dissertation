"""Aggregate scanner reports through the registered adapter catalogue.

Parser exports remain available for compatibility, but their implementation
lives with the built-in scanner adapters.
"""

from trustgate.adapters.builtin.legacy import (
    SEVERITY_RANK,
    add_arguments,
    build_parser,
    main,
    parse_args,
    parse_bandit,
    parse_gitleaks,
    parse_pip_audit,
    parse_semgrep,
    parse_trivy,
    run,
)

__all__ = [
    "SEVERITY_RANK",
    "add_arguments",
    "build_parser",
    "main",
    "parse_args",
    "parse_bandit",
    "parse_gitleaks",
    "parse_pip_audit",
    "parse_semgrep",
    "parse_trivy",
    "run",
]
