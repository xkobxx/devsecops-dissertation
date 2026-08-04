"""Default-branch baseline generation and differential comparison."""

from .creation import (
    BaselineCompatibilityError,
    BaselineError,
    BaselineIntegrityError,
    create_baseline,
    verify_baseline,
)
from .comparison import compare_to_baseline
from .gate import BaselineGateError, GateMode, evaluate_gate

__all__ = [
    "BaselineError",
    "BaselineCompatibilityError",
    "BaselineIntegrityError",
    "BaselineGateError",
    "GateMode",
    "create_baseline",
    "compare_to_baseline",
    "evaluate_gate",
    "verify_baseline",
]
