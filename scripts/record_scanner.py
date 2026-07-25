#!/usr/bin/env python3
"""Compatibility entry point for external scanner-health recording."""

import argparse
from pathlib import Path
import sys


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from trustgate.scanners.cli import add_record_arguments, run_record  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Record health for a scanner executed by an external Action."
    )
    add_record_arguments(parser)
    return run_record(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
