"""Backward-compatible command-line wrapper for licence verification."""

import argparse
from pathlib import Path
import sys


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from trustgate.licensing import (  # noqa: E402
    PUBLIC_KEY_B64,
    b64u_decode,
    verify,
)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Verify a Trust Gate licence key offline.")
    parser.add_argument(
        "--license-key",
        default="",
        help="Licence key to verify (empty = free tier)",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    valid, reason, payload = verify(args.license_key)

    if valid:
        print(
            f"License valid: {payload['customer']} "
            f"({payload['plan']}, expires {payload['expires']})"
        )
        return 0

    if not args.license_key:
        print("No license key provided -- running free tier.")
    else:
        print(f"License key not valid ({reason}) -- falling back to free tier.")
    return 1


__all__ = [
    "PUBLIC_KEY_B64",
    "b64u_decode",
    "main",
    "parse_args",
    "verify",
]


if __name__ == "__main__":
    raise SystemExit(main())
