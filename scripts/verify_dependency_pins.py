#!/usr/bin/env python3
"""Compatibility entry point for dependency-pin validation."""

from trustgate.supply_chain.pins import main


if __name__ == "__main__":
    raise SystemExit(main())
