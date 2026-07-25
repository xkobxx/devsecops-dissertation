"""Validate benchmark run provenance recorded by the canonical manifest.

Historical versions of this script appended metrics calculated with a separate
line-proximity tolerance. Run metadata now lives only in the versioned manifest;
new runs must be added there with an exact commit SHA, timestamp, artifact hash,
scanner versions, and an explicit statistical-independence decision.
"""

from pathlib import Path
import sys


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from trustgate.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(["benchmark", "--check", *sys.argv[1:]]))
