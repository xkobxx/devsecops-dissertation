#!/usr/bin/env bash
# This script runs in CI. Broken examples block releases.
#
# Validates that every YAML file under examples/ parses correctly.
# Requires Python 3 with PyYAML installed (pip install pyyaml).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0
FAIL=0

echo "Validating example YAML files..."
echo "================================"

while IFS= read -r file; do
    relpath="${file#"$SCRIPT_DIR"/}"
    if python3 -c "
import yaml, sys
with open(sys.argv[1]) as f:
    yaml.safe_load(f)
" "$file" 2>/dev/null; then
        echo "  OK  $relpath"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $relpath"
        FAIL=$((FAIL + 1))
    fi
done < <(find "$SCRIPT_DIR" \( -name '*.yaml' -o -name '*.yml' \) -not -name '._*' | sort)

echo "================================"
echo "Passed: $PASS  Failed: $FAIL"

if [ "$FAIL" -gt 0 ]; then
    echo "ERROR: $FAIL example(s) have invalid YAML."
    exit 1
fi

echo "All examples valid."
