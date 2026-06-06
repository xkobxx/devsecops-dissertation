"""
transform.py

Rewrites text to reduce AI-generated writing patterns. Applies auto-fixes
for citation bugs, chatbot artifacts, markdown, copula avoidance, filler
phrases, and curly quotes. Aggressive mode (-a) also simplifies -ing clauses
and reduces em dashes.

Usage:
  python scripts/transform.py <file>           Transform file, print to stdout
  python scripts/transform.py <file> -o out    Transform file, save to out
  python scripts/transform.py <file> -a        Aggressive mode
  python scripts/transform.py <file> -q        Quiet mode
  echo "text" | python scripts/transform.py    Transform from stdin
"""

import argparse
import json
import os
import re
import sys


def _load_patterns():
    path = os.path.join(os.path.dirname(__file__), "patterns.json")
    with open(path) as f:
        return json.load(f)


def _compile_re(pattern_str, flags_str=None):
    f = re.MULTILINE
    if flags_str and "i" in flags_str:
        f |= re.IGNORECASE
    return re.compile(pattern_str, f)


def transform_text(text, aggressive=False, quiet=False):
    data = _load_patterns()
    changes = []

    # --- Phase 1: Line removal (citation bugs, chatbot artifacts) ---
    remove_line_patterns = []
    for cat_id, cat in data["categories"].items():
        if cat.get("method") == "remove_line":
            for p in cat["patterns"]:
                is_agg = p.get("aggressive", False)
                if is_agg and not aggressive:
                    continue
                compiled = _compile_re(p["re"], p.get("flags"))
                remove_line_patterns.append((compiled, p["desc"]))

    kept_lines = []
    for line in text.split("\n"):
        skip = False
        for compiled, desc in remove_line_patterns:
            if compiled.search(line):
                changes.append(("removed", desc, line.strip()[:80]))
                skip = True
                break
        if not skip:
            kept_lines.append(line)

    text = "\n".join(kept_lines)

    # --- Phase 2: Inline replacements ---
    replace_categories = [k for k, v in data["categories"].items()
                          if v.get("method") == "replace"]
    for cat_id in replace_categories:
        cat = data["categories"][cat_id]
        is_aggressive_cat = cat.get("aggressive", False)
        if is_aggressive_cat and not aggressive:
            continue
        for p in cat["patterns"]:
            if "replacement" not in p:
                continue
            is_agg = p.get("aggressive", False)
            if is_agg and not aggressive:
                continue
            compiled = _compile_re(p["re"], p.get("flags"))
            replacement = p["replacement"]
            new_text = compiled.sub(replacement, text)
            if new_text != text:
                changes.append(("replaced", p["desc"], ""))
            text = new_text

    # --- Phase 3: Markdown conversion ---
    markdown_cat = data["categories"].get("markdown_patterns", {})
    for p in markdown_cat.get("patterns", []):
        if "replacement" not in p:
            continue
        compiled = _compile_re(p["re"], p.get("flags"))
        replacement = p["replacement"]
        new_text = compiled.sub(replacement, text)
        if new_text != text:
            changes.append(("converted", p["desc"], ""))
        text = new_text

    return text, changes


def main():
    parser = argparse.ArgumentParser(
        description="Transform text to reduce AI-generated writing patterns."
    )
    parser.add_argument("file", nargs="?", help="File to transform (stdin if omitted)")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Aggressive mode")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress change log")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    transformed, changes = transform_text(text, aggressive=args.aggressive, quiet=args.quiet)

    if not args.quiet:
        print(f"Changes made: {len(changes)}")
        for action, desc, detail in changes:
            if detail:
                print(f"  {action}: [{desc}] {detail}")
            else:
                print(f"  {action}: [{desc}]")
        print()

    if args.output:
        with open(args.output, "w") as f:
            f.write(transformed)
        if not args.quiet:
            print(f"Written to {args.output}")
    else:
        sys.stdout.write(transformed)


if __name__ == "__main__":
    main()
