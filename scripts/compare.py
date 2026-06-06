"""
compare.py

Shows side-by-side detection scores before and after transformation.

Usage:
  python scripts/compare.py <file>                  Compare and print diff
  python scripts/compare.py <file> -o clean.txt     Save transformed output
  python scripts/compare.py <file> -a               Aggressive transform
  python scripts/compare.py <file> -- -q            Pass flags to transform
"""

import argparse
import sys
import os

_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)
from scripts.detect import detect_text
from scripts.transform import transform_text


def _score_line(report):
    s = {"VERY HIGH": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return s[report["probability"]]


def main():
    parser = argparse.ArgumentParser(
        description="Compare AI detection scores before and after transformation."
    )
    parser.add_argument("file", help="Source file to analyze")
    parser.add_argument("-o", "--output", help="Save transformed output to file")
    parser.add_argument("-a", "--aggressive", action="store_true",
                        help="Aggressive transformation")
    parser.add_argument("transform_args", nargs="*",
                        help="Additional arguments passed to transform.py")

    args = parser.parse_args()

    with open(args.file) as f:
        original = f.read()

    source_name = args.file

    before = detect_text(original, aggressive=args.aggressive)
    transformed, changes = transform_text(
        original,
        aggressive=args.aggressive,
        quiet=False,
    )
    after = detect_text(transformed, aggressive=args.aggressive)

    tiers = ["critical", "high", "medium", "style"]

    print("=" * 72)
    print(f"{'Before':<36} {'After':<36}")
    print("=" * 72)

    for tier_id in tiers:
        before_cats = {k: v for k, v in before["categories"].items()
                       if v["tier"] == tier_id and v["count"] > 0}
        after_cats = {k: v for k, v in after["categories"].items()
                      if v["tier"] == tier_id and v["count"] > 0}
        if not before_cats and not after_cats:
            continue

        tier_label = tier_id.upper()
        print(f"\n  {tier_label}:")
        all_keys = sorted(set(list(before_cats.keys()) + list(after_cats.keys())))
        for key in all_keys:
            b = before_cats.get(key, {}).get("count", 0)
            a = after_cats.get(key, {}).get("count", 0)
            name = before["categories"].get(key, after["categories"].get(key, {})).get("name", key)
            if b == 0 and a == 0:
                continue
            arrow = " \u2192 " if b != a else "    "
            print(f"    {name:.<28} {b:>3}{arrow}{a:<3}")

    print()
    print("-" * 72)
    b_score = _score_line(before)
    a_score = _score_line(after)
    score_map = {4: "VERY HIGH", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}

    print(f"{' ':>8} {'Words':>8} {'Issues':>8} {'Density':>8} {'Score':>10}")
    print(f"{'Before':>8} {before['word_count']:>8} {before['total_issues']:>8} "
          f"{before['issue_density']:>7.1f}% {score_map[b_score]:>10}")
    print(f"{'After':>8} {after['word_count']:>8} {after['total_issues']:>8} "
          f"{after['issue_density']:>7.1f}% {score_map[a_score]:>10}")
    print("-" * 72)

    improvement = b_score - a_score
    if improvement > 0:
        print(f"  Improvement: {improvement} tier(s) \u2193")
    elif improvement == 0 and after["total_issues"] < before["total_issues"]:
        print(f"  Improvement: {before['total_issues'] - after['total_issues']} fewer issues")
    else:
        print("  No change detected")

    print(f"  Transform changes: {len(changes)}")

    if args.output:
        with open(args.output, "w") as f:
            f.write(transformed)
        print(f"  Transformed text saved to {args.output}")


if __name__ == "__main__":
    main()
