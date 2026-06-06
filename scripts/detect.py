"""
detect.py

Scans text for AI-generated writing patterns based on Wikipedia's
Signs of AI Writing guide. Checks 16 pattern categories across 4 tiers.

Usage:
  python scripts/detect.py <file>       Scan a file
  echo "text" | python scripts/detect.py  Scan from stdin
  python scripts/detect.py <file> -j    JSON output
  python scripts/detect.py <file> -s    Score only
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


def _count_words(text):
    return len(re.findall(r"\b\w+\b", text))


def _find_matches(pattern_conf, lines, aggressive, cat_fixable=False, cat_tier="medium", cat_aggressive=False):
    compiled = _compile_re(pattern_conf["re"], pattern_conf.get("flags"))
    tier = cat_tier
    category_fixable = cat_fixable
    is_aggressive = cat_aggressive or pattern_conf.get("aggressive", False)

    if is_aggressive and not aggressive:
        return []

    method = pattern_conf.get("method")
    if method == "remove_line":
        matches = []
        for i, line in enumerate(lines, 1):
            if compiled.search(line):
                matches.append({
                    "line": i,
                    "desc": pattern_conf.get("desc", ""),
                    "fixable": category_fixable,
                    "tier": tier,
                })
        return matches

    matches = []
    for i, line in enumerate(lines, 1):
        for m in compiled.finditer(line):
            matches.append({
                "line": i,
                "text": m.group(0)[:60],
                "desc": pattern_conf.get("desc", ""),
                "fixable": category_fixable,
                "tier": tier,
            })
    return matches


def detect_text(text, aggressive=False):
    data = _load_patterns()
    lines = text.split("\n")
    word_count = _count_words(text)

    results = {}
    total_issues = 0
    total_fixable = 0
    total_aggressive_fixable = 0
    has_critical_tier = False

    for cat_id, cat in data["categories"].items():
        tier = cat["tier"]
        matches = []
        for p in cat["patterns"]:
            matches.extend(_find_matches(p, lines, aggressive, cat_fixable=cat.get("fixable", False), cat_tier=tier, cat_aggressive=cat.get("aggressive", False)))

        fixable_count = sum(1 for m in matches if m.get("fixable"))
        cat_aggressive = cat.get("aggressive", False)

        if cat_aggressive and not aggressive:
            total_aggressive_fixable += len(matches)
        elif cat.get("fixable"):
            total_fixable += fixable_count

        total_issues += len(matches)

        if tier == "critical" and len(matches) > 0:
            has_critical_tier = True

        results[cat_id] = {
            "name": cat["name"],
            "tier": tier,
            "count": len(matches),
            "matches": matches,
            "fixable": cat.get("fixable", False),
            "fixable_count": fixable_count,
            "aggressive_only": cat.get("aggressive", False),
        }

    issue_density = (total_issues / word_count * 100) if word_count > 0 else 0

    if has_critical_tier:
        probability = "VERY HIGH"
    elif total_issues > 30 or issue_density > 5:
        probability = "HIGH"
    elif total_issues > 15 or issue_density > 2:
        probability = "MEDIUM"
    else:
        probability = "LOW"

    return {
        "word_count": word_count,
        "total_issues": total_issues,
        "issue_density": round(issue_density, 2),
        "probability": probability,
        "fixable": total_fixable,
        "fixable_aggressive": total_aggressive_fixable,
        "categories": results,
    }


def _format_report(report, file_name):
    lines = []
    lines.append(f"File: {file_name}")
    lines.append(f"Words: {report['word_count']}")
    lines.append(f"Issues: {report['total_issues']}  ({report['issue_density']}% density)")
    lines.append(f"AI Probability: {report['probability']}")
    lines.append("")

    tiers = [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("style", "Style"),
    ]

    for tier_id, tier_label in tiers:
        tier_cats = {
            k: v for k, v in report["categories"].items() if v["tier"] == tier_id
        }
        tier_total = sum(v["count"] for v in tier_cats.values())
        if tier_total == 0:
            continue
        lines.append(f"{tier_label} ({tier_total}):")
        for cat_id, cat in tier_cats.items():
            icon = "\u2713" if cat["fixable_count"] > 0 else "\u2717"
            fix_note = ""
            if cat["fixable_count"] > 0:
                if cat.get("aggressive_only"):
                    fix_note = f"  {icon} fix (-a)"
                else:
                    fix_note = f"  {icon} fix"
            lines.append(f"  {cat['name']:.<30} {cat['count']}{fix_note}")
        lines.append("")

    lines.append(f"Auto-fixable: {report['fixable']} issue(s)")
    if report["fixable_aggressive"] > 0:
        lines.append(f"  (+ {report['fixable_aggressive']} with -a)")

    return "\n".join(lines)


_cached_patterns = None


def _get_cat_patterns(cat_id):
    global _cached_patterns
    if _cached_patterns is None:
        _cached_patterns = _load_patterns()
    data = _cached_patterns["categories"].get(cat_id, {})
    return data.get("patterns", [])


def main():
    parser = argparse.ArgumentParser(
        description="Detect AI-generated writing patterns in text."
    )
    parser.add_argument("file", nargs="?", help="File to scan (reads from stdin if omitted)")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("-s", "--score", action="store_true", help="Score only")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Include aggressive patterns")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            text = f.read()
        source_name = args.file
    else:
        text = sys.stdin.read()
        source_name = "<stdin>"

    report = detect_text(text, aggressive=args.aggressive)

    if args.json:
        print(json.dumps(report, indent=2))
    elif args.score:
        score_map = {"VERY HIGH": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        print(f"{report['probability']}|{report['total_issues']}|{report['word_count']}|{score_map[report['probability']]}")
    else:
        print(_format_report(report, source_name))

    score_map = {"VERY HIGH": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    sys.exit(0 if score_map[report["probability"]] <= 2 else 1)


if __name__ == "__main__":
    main()
