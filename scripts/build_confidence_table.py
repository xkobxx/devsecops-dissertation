"""
build_confidence_table.py

PROPRIETARY -- not covered by this repository's MIT LICENSE. See
LICENSE-COMMERCIAL.

Build-time tool: matches a corpus of scanner findings (results/run_1/findings.json,
from re-running the pipeline against test_app/, our fully-enumerated vulnerable
fixture) against the seeded ground truth, and computes empirical precision per
(tool, rule_id). The output feeds score_findings.py's runtime lookup.

Honesty note: today's corpus is one small fixture (6 seeded vulns, one file).
Per-rule sample sizes are tiny (often 1-3). Every entry carries its sample_size
so downstream consumers can see how much to trust it -- these numbers are
directional, not a statistically robust benchmark, until the corpus grows.
"""

import json

GROUND_TRUTH_PATH = 'test_app/seeded_vulnerabilities.json'
CORPUS_PATH = 'results/run_1/findings.json'
OUTPUT_PATH = 'confidence_table.json'
LINE_TOLERANCE = 5


def load_ground_truth():
    with open(GROUND_TRUTH_PATH) as f:
        vulns = json.load(f).get('vulnerabilities', [])
    tools_covered = set()
    for v in vulns:
        tools_covered.update(t.strip() for t in v.get('expected_tool', '').split('/') if t.strip())
    return vulns, tools_covered


def is_true_positive(finding, seeded_vulns):
    line = finding.get('line')
    if not line:
        return False
    return any(abs(line - v.get('line', 0)) <= LINE_TOLERANCE for v in seeded_vulns)


def build_table(corpus_path, seeded_vulns, tools_covered):
    with open(corpus_path) as f:
        findings = json.load(f).get('findings', [])

    # Only Bandit/Semgrep findings can be judged: the ground truth is all
    # code-level bugs with line numbers, so a tool with no seeded vulns of
    # its own type (pip-audit, Trivy, Gitleaks today) can't be fairly scored
    # here -- scoring it would just mean "0% precision" as an artifact of an
    # empty ground truth, not a real signal about that tool's accuracy.
    unscored_tools = sorted({f.get('tool') for f in findings if f.get('tool') not in tools_covered})

    counts = {}  # (tool, rule_id) -> {'tp': int, 'fp': int}
    for f in findings:
        if f.get('tool') not in tools_covered:
            continue
        key = (f.get('tool'), f.get('rule_id'))
        bucket = counts.setdefault(key, {'tp': 0, 'fp': 0})
        if is_true_positive(f, seeded_vulns):
            bucket['tp'] += 1
        else:
            bucket['fp'] += 1

    rules = {}
    tool_totals = {}
    for (tool, rule_id), c in counts.items():
        tt = tool_totals.setdefault(tool, {'tp': 0, 'fp': 0})
        tt['tp'] += c['tp']
        tt['fp'] += c['fp']

    for (tool, rule_id), c in counts.items():
        sample_size = c['tp'] + c['fp']
        rules[f"{tool}:{rule_id}"] = {
            'tool': tool,
            'rule_id': rule_id,
            'tp': c['tp'],
            'fp': c['fp'],
            'sample_size': sample_size,
            'precision': round(c['tp'] / sample_size, 3) if sample_size else 0.0,
        }

    tool_baseline = {}
    for tool, tt in tool_totals.items():
        total = tt['tp'] + tt['fp']
        tool_baseline[tool] = {
            'tp': tt['tp'],
            'fp': tt['fp'],
            'sample_size': total,
            'precision': round(tt['tp'] / total, 3) if total else 0.0,
        }

    return rules, tool_baseline, unscored_tools


def main():
    seeded_vulns, tools_covered = load_ground_truth()
    rules, tool_baseline, unscored_tools = build_table(CORPUS_PATH, seeded_vulns, tools_covered)

    output = {
        '_license': (
            "Proprietary data, not covered by this repository's MIT LICENSE. "
            "See LICENSE-COMMERCIAL. Requires a valid subscription to use with score_findings.py."
        ),
        'methodology': (
            f"Empirical precision per (tool, rule) from matching scanner findings against "
            f"a hand-seeded ground truth ({len(seeded_vulns)} known vulnerabilities in a "
            f"single fixture app), using +/-{LINE_TOLERANCE}-line proximity matching. "
            f"Sample sizes are small -- treat entries with sample_size < 5 as directional, "
            f"not statistically robust. Tools with no seeded vulnerabilities of their own "
            f"type ({', '.join(unscored_tools) or 'none'}) are excluded rather than scored, "
            f"since an empty ground truth would produce a misleading 0% precision. Known "
            f"limitation: +/-{LINE_TOLERANCE}-line proximity matching can spuriously match an "
            f"unrelated finding to a nearby seeded vuln in dense files -- verify any single-file "
            f"benchmark result before publishing it externally."
        ),
        'rules': rules,
        'tool_baseline': tool_baseline,
        'unscored_tools': unscored_tools,
    }

    with open(OUTPUT_PATH, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"Confidence table written to {OUTPUT_PATH}: {len(rules)} rules, {len(tool_baseline)} tool baselines.")
    for key, v in sorted(rules.items()):
        print(f"  {key}: precision={v['precision']} (tp={v['tp']} fp={v['fp']} n={v['sample_size']})")


if __name__ == '__main__':
    main()
