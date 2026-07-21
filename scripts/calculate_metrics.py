"""
calculate_metrics.py

Reads findings.json files from results/run_1 through results/run_5,
compares each tool's output against the seeded vulnerability ground truth,
and calculates precision, recall, F1 score, and 95% confidence intervals.
Outputs a metrics_summary.json to the results/ directory.
"""

import json
import os
import math

GROUND_TRUTH_PATH = 'test_app/seeded_vulnerabilities.json'
RUNS_DIR = 'results'
NUM_RUNS = 5

with open(GROUND_TRUTH_PATH) as f:
    gt = json.load(f)
known_vulns = gt.get('vulnerabilities', [])

def get_expected_tools(vuln):
    """Return a list of tool names expected to detect the given vulnerability."""
    return [t.strip() for t in vuln.get('expected_tool', '').split('/')]

def analyse_run(findings, tool):
    """Calculate TP, FP, FN, precision, recall, and F1 for one tool across one run."""
    expected = [v for v in known_vulns if tool in get_expected_tools(v)]
    tool_findings = [f for f in findings if f.get('tool') == tool]

    tp = 0
    for vuln in expected:
        matched = any(
            f.get('line') and abs(f.get('line', 0) - vuln.get('line', 0)) <= 5
            for f in tool_findings
        )
        if matched:
            tp += 1

    fn = len(expected) - tp
    fp = len(tool_findings) - tp
    fp = max(fp, 0)

    precision = round(tp / (tp + fp), 3) if (tp + fp) > 0 else 0.0
    recall    = round(tp / (tp + fn), 3) if (tp + fn) > 0 else 0.0
    f1        = round(2 * precision * recall / (precision + recall), 3) if (precision + recall) > 0 else 0.0

    return {
        'tp': tp, 'fp': fp, 'fn': fn,
        'precision': precision, 'recall': recall, 'f1': f1,
        'total_findings': len(tool_findings)
    }

def mean(values):
    """Return the arithmetic mean of a list of values, rounded to 3 decimal places."""
    return round(sum(values) / len(values), 3) if values else 0.0

def confidence_interval(values, confidence=0.95):
    """Calculate the 95% confidence interval margin using the t-distribution (n=5, df=4)."""
    n = len(values)
    if n < 2:
        return 0.0
    m = mean(values)
    variance = sum((x - m) ** 2 for x in values) / (n - 1)
    std_dev = math.sqrt(variance)
    t_value = 2.776  # t-value for 95% CI with 4 degrees of freedom (n=5)
    margin = t_value * (std_dev / math.sqrt(n))
    return round(margin, 3)

tools = ['Bandit', 'Semgrep']
results = {tool: [] for tool in tools}

for i in range(1, NUM_RUNS + 1):
    path = os.path.join(RUNS_DIR, f'run_{i}', 'findings.json')
    if not os.path.exists(path):
        print(f"WARNING: {path} not found — skipping")
        continue
    with open(path) as f:
        data = json.load(f)
    findings = data.get('findings', [])
    for tool in tools:
        metrics = analyse_run(findings, tool)
        metrics['run'] = i
        results[tool].append(metrics)
        print(f"Run {i} | {tool:8s} | TP:{metrics['tp']} FP:{metrics['fp']} FN:{metrics['fn']} | P:{metrics['precision']} R:{metrics['recall']} F1:{metrics['f1']}")

print("\n" + "="*65)
print("SUMMARY — Mean metrics across 5 runs (95% confidence interval)")
print("="*65)

summary = {}
for tool in tools:
    runs = results[tool]
    if not runs:
        continue

    metrics_summary = {}
    for metric in ['precision', 'recall', 'f1', 'fp']:
        values = [r[metric] for r in runs]
        m = mean(values)
        ci = confidence_interval(values)
        metrics_summary[metric] = {'mean': m, 'ci': ci}

    summary[tool] = metrics_summary
    print(f"\n{tool}:")
    print(f"  Precision : {metrics_summary['precision']['mean']} ± {metrics_summary['precision']['ci']}")
    print(f"  Recall    : {metrics_summary['recall']['mean']} ± {metrics_summary['recall']['ci']}")
    print(f"  F1 Score  : {metrics_summary['f1']['mean']} ± {metrics_summary['f1']['ci']}")
    print(f"  False Pos : {metrics_summary['fp']['mean']} ± {metrics_summary['fp']['ci']}")

output_path = 'results/metrics_summary.json'
with open(output_path, 'w') as f:
    json.dump(summary, f, indent=2)

print(f"\nMetrics saved to {output_path}")