import json
import os
import sys
from datetime import datetime

def count_findings(findings, tool):
    return [f for f in findings if f.get('tool') == tool]

def map_to_ground_truth(findings, tool, ground_truth_path='test_app/seeded_vulnerabilities.json'):
    with open(ground_truth_path) as f:
        gt = json.load(f)
    known = gt.get('vulnerabilities', [])

    tool_findings = [f for f in findings if f.get('tool') == tool]

    tp_ids = set()
    for vuln in known:
        expected = vuln.get('expected_tool', '')
        if tool in expected:
            matched = any(
                f.get('line') and abs(f.get('line', 0) - vuln.get('line', 0)) <= 3
                for f in tool_findings
            )
            if matched:
                tp_ids.add(vuln['id'])

    tp = len(tp_ids)
    fn = sum(1 for v in known if tool in v.get('expected_tool', '') and v['id'] not in tp_ids)
    fp = len(tool_findings) - tp

    total_expected = sum(1 for v in known if tool in v.get('expected_tool', ''))
    precision = round(tp / (tp + fp), 3) if (tp + fp) > 0 else 0
    recall = round(tp / (tp + fn), 3) if (tp + fn) > 0 else 0
    f1 = round(2 * precision * recall / (precision + recall), 3) if (precision + recall) > 0 else 0

    return {
        'tp': tp, 'fp': fp, 'fn': fn,
        'precision': precision, 'recall': recall, 'f1': f1
    }

if __name__ == '__main__':
    run_number = sys.argv[1] if len(sys.argv) > 1 else '1'
    scenario = sys.argv[2] if len(sys.argv) > 2 else 'combined_sast_dast'

    findings_path = 'reports/findings.json'
    log_path = 'results/experiment_log.json'

    if not os.path.exists(findings_path):
        print("No findings.json found. Run the pipeline first.")
        sys.exit(1)

    with open(findings_path) as f:
        data = json.load(f)
    findings = data.get('findings', [])

    bandit = map_to_ground_truth(findings, 'Bandit')
    semgrep = map_to_ground_truth(findings, 'Semgrep')

    record = {
        'run': int(run_number),
        'scenario': scenario,
        'timestamp': datetime.utcnow().isoformat(),
        'total_findings': len(findings),
        'bandit': bandit,
        'semgrep': semgrep,
        'combined': {
            'tp': len(set(
                [v['id'] for v in json.load(open('test_app/seeded_vulnerabilities.json'))['vulnerabilities']
                 if any(f.get('line') and abs(f.get('line',0) - v.get('line',0)) <= 3
                        for f in findings if v.get('expected_tool','') in ('Bandit', 'Bandit/Semgrep', 'Semgrep'))]
            )),
        }
    }

    with open(log_path) as f:
        log = json.load(f)

    log['scenarios'][scenario].append(record)

    with open(log_path, 'w') as f:
        json.dump(log, f, indent=2)

    print(f"Run {run_number} recorded for scenario: {scenario}")
    print(f"Bandit  — TP: {bandit['tp']}, FP: {bandit['fp']}, FN: {bandit['fn']}, Precision: {bandit['precision']}, Recall: {bandit['recall']}, F1: {bandit['f1']}")
    print(f"Semgrep — TP: {semgrep['tp']}, FP: {semgrep['fp']}, FN: {semgrep['fn']}, Precision: {semgrep['precision']}, Recall: {semgrep['recall']}, F1: {semgrep['f1']}")