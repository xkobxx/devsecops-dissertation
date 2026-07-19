"""
aggregate_results.py

Parses scan reports from Bandit, Semgrep, pip-audit, Trivy, and Gitleaks,
normalises them into a unified findings.json, and evaluates the security
gate condition.
"""

import argparse
import json
import os
import sys

# Ranks let severities from different tools (Bandit's HIGH, Semgrep's ERROR,
# Trivy's CRITICAL, ...) be compared on one scale for gating.
SEVERITY_RANK = {
    'CRITICAL': 4,
    'HIGH': 3, 'ERROR': 3,
    'MEDIUM': 2, 'WARNING': 2,
    'LOW': 1, 'INFO': 1,
    'UNKNOWN': 0,
}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description='Aggregate per-tool scan reports into one findings feed and gate the build.'
    )
    parser.add_argument('--target', default='.',
                         help='Path that was scanned (recorded in findings.json for reference)')
    parser.add_argument('--reports-dir', default='reports',
                         help='Directory containing the raw per-tool scan reports (default: reports)')
    parser.add_argument('--output', default=None,
                         help='Path to write the unified findings.json (default: <reports-dir>/findings.json)')
    parser.add_argument('--fail-on', default='high', choices=['critical', 'high', 'medium', 'low', 'none'],
                         help='Minimum severity that fails the security gate (default: high; "none" disables the gate)')
    return parser.parse_args(argv)


def parse_bandit(path):
    findings = []
    if not os.path.exists(path):
        return findings
    with open(path) as f:
        bandit = json.load(f)
    for r in bandit.get('results', []):
        findings.append({
            'tool': 'Bandit',
            'rule_id': r.get('test_id'),
            'severity': r.get('issue_severity'),
            'description': r.get('issue_text'),
            'file': r.get('filename'),
            'line': r.get('line_number'),
        })
    return findings


def parse_semgrep(path):
    findings = []
    if not os.path.exists(path):
        return findings
    with open(path) as f:
        semgrep = json.load(f)
    for r in semgrep.get('results', []):
        findings.append({
            'tool': 'Semgrep',
            'rule_id': r.get('check_id'),
            'severity': r.get('extra', {}).get('severity', 'UNKNOWN'),
            'description': r.get('extra', {}).get('message', ''),
            'file': r.get('path'),
            'line': r.get('start', {}).get('line'),
        })
    return findings


def parse_pip_audit(path):
    findings = []
    if not os.path.exists(path):
        return findings
    with open(path) as f:
        pip_data = json.load(f)
    for dep in pip_data.get('dependencies', []):
        for vuln in dep.get('vulns', []):
            findings.append({
                'tool': 'pip-audit',
                'rule_id': vuln.get('id'),
                'severity': 'HIGH',
                'description': vuln.get('description', ''),
                'file': dep.get('name'),
                'line': None,
            })
    return findings


def parse_trivy(path):
    findings = []
    if not os.path.exists(path):
        return findings
    with open(path) as f:
        trivy = json.load(f)
    for result in trivy.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            findings.append({
                'tool': 'Trivy',
                'rule_id': vuln.get('VulnerabilityID'),
                'severity': vuln.get('Severity', 'UNKNOWN'),
                'description': vuln.get('Title', vuln.get('Description', '')),
                'file': result.get('Target', ''),
                'line': None,
            })
        for misc in result.get('Misconfigurations', []):
            findings.append({
                'tool': 'Trivy',
                'rule_id': misc.get('ID'),
                'severity': misc.get('Severity', 'UNKNOWN'),
                'description': misc.get('Title', ''),
                'file': result.get('Target', ''),
                'line': None,
            })
    return findings


def parse_gitleaks(path):
    findings = []
    if not os.path.exists(path):
        return findings
    with open(path) as f:
        leaks = json.load(f)
    if isinstance(leaks, list):
        for leak in leaks:
            findings.append({
                'tool': 'Gitleaks',
                'rule_id': leak.get('RuleID', 'secret'),
                'severity': 'HIGH',
                'description': leak.get('Description', 'Secret detected'),
                'file': leak.get('File', ''),
                'line': leak.get('StartLine'),
            })
    return findings


def main(argv=None):
    args = parse_args(argv)
    reports_dir = args.reports_dir
    output_path = args.output or os.path.join(reports_dir, 'findings.json')
    if output_path.endswith(os.sep) or os.path.isdir(output_path):
        output_path = os.path.join(output_path, 'findings.json')

    findings = []
    findings += parse_bandit(os.path.join(reports_dir, 'bandit_report.json'))
    findings += parse_semgrep(os.path.join(reports_dir, 'semgrep_report.json'))
    findings += parse_pip_audit(os.path.join(reports_dir, 'pip_audit_report.json'))
    findings += parse_trivy(os.path.join(reports_dir, 'trivy_report.json'))
    findings += parse_gitleaks(os.path.join(reports_dir, 'gitleaks_report.json'))

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump({'target': args.target, 'total': len(findings), 'findings': findings}, f, indent=2)

    print(f"Aggregated {len(findings)} total findings.")

    if args.fail_on == 'none':
        print("Security gate disabled (--fail-on none).")
        return

    threshold_rank = SEVERITY_RANK[args.fail_on.upper()]

    # Gate on every tool's findings, not just Bandit/Semgrep — a HIGH from
    # Trivy or Gitleaks is just as build-blocking as one from Bandit.
    gating_findings = [
        f for f in findings
        if SEVERITY_RANK.get((f['severity'] or 'UNKNOWN').upper(), 0) >= threshold_rank
    ]

    if gating_findings:
        print(f"SECURITY GATE FAILED: {len(gating_findings)} finding(s) at or above '{args.fail_on}' severity.")
        for f in gating_findings:
            print(f"  [{f['tool']}] {f['rule_id']} - {f['description']} ({f['file']} line {f['line']})")
        sys.exit(1)

    print("Security gate passed.")


if __name__ == '__main__':
    main()
