"""
aggregate_results.py

Parses scan reports from Bandit, Semgrep, ZAP, pip-audit, Trivy,
and Gitleaks, normalises them into a unified findings.json, and
evaluates the security gate condition.
"""

import json
import sys
import os

findings = []

# Parse Bandit
bandit_path = 'reports/bandit_report.json'
if os.path.exists(bandit_path):
    with open(bandit_path) as f:
        bandit = json.load(f)
    for r in bandit.get('results', []):
        findings.append({
            'tool': 'Bandit',
            'rule_id': r.get('test_id'),
            'severity': r.get('issue_severity'),
            'description': r.get('issue_text'),
            'file': r.get('filename'),
            'line': r.get('line_number')
        })

# Parse Semgrep
semgrep_path = 'reports/semgrep_report.json'
if os.path.exists(semgrep_path):
    with open(semgrep_path) as f:
        semgrep = json.load(f)
    for r in semgrep.get('results', []):
        findings.append({
            'tool': 'Semgrep',
            'rule_id': r.get('check_id'),
            'severity': r.get('extra', {}).get('severity', 'UNKNOWN'),
            'description': r.get('extra', {}).get('message', ''),
            'file': r.get('path'),
            'line': r.get('start', {}).get('line')
        })

# Parse ZAP
zap_path = 'reports/zap_report.json'
if os.path.exists(zap_path):
    with open(zap_path) as f:
        zap = json.load(f)
    for site in zap.get('site', []):
        for alert in site.get('alerts', []):
            findings.append({
                'tool': 'ZAP',
                'rule_id': alert.get('pluginid'),
                'severity': alert.get('riskdesc', '').split(' ')[0],
                'description': alert.get('name'),
                'file': alert.get('uri', ''),
                'line': None
            })

# Parse pip-audit (SCA)
pip_audit_path = 'reports/pip_audit_report.json'
if os.path.exists(pip_audit_path):
    with open(pip_audit_path) as f:
        pip_data = json.load(f)
    for dep in pip_data.get('dependencies', []):
        for vuln in dep.get('vulns', []):
            findings.append({
                'tool': 'pip-audit',
                'rule_id': vuln.get('id'),
                'severity': 'HIGH',
                'description': vuln.get('description', ''),
                'file': dep.get('name'),
                'line': None
            })

# Parse Trivy (container/config scanning)
trivy_path = 'reports/trivy_report.json'
if os.path.exists(trivy_path):
    with open(trivy_path) as f:
        trivy = json.load(f)
    for result in trivy.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            findings.append({
                'tool': 'Trivy',
                'rule_id': vuln.get('VulnerabilityID'),
                'severity': vuln.get('Severity', 'UNKNOWN'),
                'description': vuln.get('Title', vuln.get('Description', '')),
                'file': result.get('Target', ''),
                'line': None
            })
        for misc in result.get('Misconfigurations', []):
            findings.append({
                'tool': 'Trivy',
                'rule_id': misc.get('ID'),
                'severity': misc.get('Severity', 'UNKNOWN'),
                'description': misc.get('Title', ''),
                'file': result.get('Target', ''),
                'line': None
            })

# Parse Gitleaks (secrets scanning)
gitleaks_path = 'reports/gitleaks_report.json'
if os.path.exists(gitleaks_path):
    with open(gitleaks_path) as f:
        leaks = json.load(f)
    if isinstance(leaks, list):
        for leak in leaks:
            findings.append({
                'tool': 'Gitleaks',
                'rule_id': leak.get('RuleID', 'secret'),
                'severity': 'HIGH',
                'description': leak.get('Description', 'Secret detected'),
                'file': leak.get('File', ''),
                'line': leak.get('StartLine')
            })

# Write unified findings
os.makedirs('reports', exist_ok=True)
with open('reports/findings.json', 'w') as f:
    json.dump({'total': len(findings), 'findings': findings}, f, indent=2)

print(f"Aggregated {len(findings)} total findings.")

# Security gate — fail build on any HIGH severity finding from SAST tools
critical_findings = [
    f for f in findings
    if f['tool'] in ('Bandit', 'Semgrep')
    and f['severity'].upper() in ('HIGH', 'ERROR', 'CRITICAL')
]

if critical_findings:
    print(f"SECURITY GATE FAILED: {len(critical_findings)} high/critical findings detected.")
    for f in critical_findings:
        print(f"  [{f['tool']}] {f['rule_id']} - {f['description']} ({f['file']} line {f['line']})")
    sys.exit(1)

print("Security gate passed.")
