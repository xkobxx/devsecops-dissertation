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

# Write unified findings
os.makedirs('reports', exist_ok=True)
with open('reports/findings.json', 'w') as f:
    json.dump({'total': len(findings), 'findings': findings}, f, indent=2)

print(f"Aggregated {len(findings)} total findings.")

# Security gate — fail build on any HIGH severity finding from Bandit or Semgrep
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