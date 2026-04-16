import json
import os
from collections import defaultdict

findings_path = 'reports/findings.json'
seeded_path = 'test-app/seeded_vulnerabilities.json'
output_path = 'reports/dashboard.html'

# Load findings
if not os.path.exists(findings_path):
    print(f"No findings.json found at {findings_path}. Run aggregate_results.py first.")
    exit(1)

with open(findings_path) as f:
    data = json.load(f)

findings = data.get('findings', [])

# Load seeded vulnerabilities for detection rate
seeded_vulns = []
if os.path.exists(seeded_path):
    with open(seeded_path) as f:
        raw = json.load(f)
        seeded_vulns = raw.get('vulnerabilities', raw) if isinstance(raw, dict) else raw

# Summary stats by tool
by_tool = defaultdict(lambda: defaultdict(int))
for finding in findings:
    tool = finding.get('tool', 'Unknown')
    severity = finding.get('severity', 'UNKNOWN').upper()
    by_tool[tool][severity] += 1

tools = sorted(by_tool.keys())
severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'WARNING', 'ERROR', 'UNKNOWN']

# Build summary table rows
summary_rows = ''
for tool in tools:
    counts = by_tool[tool]
    total = sum(counts.values())
    cells = ''.join(f'<td>{counts.get(s, 0)}</td>' for s in severities)
    summary_rows += f'<tr><td><strong>{tool}</strong></td>{cells}<td>{total}</td></tr>'

# Build findings table rows (all findings)
finding_rows = ''
for f in findings:
    sev = f.get('severity', 'UNKNOWN').upper()
    sev_class = {
        'CRITICAL': 'sev-critical',
        'HIGH': 'sev-high',
        'ERROR': 'sev-high',
        'MEDIUM': 'sev-medium',
        'WARNING': 'sev-medium',
        'LOW': 'sev-low',
    }.get(sev, '')
    finding_rows += (
        f'<tr data-tool="{f.get("tool","")}" data-sev="{sev}">'
        f'<td>{f.get("tool","")}</td>'
        f'<td class="{sev_class}">{sev}</td>'
        f'<td>{f.get("rule_id","")}</td>'
        f'<td>{f.get("description","")}</td>'
        f'<td>{f.get("file","")}</td>'
        f'<td>{f.get("line","") or ""}</td>'
        f'</tr>'
    )

# Seeded vulnerability detection rate section
seeded_html = ''
if seeded_vulns:
    detected = 0
    seeded_rows = ''
    for v in seeded_vulns:
        vuln_id = v.get('id', '')
        vuln_type = v.get('type', '')
        detection_tool = v.get('expected_tool', '')
        # Check if any finding references this vulnerability's expected tool
        is_detected = any(
            finding.get('tool') in detection_tool
            for finding in findings
        )
        if is_detected:
            detected += 1
        status = '✅ Detected' if is_detected else '❌ Missed'
        status_class = 'detected' if is_detected else 'missed'
        seeded_rows += (
            f'<tr>'
            f'<td>{vuln_id}</td>'
            f'<td>{vuln_type}</td>'
            f'<td>{v.get("severity","")}</td>'
            f'<td>{detection_tool}</td>'
            f'<td class="{status_class}">{status}</td>'
            f'</tr>'
        )
    rate = round(detected / len(seeded_vulns) * 100) if seeded_vulns else 0
    seeded_html = f'''
    <h2>Seeded Vulnerability Detection Rate</h2>
    <p><strong>{detected}/{len(seeded_vulns)} detected ({rate}%)</strong></p>
    <div class="progress-bar-bg"><div class="progress-bar" style="width:{rate}%">{rate}%</div></div>
    <table>
      <thead><tr><th>ID</th><th>Type</th><th>Severity</th><th>Expected Tool</th><th>Status</th></tr></thead>
      <tbody>{seeded_rows}</tbody>
    </table>
    '''

tool_options = ''.join(f'<option value="{t}">{t}</option>' for t in tools)

html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DevSecOps Security Dashboard</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; padding: 20px; background: #f4f6f9; color: #333; }}
  h1 {{ color: #1a1a2e; }}
  h2 {{ color: #16213e; margin-top: 40px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,0.1); margin-bottom: 30px; }}
  th {{ background: #1a1a2e; color: #fff; padding: 10px 14px; text-align: left; font-size: 13px; }}
  td {{ padding: 9px 14px; border-bottom: 1px solid #eee; font-size: 13px; word-break: break-word; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f0f4ff; }}
  .sev-critical {{ color: #7b0000; font-weight: bold; }}
  .sev-high {{ color: #c0392b; font-weight: bold; }}
  .sev-medium {{ color: #e67e22; font-weight: bold; }}
  .sev-low {{ color: #27ae60; }}
  .detected {{ color: #27ae60; font-weight: bold; }}
  .missed {{ color: #c0392b; font-weight: bold; }}
  .stats {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 30px; }}
  .stat-card {{ background: #fff; border-radius: 8px; padding: 20px 28px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); text-align: center; min-width: 120px; }}
  .stat-card .num {{ font-size: 36px; font-weight: bold; color: #1a1a2e; }}
  .stat-card .label {{ font-size: 13px; color: #666; margin-top: 4px; }}
  .filter-bar {{ display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }}
  .filter-bar select, .filter-bar input {{ padding: 7px 12px; border: 1px solid #ccc; border-radius: 6px; font-size: 13px; }}
  .progress-bar-bg {{ background: #e0e0e0; border-radius: 8px; height: 22px; margin-bottom: 16px; overflow: hidden; max-width: 500px; }}
  .progress-bar {{ background: #27ae60; height: 100%; border-radius: 8px; display: flex; align-items: center; padding-left: 10px; color: #fff; font-size: 13px; font-weight: bold; }}
</style>
</head>
<body>
<h1>DevSecOps Security Dashboard</h1>

<div class="stats">
  <div class="stat-card"><div class="num">{len(findings)}</div><div class="label">Total Findings</div></div>
  {"".join(f'<div class="stat-card"><div class="num">{sum(by_tool[t].values())}</div><div class="label">{t}</div></div>' for t in tools)}
</div>

<h2>Findings by Tool & Severity</h2>
<table>
  <thead>
    <tr>
      <th>Tool</th>
      {"".join(f"<th>{s}</th>" for s in severities)}
      <th>Total</th>
    </tr>
  </thead>
  <tbody>{summary_rows}</tbody>
</table>

{seeded_html}

<h2>All Findings</h2>
<div class="filter-bar">
  <label>Tool:
    <select id="filterTool" onchange="filterTable()">
      <option value="">All</option>
      {tool_options}
    </select>
  </label>
  <label>Severity:
    <select id="filterSev" onchange="filterTable()">
      <option value="">All</option>
      {"".join(f'<option value="{s}">{s}</option>' for s in severities)}
    </select>
  </label>
  <label>Search:
    <input type="text" id="filterSearch" placeholder="keyword..." oninput="filterTable()">
  </label>
</div>
<table id="findingsTable">
  <thead><tr><th>Tool</th><th>Severity</th><th>Rule ID</th><th>Description</th><th>File</th><th>Line</th></tr></thead>
  <tbody>{finding_rows}</tbody>
</table>

<script>
function filterTable() {{
  var tool = document.getElementById('filterTool').value.toLowerCase();
  var sev = document.getElementById('filterSev').value.toLowerCase();
  var search = document.getElementById('filterSearch').value.toLowerCase();
  var rows = document.querySelectorAll('#findingsTable tbody tr');
  rows.forEach(function(row) {{
    var rowTool = (row.dataset.tool || '').toLowerCase();
    var rowSev = (row.dataset.sev || '').toLowerCase();
    var text = row.textContent.toLowerCase();
    var show = (!tool || rowTool === tool) && (!sev || rowSev === sev) && (!search || text.includes(search));
    row.style.display = show ? '' : 'none';
  }});
}}
</script>
</body>
</html>'''

os.makedirs('reports', exist_ok=True)
with open(output_path, 'w') as f:
    f.write(html)

print(f"Dashboard generated: {output_path}")
print(f"Total findings: {len(findings)}")
for tool in tools:
    print(f"  {tool}: {sum(by_tool[tool].values())}")
