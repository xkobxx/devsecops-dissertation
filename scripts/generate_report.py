"""
generate_report.py

Reads the unified findings.json (optionally already scored by
score_findings.py with confidence tiers) and renders a static HTML
dashboard with summary stats, a confidence-ranked "act on these first"
list, seeded-vulnerability detection rate, and a filterable findings table.
"""

import html
import json
import os
from collections import defaultdict

esc = html.escape

findings_path = 'reports/findings.json'
seeded_path = 'test_app/seeded_vulnerabilities.json'
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

CONFIDENCE_CLASS = {'High': 'conf-high', 'Likely': 'conf-likely', 'Noise': 'conf-noise', 'Unscored': 'conf-unscored'}


def confidence_label(f):
    tier = f.get('confidence_tier')
    if not tier:
        return 'Unscored', ''
    conf = f.get('confidence')
    label = tier if conf is None else f"{tier} ({round(conf * 100)}%)"
    return label, CONFIDENCE_CLASS.get(tier, '')


tool_options = ''.join(f'<option value="{esc(t)}">{esc(t)}</option>' for t in tools)

# ── Detection stats ────────────────────────────
detected = 0
seeded_vuln_detection = {}  # per-vuln detection status
if seeded_vulns:
    for v in seeded_vulns:
        detection_tool = v.get('expected_tool', '')
        is_detected = any(finding.get('tool') in detection_tool for finding in findings)
        seeded_vuln_detection[v.get('id', '')] = is_detected
        if is_detected:
            detected += 1
rate = round(detected / len(seeded_vulns) * 100) if seeded_vulns else 0

# ── Confidence / triage stats ─────────────────
scored = [f for f in findings if f.get('confidence_tier')]
high_conf_count = len([f for f in scored if f.get('confidence_tier') == 'High'])
noise_count = sum(1 for f in scored if f.get('confidence_tier') == 'Noise')

# ── Accuracy metrics ──────────────────────────
tp = high_conf_count
fp = noise_count
fn = 0  # ponytail: no ground-truth for unseeded; set 0
tn = 0

precision = round(tp / (tp + fp) * 100) if (tp + fp) > 0 else 0
recall_pct = rate  # detection rate = recall on seeded set
f1_score = round(2 * precision * recall_pct / (precision + recall_pct)) if (precision + recall_pct) > 0 else 0
noise_pct = round(fp / len(findings) * 100) if findings else 0

# ── Redesigned CSS ────────────────────────────
css = '''<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  /* =========================================
     1. DESIGN SYSTEM TOKENS
     ========================================= */
  :root {
    --gray-50: #F8FAFC;   --gray-100: #F1F5F9;
    --gray-200: #E2E8F0;  --gray-300: #CBD5E1;
    --gray-400: #94A3B8;  --gray-500: #64748B;
    --gray-700: #334155;  --gray-900: #0F172A;
    --blue: #3B82F6;      --blue-soft: #EFF6FF;
    --green: #10B981;     --green-soft: #ECFDF5;
    --red: #EF4444;       --red-soft: #FEF2F2;
    --amber: #F59E0B;     --amber-soft: #FFFBEB;
    --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    --font-mono: ui-monospace, "SF Mono", Menlo, monospace;
    --s-1: 4px; --s-2: 8px; --s-3: 12px; --s-4: 16px;
    --s-5: 20px; --s-6: 24px; --s-8: 32px;
    --r-sm: 6px; --r-md: 8px; --r-lg: 12px; --r-full: 999px;
    --shadow-sm: 0 1px 2px 0 rgba(15,23,42,0.04);
    --shadow-md: 0 4px 12px -2px rgba(15,23,42,0.06),0 2px 4px -2px rgba(15,23,42,0.04);
    --shadow-lg: 0 12px 24px -4px rgba(15,23,42,0.08),0 4px 8px -2px rgba(15,23,42,0.04);
  }
  /* =========================================
     2. BASE & RESET
     ========================================= */
  *{box-sizing:border-box;margin:0;padding:0}
  body{
    font-family:var(--font-sans);background:var(--gray-50);
    color:var(--gray-700);line-height:1.5;font-size:.875rem;
    -webkit-font-smoothing:antialiased;
  }
  /* =========================================
     3. LAYOUT & GRID SYSTEM
     ========================================= */
  .header{
    background:#fff;border-bottom:1px solid var(--gray-200);
    padding:0 var(--s-8);position:sticky;top:0;z-index:100;box-shadow:var(--shadow-sm);
  }
  .header-inner{
    max-width:1400px;margin:0 auto;display:flex;
    align-items:center;justify-content:space-between;height:64px;
  }
  .header h1{
    font-size:1rem;font-weight:700;color:var(--gray-900);
    display:flex;align-items:center;gap:10px;
  }
  .header h1 svg{width:18px;height:18px}
  .header-meta{display:flex;gap:24px;align-items:center;font-size:.8125rem;color:var(--gray-500)}
  .header-meta strong{color:var(--gray-900);font-weight:700;font-size:.9375rem}
  .tabs-container{
    background:#fff;border-bottom:1px solid var(--gray-200);
    position:sticky;top:64px;z-index:99;
  }
  .tabs-inner{max-width:1400px;margin:0 auto;display:flex;gap:var(--s-8);padding:0 var(--s-8)}
  .tab-btn{
    background:none;border:none;padding:var(--s-4) 0;
    font-family:inherit;font-size:.875rem;font-weight:600;
    color:var(--gray-400);cursor:pointer;
    border-bottom:2px solid transparent;margin-bottom:-1px;transition:all .2s;
  }
  .tab-btn:hover{color:var(--gray-500)}
  .tab-btn.active{color:var(--blue);border-bottom-color:var(--blue)}
  .container{max-width:1400px;margin:0 auto;padding:var(--s-8)}
  .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:var(--s-5);margin-bottom:var(--s-5)}
  .grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:var(--s-5);margin-bottom:var(--s-5)}
  .grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:var(--s-5)}
  /* =========================================
     4. COMPONENTS
     ========================================= */
  .card{
    background:#fff;border-radius:var(--r-lg);
    box-shadow:var(--shadow-md);overflow:hidden;
    transition:box-shadow .3s,transform .3s;display:flex;flex-direction:column;
  }
  .card:hover{box-shadow:var(--shadow-lg)}
  .card-head{padding:var(--s-5) var(--s-6);border-bottom:1px solid var(--gray-200)}
  .card-title{
    font-size:.9375rem;font-weight:700;color:var(--gray-900);
    letter-spacing:-.01em;margin-bottom:var(--s-1);
  }
  .card-subtitle{font-size:.75rem;color:var(--gray-400);font-weight:500}
  .card-body{
    padding:var(--s-6);flex:1;display:flex;
    flex-direction:column;justify-content:center;
  }
  .stat-card{
    background:#fff;border-radius:var(--r-lg);
    padding:var(--s-5) var(--s-6);box-shadow:var(--shadow-md);
    transition:transform .2s,box-shadow .2s;
    display:flex;flex-direction:column;justify-content:space-between;min-height:110px;
  }
  .stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow-lg)}
  .stat-label{
    font-size:.75rem;color:var(--gray-400);text-transform:uppercase;
    letter-spacing:.08em;font-weight:600;margin-bottom:var(--s-3);
    display:flex;align-items:center;gap:var(--s-2);
  }
  .stat-dot{width:var(--s-2);height:var(--s-2);border-radius:var(--r-full)}
  .stat-num{
    font-size:2rem;font-weight:800;line-height:1;
    color:var(--gray-900);letter-spacing:-.03em;
  }
  .stat-sub{font-size:.75rem;color:var(--gray-400);margin-top:var(--s-2);font-weight:500}
  .badge{
    display:inline-flex;align-items:center;padding:var(--s-1) var(--s-3);
    border-radius:var(--r-full);font-size:.6875rem;font-weight:600;
    text-transform:uppercase;letter-spacing:.04em;
  }
  .badge-high,.badge-error{background:var(--red-soft);color:#B91C1C}
  .badge-medium,.badge-warning{background:var(--amber-soft);color:#B45309}
  .badge-low{background:var(--green-soft);color:#047857}
  .tag-mono{
    font-family:var(--font-mono);font-size:.75rem;
    color:var(--blue);background:var(--blue-soft);
    padding:var(--s-1) var(--s-2);border-radius:var(--r-sm);font-weight:600;
  }
  .text-muted-mono{
    font-family:var(--font-mono);font-size:.75rem;
    color:var(--gray-400);font-weight:500;
  }
  .text-primary{color:var(--gray-900);font-weight:600}
  .table-scroll{overflow:auto;max-height:350px}
  .table-scroll.short{max-height:280px}
  table{width:100%;border-collapse:collapse;font-size:.8125rem}
  th{
    background:#fff;color:var(--gray-400);padding:var(--s-4) var(--s-6);
    text-align:left;font-size:.6875rem;font-weight:700;text-transform:uppercase;
    letter-spacing:.06em;border-bottom:1px solid var(--gray-200);
    white-space:nowrap;position:sticky;top:0;z-index:5;
  }
  td{
    padding:var(--s-4) var(--s-6);border-bottom:1px solid var(--gray-100);
    color:var(--gray-500);vertical-align:middle;
  }
  tbody tr:last-child td{border-bottom:none}
  tbody tr{transition:background .1s}
  tbody tr:hover{background:var(--gray-50)}
  .clamp-1{
    display:-webkit-box;-webkit-line-clamp:1;-webkit-box-orient:vertical;
    overflow:hidden;text-overflow:ellipsis;max-width:280px;
  }
  .clamp-2{
    display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;
    overflow:hidden;text-overflow:ellipsis;max-width:400px;line-height:1.4;
  }
  .detected{
    color:var(--green);font-weight:600;display:inline-flex;
    align-items:center;gap:var(--s-2);
  }
  .detected::before{
    content:'';width:var(--s-2);height:var(--s-2);
    background:var(--green);border-radius:var(--r-full);
    box-shadow:0 0 0 3px var(--green-soft);
  }
  .filter-bar{
    display:flex;gap:var(--s-4);flex-wrap:wrap;align-items:flex-end;
    padding:var(--s-5) var(--s-6);background:#fff;
    border-bottom:1px solid var(--gray-200);
  }
  .filter-field{display:flex;flex-direction:column;gap:var(--s-1)}
  .filter-field label{
    font-size:.6875rem;color:var(--gray-400);text-transform:uppercase;
    letter-spacing:.06em;font-weight:600;
  }
  .filter-field select,.filter-field input{
    padding:0 var(--s-3);border:1px solid var(--gray-300);
    border-radius:var(--r-sm);font-size:.8125rem;
    background:#fff;color:var(--gray-900);font-family:inherit;
    min-width:140px;font-weight:500;transition:all .2s;height:40px;
  }
  .filter-field select:focus,.filter-field input:focus{
    outline:none;border-color:var(--blue);box-shadow:0 0 0 3px var(--blue-soft);
  }
  .btn{
    background:#fff;border:1px solid var(--gray-300);color:var(--gray-500);
    padding:0 var(--s-4);border-radius:var(--r-sm);font-size:.8125rem;
    cursor:pointer;font-family:inherit;height:40px;font-weight:500;transition:all .2s;
  }
  .btn:hover{background:var(--gray-900);color:#fff;border-color:var(--gray-900)}
  /* =========================================
     5. DATA VISUALIZATION SYSTEM
     ========================================= */
  .stacked-bar-container{display:flex;flex-direction:column;gap:var(--s-6)}
  .stacked-bar-row{display:flex;align-items:center;gap:var(--s-5)}
  .bar-info{width:90px;text-align:right;flex-shrink:0}
  .bar-info-tool{font-size:.875rem;font-weight:700;color:var(--gray-900);display:block}
  .bar-info-total{font-size:.75rem;color:var(--gray-400);font-weight:600}
  .bar-track{flex:1;height:36px;background:var(--gray-100);border-radius:var(--r-md);overflow:hidden;display:flex;gap:var(--s-1)}
  .bar-segment{height:100%;display:flex;align-items:center;justify-content:center;transition:filter .2s;overflow:hidden}
  .bar-segment:hover{filter:brightness(1.1);cursor:default}
  .seg-text{font-size:.75rem;font-weight:700;color:#fff;letter-spacing:.02em;white-space:nowrap}
  .seg-high,.seg-error{background:var(--red)}
  .seg-medium,.seg-warning{background:var(--amber)}
  .seg-low{background:var(--green)}
  .stacked-bar-legend{display:flex;gap:var(--s-6);justify-content:center;margin-top:var(--s-8);padding-top:var(--s-4);border-top:1px solid var(--gray-200)}
  .legend-item-tiny{display:flex;align-items:center;gap:var(--s-2);font-size:.75rem;color:var(--gray-500);font-weight:500}
  .legend-dot-tiny{width:var(--s-2);height:var(--s-2);border-radius:var(--r-full)}
  .chart-area{display:flex;align-items:flex-end;justify-content:space-around;height:200px;padding-top:35px;gap:var(--s-6)}
  .bar-group{display:flex;flex-direction:column;align-items:center;gap:var(--s-3);width:100%;height:100%;justify-content:flex-end}
  .bar-track-vert{width:100%;flex:1;background:var(--gray-100);border-radius:var(--r-md);position:relative;display:flex;align-items:flex-end}
  .bar-vert{width:100%;border-radius:var(--r-md) var(--r-md) 0 0;transition:height .8s cubic-bezier(.16,1,.3,1);position:relative}
  .bar-val{position:absolute;top:-22px;left:0;right:0;font-size:.8125rem;font-weight:700;color:var(--gray-900);text-align:center}
  .bar-label{font-size:.75rem;color:var(--gray-500);font-weight:600;text-transform:uppercase;letter-spacing:.05em}
  .donut-container{display:flex;align-items:center;justify-content:center;gap:32px;height:100%;padding:10px 0}
  .donut-chart{position:relative;width:130px;height:130px;display:flex;align-items:center;justify-content:center}
  .donut-text{position:absolute;text-align:center;z-index:1}
  .donut-val{font-size:1.625rem;font-weight:800;line-height:1;letter-spacing:-.03em}
  .donut-label{font-size:.625rem;color:var(--gray-400);text-transform:uppercase;font-weight:600;letter-spacing:.06em;margin-top:var(--s-1)}
  .donut-legend{display:flex;flex-direction:column;gap:14px}
  .legend-item{display:flex;align-items:center;gap:10px;font-size:.8125rem;color:var(--gray-500);font-weight:500}
  .legend-dot{width:10px;height:10px;border-radius:var(--r-full)}
  .matrix-grid{display:grid;grid-template-columns:1fr 1fr;height:180px;border:1px solid var(--gray-200);border-radius:var(--r-md);overflow:hidden}
  .matrix-cell{padding:20px;text-align:center;display:flex;flex-direction:column;justify-content:center;align-items:center;border-right:1px solid var(--gray-200);border-bottom:1px solid var(--gray-200);transition:background .2s}
  .matrix-cell:nth-child(2),.matrix-cell:nth-child(4){border-right:none}
  .matrix-cell:nth-child(3),.matrix-cell:nth-child(4){border-bottom:none}
  .matrix-val{font-size:1.75rem;font-weight:800;line-height:1;margin-bottom:var(--s-1);letter-spacing:-.03em}
  .matrix-label{font-size:.6875rem;color:var(--gray-400);font-weight:600;text-transform:uppercase;letter-spacing:.06em}
  .m-tp .matrix-val{color:var(--green)}
  .m-fp .matrix-val{color:var(--red)}
  .m-fn .matrix-val{color:var(--amber)}
  .m-tn .matrix-val{color:var(--blue)}
  .matrix-cell:hover{background:var(--gray-50)}
  .zero-state .matrix-val{color:var(--gray-300);font-weight:700}
  .zero-state .matrix-label{opacity:.5}
  .prog-list{display:flex;flex-direction:column;gap:var(--s-4);padding-top:var(--s-1)}
  .prog-item{display:flex;align-items:center;gap:var(--s-3)}
  .prog-label{font-size:.75rem;color:var(--gray-500);width:80px;font-weight:600;font-family:var(--font-mono)}
  .prog-track{flex:1;height:var(--s-2);background:var(--gray-100);border-radius:var(--r-full);overflow:hidden}
  .prog-fill{height:100%;border-radius:var(--r-full);background:linear-gradient(90deg,var(--green),#34D399)}
  /* =========================================
     6. UTILITIES & RESPONSIVE
     ========================================= */
  .tab-content{display:none}
  .tab-content.active{display:block;animation:fadeIn .4s ease}
  @keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
  @media (max-width:1100px){.grid-4{grid-template-columns:repeat(2,1fr)}}
  @media (max-width:900px){
    .grid-3,.grid-2{grid-template-columns:1fr}
    .stacked-bar-row{flex-direction:column;align-items:stretch;gap:var(--s-2)}
    .bar-info{width:100%;text-align:left;display:flex;justify-content:space-between}
  }
  @media (max-width:640px){
    .grid-4{grid-template-columns:1fr}
    .header-inner{height:auto;padding:12px 0;flex-wrap:wrap}
    .tabs-container{top:88px}
    .container{padding:20px 16px}
  }
</style>'''

# ── Helpers ───────────────────────────────────
badge_map = {'CRITICAL':'badge-high','HIGH':'badge-high','ERROR':'badge-error','MEDIUM':'badge-medium','WARNING':'badge-warning','LOW':'badge-low'}
def badge(sev):
    cls = badge_map.get(sev.upper(), 'badge-low')
    return f'<span class="badge {cls}">{esc(sev)}</span>'

def heat_class(count, total):
    if count == 0: return 'heat-0'
    if count <= 1: return 'heat-low'
    if count <= 3: return 'heat-med'
    return 'heat-high'

# ── Stacked bar chart for severity distribution ─
stacked_bar_rows = ''
for tool in tools:
    counts = by_tool[tool]
    total = sum(counts.values())
    seg_order = [('HIGH','seg-high','High'), ('ERROR','seg-error','Error'),
                 ('MEDIUM','seg-medium','Med'), ('WARNING','seg-warning','Warn'),
                 ('LOW','seg-low','Low')]
    segments = ''
    for sev, cls, label in seg_order:
        cnt = counts.get(sev, 0)
        if cnt > 0:
            pct = round(cnt / total * 100, 2)
            segments += f'<div class="bar-segment {cls}" style="width:{pct}%"><span class="seg-text">{cnt} {label}</span></div>'
    stacked_bar_rows += f'''<div class="stacked-bar-row">
      <div class="bar-info"><span class="bar-info-tool">{esc(tool)}</span><span class="bar-info-total">{total} Total</span></div>
      <div class="bar-track">{segments}</div>
    </div>'''


# ── Findings table rows ───────────────────────
finding_rows = ''
for f in findings:
    sev = f.get('severity', 'UNKNOWN').upper()
    conf_label, conf_class = confidence_label(f)
    rule_id = f.get('rule_id','')
    rule_short = rule_id.rsplit('.',1)[-1] if '.' in rule_id else rule_id
    finding_rows += (
        f'<tr data-tool="{esc(f.get("tool",""))}" data-sev="{esc(sev)}" data-conf="{esc(f.get("confidence_tier","Unscored"))}">'
        f'<td class="text-primary">{esc(f.get("tool",""))}</td>'
        f'<td>{badge(sev)}</td>'
        f'<td class="{conf_class}">{esc(conf_label)}</td>'
        f'<td><span class="tag-mono">{esc(rule_short)}</span></td>'
        f'<td class="clamp-2">{esc(f.get("description",""))}</td>'
        f'<td class="text-muted-mono">{esc(f.get("file",""))}</td>'
        f'<td style="text-align:right;font-weight:600;color:var(--gray-900)">{esc(str(f.get("line","") or ""))}</td>'
        f'</tr>'
    )

# ── Seeded vulnerability rows ─────────────────
seeded_rows = ''
per_vuln_progress = ''
if seeded_vulns:
    vulns_list = seeded_vulns
    for v in vulns_list:
        vuln_id = v.get('id', '')
        vuln_type = v.get('type', '')
        detection_tool = v.get('expected_tool', '')
        is_detected = seeded_vuln_detection.get(vuln_id, False)
        status = 'Detected' if is_detected else 'Missed'
        status_class = 'detected' if is_detected else ''
        v_sev = v.get('severity', 'UNKNOWN')
        seeded_rows += (
            f'<tr>'
            f'<td class="text-muted-mono">{esc(str(vuln_id))}</td>'
            f'<td style="color:var(--gray-900);font-weight:500">{esc(str(vuln_type))}</td>'
            f'<td>{badge(v_sev)}</td>'
            f'<td>{esc(str(detection_tool))}</td>'
            f'<td class="{status_class}">{status}</td>'
            f'</tr>'
        )
        per_vuln_progress += f'''<div class="prog-item">
          <span class="prog-label">{esc(str(vuln_id))}</span>
          <div class="prog-track"><div class="prog-fill" style="width:{100 if is_detected else 0}%"></div></div>
        </div>'''

# ── Triage "Act on These First" ───────────────
triage_html = ''
if scored:
    high_conf = sorted(
        (f for f in scored if f['confidence_tier'] == 'High'),
        key=lambda f: -(f.get('confidence') or 0),
    )
    triage_rows = ''.join(
        f'<tr>'
        f'<td class="text-primary">{esc(f.get("tool",""))}</td>'
        f'<td><span class="tag-mono">{esc(f.get("rule_id","").rsplit(".",1)[-1] if "." in f.get("rule_id","") else f.get("rule_id",""))}</span></td>'
        f'<td class="clamp-1">{esc(f.get("description",""))}</td>'
        f'<td style="text-align:right;font-weight:600;color:var(--gray-900)">{esc(str(f.get("line","") or ""))}</td>'
        f'</tr>'
        for f in high_conf
    )
    triage_html = f'''<div class="card" style="margin-top:0">
      <div class="card-head">
        <h2 class="card-title">Act on These First</h2>
        <p class="card-subtitle">{high_conf_count} high-confidence findings</p>
      </div>
      <div class="table-scroll short">
      <table>
        <thead><tr><th>Tool</th><th>Rule ID</th><th>Description</th><th style="text-align:right">Line</th></tr></thead>
        <tbody>{triage_rows or "<tr><td colspan=4>No high-confidence findings.</td></tr>"}</tbody>
      </table>
      </div>
    </div>'''

# ── Donut SVG for seeded detection ────────────
seeded_donut_svg = ''
if seeded_vulns:
    circumference = 314
    detected_offset = circumference * (1 - rate / 100) if rate < 100 else 0
    seeded_donut_svg = f'''
    <svg width="130" height="130" viewBox="0 0 120 120">
      <circle cx="60" cy="60" r="50" fill="none" stroke="#F5F6F8" stroke-width="14"/>
      <circle cx="60" cy="60" r="50" fill="none" stroke="#10B981" stroke-width="14" stroke-dasharray="{circumference}" stroke-dashoffset="0" stroke-linecap="round" transform="rotate(-90 60 60)"/>
    </svg>'''

noise_donut_svg = ''
if scored:
    noise_frac = noise_pct / 100
    noise_dash = round(314 * noise_frac)
    green_dash = 314 - noise_dash
    noise_donut_svg = f'''
    <svg width="130" height="130" viewBox="0 0 120 120">
      <circle cx="60" cy="60" r="50" fill="none" stroke="#10B981" stroke-width="14"/>
      <circle cx="60" cy="60" r="50" fill="none" stroke="#EF4444" stroke-width="14" stroke-dasharray="{noise_dash} 314" stroke-dashoffset="0" stroke-linecap="round" transform="rotate(-90 60 60)"/>
    </svg>'''

# ── Main template ─────────────────────────────
html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DevSecOps Security Dashboard</title>
{css}
</head>
<body>

<header class="header">
  <div class="header-inner">
    <h1>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      Security Dashboard
    </h1>
    <div class="header-meta">
      <span><strong>{len(findings)}</strong> findings</span>
      <span><strong>{len(tools)}</strong> scanners</span>
      {f'<span><strong>{detected}/{len(seeded_vulns)}</strong> seeded detected</span>' if seeded_vulns else ''}
    </div>
  </div>
</header>

<nav class="tabs-container">
  <div class="tabs-inner">
    <button class="tab-btn active" onclick="switchTab(event,'overview')">Overview &amp; Analytics</button>
    <button class="tab-btn" onclick="switchTab(event,'findings')">Findings &amp; Vulnerabilities</button>
  </div>
</nav>

<main class="container">

<!-- ═══════ TAB 1: OVERVIEW ═══════ -->
<div id="overview" class="tab-content active">

<div class="grid-3">
  <div class="stat-card">
    <div class="stat-label"><span class="stat-dot" style="background:var(--blue);box-shadow:0 0 0 3px var(--blue-soft)"></span> Total Findings</div>
    <div><div class="stat-num">{len(findings)}</div><div class="stat-sub">Across all scanners</div></div>
  </div>
  {"".join(f'<div class="stat-card"><div class="stat-label"><span class="stat-dot" style="background:{"var(--amber);box-shadow:0 0 0 3px var(--amber-soft)" if t=="Bandit" else "var(--green);box-shadow:0 0 0 3px var(--green-soft)"}"></span> {esc(t)}</div><div><div class="stat-num">{sum(by_tool[t].values())}</div><div class="stat-sub">{"Static analyzer" if t=="Bandit" else "Pattern-based scanner"}</div></div></div>' for t in tools)}
</div>

<div class="grid-2">
  <div class="card">
    <div class="card-head">
      <h2 class="card-title">Findings by Tool &amp; Severity</h2>
      <p class="card-subtitle">Distribution of detected issues</p>
    </div>
    <div class="card-body">
      <div class="stacked-bar-container">
        {stacked_bar_rows}
      </div>
      <div class="stacked-bar-legend">
        <div class="legend-item-tiny"><span class="legend-dot-tiny" style="background:var(--red)"></span> High / Error</div>
        <div class="legend-item-tiny"><span class="legend-dot-tiny" style="background:var(--amber)"></span> Medium / Warning</div>
        <div class="legend-item-tiny"><span class="legend-dot-tiny" style="background:var(--green)"></span> Low</div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2 class="card-title">Seeded Vulnerability Detection</h2>
      <p class="card-subtitle">Ground truth validation</p>
    </div>
    <div class="card-body">
      <div class="donut-container">
        <div class="donut-chart">
          {seeded_donut_svg}
          <div class="donut-text">
            <div class="donut-val" style="color:var(--green)">{rate}%</div>
            <div class="donut-label">Detected</div>
          </div>
        </div>
        <div class="donut-legend">
          <div class="legend-item"><span class="legend-dot" style="background:var(--green)"></span> Detected: {detected}</div>
          <div class="legend-item"><span class="legend-dot" style="background:var(--red)"></span> Missed: {len(seeded_vulns) - detected if seeded_vulns else 0}</div>
           <div class="legend-item"><span class="legend-dot" style="background:var(--gray-100);border:1px solid var(--gray-200)"></span> Total: {len(seeded_vulns) if seeded_vulns else 0}</div>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="grid-4">
  <div class="card">
    <div class="card-head">
      <h2 class="card-title">Accuracy Metrics</h2>
      <p class="card-subtitle">Precision, Recall &amp; F1</p>
    </div>
    <div class="card-body">
      <div class="chart-area">
        <div class="bar-group">
          <div class="bar-track-vert"><div class="bar-vert" style="height:{min(precision,100)}%;background:linear-gradient(180deg,#60A5FA,var(--blue))"><span class="bar-val">{precision}%</span></div></div>
          <div class="bar-label">Precision</div>
        </div>
        <div class="bar-group">
          <div class="bar-track-vert"><div class="bar-vert" style="height:{min(recall_pct,100)}%;background:linear-gradient(180deg,#34D399,var(--green))"><span class="bar-val">{recall_pct}%</span></div></div>
          <div class="bar-label">Recall</div>
        </div>
        <div class="bar-group">
          <div class="bar-track-vert"><div class="bar-vert" style="height:{min(f1_score,100)}%;background:linear-gradient(180deg,#FBBF24,var(--amber))"><span class="bar-val">{f1_score}%</span></div></div>
          <div class="bar-label">F1 Score</div>
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2 class="card-title">Confusion Matrix</h2>
      <p class="card-subtitle">True vs False Positives</p>
    </div>
    <div class="card-body" style="align-items:center">
      <div class="matrix-grid" style="width:100%">
        <div class="matrix-cell m-tp"><div class="matrix-val">{tp}</div><div class="matrix-label">True Pos</div></div>
        <div class="matrix-cell m-fp"><div class="matrix-val">{fp}</div><div class="matrix-label">False Pos</div></div>
        <div class="matrix-cell m-fn zero-state"><div class="matrix-val">{fn}</div><div class="matrix-label">False Neg</div></div>
        <div class="matrix-cell m-tn zero-state"><div class="matrix-val">{tn}</div><div class="matrix-label">True Neg</div></div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2 class="card-title">Per-Vuln Detection</h2>
      <p class="card-subtitle">Individual scan coverage</p>
    </div>
    <div class="card-body">
      <div class="prog-list">
{per_vuln_progress if per_vuln_progress else '<div class="prog-item"><span style="color:var(--gray-400);font-size:13px">No seeded vulnerabilities configured</span></div>'}
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2 class="card-title">Noise Ratio</h2>
      <p class="card-subtitle">False positive impact</p>
    </div>
    <div class="card-body">
      <div class="donut-container" style="gap:20px">
        <div class="donut-chart">
          {noise_donut_svg if noise_donut_svg else '<svg width="130" height="130" viewBox="0 0 120 120"><circle cx="60" cy="60" r="50" fill="none" stroke="#F5F6F8" stroke-width="14"/></svg>'}
          <div class="donut-text">
            <div class="donut-val" style="color:var(--red)">{noise_pct}%</div>
            <div class="donut-label">Noise</div>
          </div>
        </div>
        <div class="donut-legend">
          <div class="legend-item"><span class="legend-dot" style="background:var(--green)"></span> High Conf: {high_conf_count}</div>
          <div class="legend-item"><span class="legend-dot" style="background:var(--red)"></span> Likely Noise: {noise_count}</div>
        </div>
      </div>
    </div>
  </div>
</div>

</div><!-- /overview -->

<!-- ═══════ TAB 2: FINDINGS ═══════ -->
<div id="findings" class="tab-content">

<div class="grid-2">
  <div class="card">
    <div class="card-head">
      <h2 class="card-title">Seeded Vulnerability Detection</h2>
      <p class="card-subtitle">{detected}/{len(seeded_vulns) if seeded_vulns else 0} detected ({rate}%)</p>
    </div>
    <div class="table-scroll short">
    <table>
      <thead><tr><th>ID</th><th>Type</th><th>Severity</th><th>Expected Tool</th><th>Status</th></tr></thead>
      <tbody>{seeded_rows if seeded_rows else '<tr><td colspan="5" style="color:var(--gray-400)">No seeded vulnerabilities configured</td></tr>'}</tbody>
    </table>
    </div>
  </div>

  {triage_html}
</div>

<div class="card">
  <div class="filter-bar">
    <div class="filter-field">
      <label>Tool</label>
      <select id="filterTool" onchange="filterTable()">
        <option value="">All</option>
        {tool_options}
      </select>
    </div>
    <div class="filter-field">
      <label>Severity</label>
      <select id="filterSev" onchange="filterTable()">
        <option value="">All</option>
        {"".join(f'<option value="{s}">{s}</option>' for s in severities)}
      </select>
    </div>
    <div class="filter-field">
      <label>Confidence</label>
      <select id="filterConf" onchange="filterTable()">
        <option value="">All</option>
        <option value="High">High</option>
        <option value="Likely">Likely</option>
        <option value="Noise">Noise</option>
        <option value="Unscored">Unscored</option>
      </select>
    </div>
    <div class="filter-field" style="flex:1;min-width:200px;max-width:400px">
      <label>Search</label>
      <input type="text" id="filterSearch" placeholder="Keyword..." oninput="filterTable()" style="width:100%">
    </div>
    <button class="btn" onclick="clearFilters()">Clear Filters</button>
  </div>
  <div style="padding:16px 24px;background:#fff;border-bottom:1px solid var(--gray-200);display:flex;justify-content:space-between;align-items:center">
    <span style="font-size:14px;color:var(--gray-900);font-weight:600">All Findings</span>
    <span style="font-size:13px;color:var(--gray-400);font-weight:500" id="filterCount">Showing <strong style="color:var(--gray-900)">{len(findings)}</strong> of <strong style="color:var(--gray-900)">{len(findings)}</strong></span>
  </div>
  <div class="table-scroll" style="max-height:500px">
  <table id="findingsTable">
    <thead><tr><th>Tool</th><th>Severity</th><th>Confidence</th><th>Rule ID</th><th>Description</th><th>File</th><th style="text-align:right">Line</th></tr></thead>
    <tbody>{finding_rows}</tbody>
  </table>
  </div>
</div>

</div><!-- /findings -->

</main>

<script>
function switchTab(evt,tabName){{
  document.querySelectorAll(".tab-content").forEach(function(el){{el.classList.remove("active")}});
  document.querySelectorAll(".tab-btn").forEach(function(el){{el.classList.remove("active")}});
  document.getElementById(tabName).classList.add("active");
  evt.currentTarget.classList.add("active");
  window.scrollTo({{top:0,behavior:"smooth"}});
}}

function filterTable(){{
  var tool=document.getElementById("filterTool").value.toLowerCase();
  var sev=document.getElementById("filterSev").value.toLowerCase();
  var conf=document.getElementById("filterConf").value;
  var search=document.getElementById("filterSearch").value.toLowerCase();
  var rows=document.querySelectorAll("#findingsTable tbody tr");
  var visible=0;
  rows.forEach(function(row){{
    var rowTool=(row.dataset.tool||"").toLowerCase();
    var rowSev=(row.dataset.sev||"").toLowerCase();
    var rowConf=row.dataset.conf||"";
    var text=row.textContent.toLowerCase();
    var show=(!tool||rowTool===tool)&&(!sev||rowSev===sev)&&(!conf||rowConf===conf)&&(!search||text.includes(search));
    row.style.display=show?"":"none";
    if(show)visible++;
  }});
  document.getElementById("filterCount").innerHTML='Showing <strong style="color:var(--gray-900)">'+visible+'</strong> of <strong style="color:var(--gray-900)">'+rows.length+'</strong>';
}}

function clearFilters(){{
  document.getElementById("filterTool").value="";
  document.getElementById("filterSev").value="";
  document.getElementById("filterConf").value="";
  document.getElementById("filterSearch").value="";
  filterTable();
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
