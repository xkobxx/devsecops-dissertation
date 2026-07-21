# Research Methodology

The confidence-scoring engine (the paid feature) and the dissertation's own precision/recall research share the same ground truth. This doc covers both.

## The Seeded Vulnerability Fixture

`test_app/app.py` has 6 deliberately seeded vulnerabilities — a fully-enumerated ground truth used both for the dissertation's precision/recall research and as the corpus behind `confidence_table.json`.

| ID | Vulnerability | CWE | Severity | Expected Tool |
|----|--------------|-----|----------|---------------|
| VULN-001 | Hardcoded Credentials | CWE-798 | HIGH | Bandit |
| VULN-002 | SQL Injection | CWE-89 | HIGH | Bandit / Semgrep |
| VULN-003 | OS Command Injection | CWE-78 | HIGH | Bandit / Semgrep |
| VULN-004 | Code Injection (eval) | CWE-94 | HIGH | Bandit / Semgrep |
| VULN-005 | Unvalidated Redirect | CWE-601 | MEDIUM | Semgrep |
| VULN-006 | Path Traversal | CWE-22 | HIGH | Bandit / Semgrep |

## Measuring Effectiveness

The pipeline runs **5 times** against the same app and results are compared to the ground truth.

```bash
cp reports/findings.json results/run_1/findings.json   # repeat for run_2 … run_5
python scripts/calculate_metrics.py       # → results/metrics_summary.json
python scripts/visualise_results.py       # → reports/charts/ (4 PNG charts)
```

### Results Summary

| Tool | Precision | Recall | F1 |
|------|-----------|--------|----|
| Bandit | 0.571 | 0.800 | 0.666 |
| Semgrep | 0.625 | 1.000 | 0.769 |

## How the confidence layer uses this

`confidence_table.json` is built from `scripts/build_confidence_table.py`, which matches historical scanner findings against this same seeded fixture and computes real precision per `(tool, rule)`. Tools with no ground-truth coverage for their finding type (today: pip-audit, Trivy, Gitleaks) are excluded rather than scored — an empty ground truth would otherwise produce a fake 0% precision, and that's exactly the kind of unearned confidence number this project exists to avoid.

**Honesty, up front:** today's corpus is one small fixture with 6 seeded vulnerabilities. Per-rule sample sizes are tiny (often 1-3) — every table entry carries its own `sample_size` so this is visible rather than hidden. Treat published numbers as directional until the corpus grows. The matching method (±5-line proximity) can also spuriously match an unrelated finding to a nearby seeded vuln in dense files — a known, disclosed limitation, not a hidden one.
