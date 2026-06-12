# DevSecOps Dissertation

A security pipeline that automatically scans a vulnerable Python Flask app every time code is pushed to GitHub. If it finds serious problems, the build fails and nothing ships until they are fixed.

> **In simple words:** think of it as a metal detector at an airport — every time code goes through, it gets checked. Bad stuff gets flagged before it ever reaches production.

---

## What Does It Do?

Six security tools run automatically in parallel on every push:

| Tool | What It Checks |
|------|---------------|
| **Bandit** | Python code — hardcoded passwords, unsafe functions |
| **Semgrep** | Python code — injection flaws, data flow patterns |
| **OWASP ZAP** | The running app — live HTTP requests and responses |
| **pip-audit** | Dependencies — known vulnerable packages |
| **Trivy** | Docker and config files — misconfigurations |
| **Gitleaks** | Git history — accidentally committed secrets |

After all tools finish, a **Security Gate** reads the results. If anything HIGH or CRITICAL is found, the build fails automatically.

---

## Quick Start

```bash
# Install tools
pip install bandit semgrep pip-audit flask
brew install trivy        # macOS only

# Run all scanners
bandit -r test-app/ -f json -o reports/bandit_report.json
semgrep --config=p/python --json --output reports/semgrep_report.json test-app/
pip-audit -r test-app/requirements.txt --format json -o reports/pip_audit_report.json
trivy config . --format json --output reports/trivy_report.json
docker run --rm -v "$PWD":/repo ghcr.io/gitleaks/gitleaks:latest \
  detect --source /repo --report-format json \
  --report-path /repo/reports/gitleaks_report.json --exit-code 0

# Aggregate results and generate report
python scripts/aggregate_results.py    # → reports/findings.json
python scripts/generate_report.py      # → reports/dashboard.html
```

Open `reports/dashboard.html` in your browser to see the results.

---

## Tool Versions

| Tool | Version |
|------|---------|
| Python | 3.11.x |
| Flask | 3.1.1 |
| Bandit | 1.9.4 |
| Semgrep | 1.156.0 |
| pip-audit | latest |
| Trivy | latest |
| Gitleaks | latest |
| Docker | latest |

---

## Project Structure

```
devsecops-dissertation/
├── test-app/
│   ├── app.py                       # Vulnerable Flask app (6 seeded vulnerabilities)
│   ├── seeded_vulnerabilities.json  # Ground truth — what tools should find
│   └── requirements.txt
├── scripts/
│   ├── aggregate_results.py         # Merges all reports → findings.json + security gate
│   ├── generate_report.py           # Builds the HTML dashboard
│   ├── calculate_metrics.py         # Precision / recall / F1 across 5 runs
│   └── visualise_results.py         # Generates 4 metric charts
├── reports/                         # All scan output lives here
├── results/run_1 … run_5/           # findings.json per experiment run
├── docs/                            # Screenshots and pipeline diagram
├── .github/workflows/devsecops.yml  # GitHub Actions pipeline definition
└── docker-compose.yml               # Vulnerable apps for DAST testing
```

---

## The Test Application

`test-app/app.py` has 6 deliberately seeded vulnerabilities — put there on purpose so we can check the tools actually find them.

| ID | Vulnerability | CWE | Severity | Expected Tool |
|----|--------------|-----|----------|---------------|
| VULN-001 | Hardcoded Credentials | CWE-798 | HIGH | Bandit |
| VULN-002 | SQL Injection | CWE-89 | HIGH | Bandit / Semgrep |
| VULN-003 | OS Command Injection | CWE-78 | HIGH | Bandit / Semgrep |
| VULN-004 | Code Injection (eval) | CWE-94 | HIGH | Bandit / Semgrep |
| VULN-005 | Unvalidated Redirect | CWE-601 | MEDIUM | Semgrep |
| VULN-006 | Path Traversal | CWE-22 | HIGH | Bandit / Semgrep |

---

## Running the Pipeline Step by Step

All commands run from the repo root unless stated otherwise.

### 1. Start the Flask app
```bash
cd test-app
python app.py    # runs at http://localhost:5000
```

### 2. Run SAST (static code scan)
```bash
bandit -r test-app/ -f json -o reports/bandit_report.json
semgrep --config=p/python --json --output reports/semgrep_report.json test-app/
```

### 3. Run SCA (dependency check)
```bash
pip-audit -r test-app/requirements.txt --format json -o reports/pip_audit_report.json
```

### 4. Run config scan
```bash
trivy config . --format json --output reports/trivy_report.json
```

### 5. Run secrets scan
```bash
docker run --rm -v "$PWD":/repo ghcr.io/gitleaks/gitleaks:latest \
  detect --source /repo --report-format json \
  --report-path /repo/reports/gitleaks_report.json --exit-code 0
```

### 6. Aggregate and run the security gate
```bash
python scripts/aggregate_results.py
# Fails with exit code 1 if HIGH/CRITICAL findings from Bandit or Semgrep exist
```

### 7. Generate the dashboard
```bash
python scripts/generate_report.py
# Open reports/dashboard.html in a browser
```

---

## Measuring Effectiveness

The pipeline runs **5 times** against the same app and results are compared to the ground truth.

```bash
# After each run, save findings
cp reports/findings.json results/run_1/findings.json   # repeat for run_2 … run_5

# Calculate precision, recall, F1
python scripts/calculate_metrics.py
# → results/metrics_summary.json

# Generate charts
python scripts/visualise_results.py
# → reports/charts/ (4 PNG charts)
```

### Results Summary

| Tool | Precision | Recall | F1 |
|------|-----------|--------|----|
| Bandit | 0.571 | 0.800 | 0.666 |
| Semgrep | 0.625 | 1.000 | 0.769 |

---

## DAST Test Apps

Three well-known vulnerable apps for dynamic testing — run locally via Docker:

```bash
docker-compose up -d    # start
docker-compose down     # stop
```

| App | URL | Notes |
|-----|-----|-------|
| DVWA | http://localhost:8081 | Click **Setup / Reset DB** on first visit. Login: `admin` / `password` |
| Juice Shop | http://localhost:3000 | No login needed. Visit `/score-board` to see all challenges |
| WebGoat | http://localhost:8080/WebGoat | Register a local account, then work through the lessons |

---

## CI/CD Pipeline

Runs automatically on every push to `main`.

```
sast-bandit ──────────────┐
sast-semgrep ─────────────┤
dast-zap ─────────────────┤──→ security-gate ──→ generate-dashboard
sca-pip-audit ────────────┤
container-scan-trivy ─────┤
secrets-scan-gitleaks ────┘
```

The **security gate** fails the build if Bandit or Semgrep find anything HIGH or CRITICAL. All scan reports are downloadable as artifacts from the GitHub Actions run summary.

---

## GitHub Repository

**https://github.com/xkobxx/devsecops-dissertation**