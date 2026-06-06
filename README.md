# DevSecOps Dissertation

A DevSecOps pipeline that automatically detects security vulnerabilities in a deliberately vulnerable Python Flask application. Built for a dissertation on integrating security tooling into CI/CD workflows.

> **In plain terms:** every time code is pushed to GitHub, a series of security scanners run automatically. If serious problems are found, the pipeline fails and nothing ships until they are fixed — a safety net built into the development process itself.

---

## Quick Start

> All commands are run from the **repository root** (`devsecops-dissertation/`) unless stated otherwise.

```bash
# 1. Install tools
pip install bandit semgrep pip-audit flask
brew install trivy          # macOS (Trivy container/config scanner)
# Docker must also be installed and running.

# 2. Run all scanners and build the report
bandit -r test-app/ -f json -o reports/bandit_report.json
semgrep --config=p/owasp-2021 --json --output reports/semgrep_report.json test-app/
pip-audit -r test-app/requirements.txt --format json -o reports/pip_audit_report.json
trivy config . --format json --output reports/trivy_report.json
docker run --rm -v "$PWD":/repo ghcr.io/gitleaks/gitleaks:latest \
  detect --source /repo --report-format json \
  --report-path /repo/reports/gitleaks_report.json --exit-code 0

python scripts/aggregate_results.py      # → reports/findings.json (+ security gate)
python scripts/generate_report.py        # → reports/dashboard.html
```

Open `reports/dashboard.html` in a browser to view the results.
Full step-by-step explanations are in [Running the Pipeline](#running-the-pipeline).

---

## Key Terms

| Term | Full Name | What It Means |
|------|-----------|---------------|
| **DevSecOps** | Development, Security, Operations | A practice of baking security checks directly into the software development and deployment process, rather than treating security as an afterthought at the end. |
| **SAST** | Static Application Security Testing | Scanning source code *without running it* — like proofreading a recipe for dangerous ingredients before cooking anything. Tools read the code and flag risky patterns. |
| **DAST** | Dynamic Application Security Testing | Scanning a *running* application by sending it real requests and watching how it responds — like actually trying to pick the lock rather than just reading the blueprints. |
| **SCA** | Software Composition Analysis | Checking the third-party packages (libraries) your project depends on for known security vulnerabilities — like checking whether the ingredients you bought from a supplier have been recalled. |
| **Bandit** | — | A SAST tool built specifically for Python. It reads through Python code and flags well-known dangerous patterns such as hardcoded passwords, code injection sinks, and unsafe subprocess calls. |
| **Semgrep** | Semantic Grep | A SAST tool that scans code using customisable rules. It can detect complex multi-line vulnerability patterns across many languages. Used here with the OWASP Top 10 ruleset. |
| **pip-audit** | — | An SCA tool for Python projects. It checks your `requirements.txt` against a database of known vulnerable package versions and reports anything that needs updating. |
| **Trivy** | — | A container and configuration scanner. It checks Docker files and infrastructure configs for security misconfigurations and known CVEs (published vulnerability records). |
| **Gitleaks** | — | A secrets scanner that searches your entire git history for accidentally committed sensitive data — API keys, passwords, tokens — that should never have been pushed. |
| **OWASP** | Open Worldwide Application Security Project | A non-profit that publishes the most widely referenced list of web security risks (the OWASP Top 10). The scanning rules used in this project are based on their guidelines. |
| **CVE** | Common Vulnerabilities and Exposures | A publicly catalogued security flaw in a piece of software, assigned a unique ID (e.g. CVE-2024-1234) so everyone uses the same reference when discussing it. |
| **CI/CD** | Continuous Integration / Continuous Deployment | An automated pipeline that builds, tests, and deploys code every time a change is pushed — this project adds security scanning as a mandatory step in that pipeline. |
| **Security Gate** | — | A checkpoint in the pipeline that reads all scan results and deliberately fails the build if any high or critical vulnerabilities are found, blocking deployment until they are fixed. |
| **Flask** | — | A lightweight Python web framework used here to build the deliberately vulnerable test application that the scanners are tested against. |
| **ZAP** | Zed Attack Proxy | A DAST tool by OWASP that scans a *running* web application by sending real HTTP requests and observing how it responds. Unlike SAST tools that read code, ZAP finds vulnerabilities that only appear when the app is live — such as missing security headers, exposed error messages, and unprotected endpoints. |

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

```text
devsecops-dissertation/
├── test-app/
│   ├── app.py                      # Deliberately vulnerable Flask app (6 seeded vulns)
│   ├── seeded_vulnerabilities.json # Ground truth: catalogue of known vulnerabilities
│   └── requirements.txt
├── scripts/
│   ├── aggregate_results.py        # Aggregates all scan reports → findings.json (+ security gate)
│   ├── generate_report.py          # Generates the HTML dashboard from findings.json
│   ├── calculate_metrics.py        # Precision / recall / F1 across 5 runs → metrics_summary.json
│   ├── visualise_results.py        # Renders the 4 dissertation charts → reports/charts/
│   └── record_run.py               # Logs a single pipeline run → results/experiment_log.json
├── reports/
│   ├── bandit_report.json          # Bandit SAST output
│   ├── semgrep_report.json         # Semgrep SAST output
│   ├── pip_audit_report.json       # pip-audit SCA output
│   ├── trivy_report.json           # Trivy container/config scan output
│   ├── gitleaks_report.json        # Gitleaks secrets scan output
│   ├── findings.json               # Unified aggregated findings
│   ├── dashboard.html              # Interactive HTML report dashboard
│   └── charts/                     # Generated metric charts (PNG)
├── results/
│   ├── run_1/ … run_5/             # findings.json captured per experiment run
│   ├── ground_truth.json           # Expected detections per tool
│   ├── metrics_summary.json        # Aggregated precision/recall/F1 (mean ± 95% CI)
│   └── experiment_log.{json,md}    # Per-run experiment log
├── docs/                           # Pipeline diagram, screenshots, PoC images
├── .github/workflows/
│   └── devsecops.yml               # GitHub Actions CI/CD pipeline
├── docker-compose.yml              # Vulnerable apps for DAST testing
└── .agent/system/
    └── project_architecture.md     # Full architecture reference
```

---

## Seeded Vulnerabilities

The test app (`test-app/app.py`) contains 6 intentional vulnerabilities used to validate the tools:

| ID | Type | CWE | Severity | Expected Tool |
|----|------|-----|----------|---------------|
| VULN-001 | Hardcoded Credentials | CWE-798 | HIGH | Bandit |
| VULN-002 | SQL Injection | CWE-89 | HIGH | Bandit / Semgrep |
| VULN-003 | OS Command Injection | CWE-78 | HIGH | Bandit / Semgrep |
| VULN-004 | Code Injection (eval) | CWE-94 | HIGH | Bandit / Semgrep |
| VULN-005 | Unvalidated Redirect | CWE-601 | MEDIUM | Semgrep |
| VULN-006 | Path Traversal | CWE-22 | HIGH | Bandit / Semgrep |

---

## Running the Pipeline

The [Quick Start](#quick-start) runs everything at once. Below is each step explained individually. All commands run from the repository root.

### 1. Start the Flask test app

*Switches on the deliberately vulnerable app so the scanners have a live target.*

```bash
cd test-app
python app.py        # App runs at http://localhost:5000
```

### 2. Run SAST scans

*Two tools read the source code and flag dangerous patterns — hardcoded passwords, injection points, and similar.*

```bash
bandit -r test-app/ -f json -o reports/bandit_report.json
semgrep --config=p/owasp-2021 --json --output reports/semgrep_report.json test-app/
```

### 3. Run SCA (dependency scanning)

*Checks the project's third-party packages for known security flaws.*

```bash
pip-audit -r test-app/requirements.txt --format json -o reports/pip_audit_report.json
```

### 4. Run container / config scanning

*Checks the Docker and infrastructure config files for security misconfigurations.*

```bash
trivy config . --format json --output reports/trivy_report.json
```

### 5. Run secrets scanning

*Scans the entire git history for accidentally committed passwords, API keys, or tokens.*

```bash
docker run --rm -v "$PWD":/repo ghcr.io/gitleaks/gitleaks:latest \
  detect --source /repo --report-format json \
  --report-path /repo/reports/gitleaks_report.json \
  --exit-code 0
```

### 6. Aggregate findings and run the security gate

*Combines all scan results into one report and fails the build if anything serious is found.*

```bash
python scripts/aggregate_results.py
# Output: reports/findings.json
# Exits with code 1 if HIGH/CRITICAL findings from Bandit or Semgrep are detected.
```

### 7. Generate the HTML dashboard

*Turns the raw results into a readable, colour-coded page filterable by tool and severity.*

```bash
python scripts/generate_report.py
# Output: reports/dashboard.html — open in a browser.
```

---

## Measuring Effectiveness

To evaluate detection quality, the pipeline is run **5 times** and the results compared against the ground truth in `test-app/seeded_vulnerabilities.json`.

**1. Capture each run.** After running the pipeline, copy the findings into a numbered run folder:

```bash
cp reports/findings.json results/run_1/findings.json   # repeat for run_2 … run_5
```

**2. Calculate metrics** across all 5 runs:

```bash
python scripts/calculate_metrics.py
# Output: results/metrics_summary.json (precision, recall, F1, false positives — mean ± 95% CI)
```

**3. Generate charts:**

```bash
python scripts/visualise_results.py
# Output: reports/charts/chart1_precision_recall_f1.png, chart2_confusion_matrices.png,
#         chart3_per_vuln_detection.png, chart4_false_positives.png
```

*Optional:* `python scripts/record_run.py [run_number] [scenario]` logs a single run's metrics to `results/experiment_log.json`.

### Current Results

| Tool | Precision | Recall | F1 |
|------|-----------|--------|-----|
| Bandit | 0.571 | 0.800 | 0.666 |
| Semgrep | 0.625 | 1.000 | 0.769 |

---

## Vulnerable Apps for DAST

Spin up three well-known deliberately vulnerable web apps as live targets for dynamic (running-app) testing:

```bash
docker-compose up -d     # start
docker-compose down      # stop
```

| App | URL | Purpose |
|-----|-----|---------|
| DVWA | <http://localhost:8081> | Damn Vulnerable Web Application |
| OWASP Juice Shop | <http://localhost:3000> | Modern vulnerable Node.js app |
| WebGoat | <http://localhost:8080/WebGoat> | Java-based security training app |

- **DVWA** — A classic PHP app built to be hacked. On first visit click **Setup / Reset DB**, then log in with `admin` / `password`. Pick a vulnerability category from the left menu; adjust difficulty under **DVWA Security** (start on Low).
- **OWASP Juice Shop** — A modern shop full of flaws; no login needed. A built-in **Score Board** (`/score-board`) lists all challenges and tracks progress.
- **WebGoat** — A structured training platform. Click **Register** to create a local account, then work through the lessons in the left sidebar (each explains a vulnerability and gives you a live form to exploit).

---

## CI/CD Pipeline

The GitHub Actions pipeline (`.github/workflows/devsecops.yml`) runs automatically on push or pull request to `main`.

```text
sast-bandit ──────────────────────────┐
sast-semgrep ─────────────────────────┤
dast-zap ─────────────────────────────┤─→ security-gate → generate-dashboard
sca-pip-audit ────────────────────────┤
container-scan-trivy ─────────────────┤
secrets-scan-gitleaks ────────────────┘
```

| Job | Tool | Type | Artifact |
|-----|------|------|----------|
| `sast-bandit` | Bandit | SAST | `bandit-report` |
| `sast-semgrep` | Semgrep | SAST | `semgrep-report` |
| `dast-zap` | OWASP ZAP | DAST | `zap-report` |
| `sca-pip-audit` | pip-audit | SCA | `pip-audit-report` |
| `container-scan-trivy` | Trivy | Container/Config | `trivy-report` |
| `secrets-scan-gitleaks` | Gitleaks | Secrets | `gitleaks-report` |
| `security-gate` | — | Aggregation | `unified-findings` |
| `generate-dashboard` | — | Reporting | `dashboard` |

**Security Gate:** the build fails if any **HIGH** or **CRITICAL** finding is detected by Bandit or Semgrep. All scan artifacts are downloadable from the GitHub Actions run summary.

---

## Reports

All reports are written to the `reports/` directory.

| File | Contents |
|------|----------|
| `bandit_report.json` | Raw Bandit findings |
| `semgrep_report.json` | Raw Semgrep findings |
| `pip_audit_report.json` | Vulnerable dependencies |
| `trivy_report.json` | Container/config issues |
| `gitleaks_report.json` | Detected secrets |
| `findings.json` | Unified findings from all tools |
| `dashboard.html` | Interactive HTML report — open in browser |
| `charts/` | Generated metric charts (PNG) |
