# DevSecOps Dissertation

A DevSecOps pipeline that demonstrates automated security vulnerability detection across a deliberately vulnerable Python Flask application. Built as part of a dissertation on integrating security tooling into CI/CD workflows.

<!-- In plain terms: every time code is pushed to GitHub, a series of security scanners run automatically. If the code has serious security problems, the pipeline fails and nothing gets deployed until they are fixed. It is a safety net built into the development process itself. -->

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
│   ├── app.py                     # Deliberately vulnerable Flask app (6 seeded vulns)
│   ├── seeded_vulnerabilities.json # Catalogue of known vulnerabilities
│   └── requirements.txt
├── scripts/
│   ├── aggregate_results.py       # Aggregates all scan reports → findings.json
│   └── generate_report.py         # Generates HTML dashboard from findings.json
├── reports/
│   ├── bandit_report.json         # Bandit SAST output
│   ├── semgrep_report.json        # Semgrep SAST output
│   ├── pip_audit_report.json      # pip-audit SCA output
│   ├── trivy_report.json          # Trivy container/config scan output
│   ├── gitleaks_report.json       # Gitleaks secrets scan output
│   ├── findings.json              # Unified aggregated findings
│   └── dashboard.html             # HTML report dashboard
├── .github/workflows/
│   └── devsecops.yml              # GitHub Actions CI/CD pipeline
├── docker-compose.yml             # Vulnerable apps for DAST testing
└── .agent/system/
    └── project_architecture.md   # Full architecture reference
```

---

## Seeded Vulnerabilities

The test app (`test-app/app.py`) contains 6 intentional vulnerabilities for tool validation:

| ID | Type | CWE | Severity | Expected Tool |
|----|------|-----|----------|---------------|
| VULN-001 | Hardcoded Credentials | CWE-798 | HIGH | Bandit |
| VULN-002 | SQL Injection | CWE-89 | HIGH | Bandit / Semgrep |
| VULN-003 | OS Command Injection | CWE-78 | HIGH | Bandit / Semgrep |
| VULN-004 | Code Injection (eval) | CWE-94 | HIGH | Bandit / Semgrep |
| VULN-005 | Unvalidated Redirect | CWE-601 | MEDIUM | Semgrep |
| VULN-006 | Path Traversal | CWE-22 | HIGH | Bandit / Semgrep |

---

## Running the Program

<!-- Think of this project as a security checkpoint system for code — like a metal detector at an airport, but for software vulnerabilities. Each step below is one detector in the line. -->

### Prerequisites

```bash
pip install bandit semgrep pip-audit flask
```

```bash
# macOS — install Trivy via Homebrew
brew install trivy
```

Docker must be installed and running for DAST and container scanning.

---

### 1. Start the Flask test app

<!-- This switches the fake website on so the scanners have something to look at. The app is built on purpose with security holes — like leaving doors unlocked — so we can test whether our detectors find them. -->

```bash
# Run from: devsecops-dissertation/
cd test-app
python app.py
# App runs at http://localhost:5000
```

---

### 2. Run SAST scans

<!-- Two tools read through the code like a spell-checker, but instead of typos they look for dangerous patterns — things like passwords hardcoded in the code, or places where a hacker could trick the app into running their own commands. -->

```bash
# Run from: devsecops-dissertation/

# Bandit — Python security linter
bandit -r test-app/ -f json -o reports/bandit_report.json

# Semgrep — pattern-based static analysis (OWASP Top 10 ruleset)
semgrep --config=p/owasp-2021 --json --output reports/semgrep_report.json test-app/
```

---

### 3. Run SCA (dependency scanning)

<!-- The app uses third-party software packages (like plug-ins). This step checks whether any of those plug-ins have known security flaws — like checking whether the locks you bought from a shop are ones burglars already know how to pick. -->

```bash
# Run from: devsecops-dissertation/
pip-audit -r test-app/requirements.txt --format json -o reports/pip_audit_report.json
```

---

### 4. Run container / config scanning

<!-- The Docker files describe how to package and deploy the app. This step checks those files for security misconfigurations — like making sure the packaging itself isn't leaving a window open. -->

```bash
# Run from: devsecops-dissertation/
trivy config . --format json --output reports/trivy_report.json
```

---

### 5. Run secrets scanning

<!-- This scans the entire git history looking for accidentally committed passwords, API keys, or tokens — like checking whether anyone ever texted their bank PIN in the company group chat. -->

```bash
# Run from: devsecops-dissertation/
docker run --rm -v "$PWD":/repo ghcr.io/gitleaks/gitleaks:latest \
  detect --source /repo --report-format json \
  --report-path /repo/reports/gitleaks_report.json \
  --exit-code 0
```

---

### 6. Aggregate findings and run security gate

<!-- All the scan results are combined into one report. If anything serious is found, the build is marked as failed — a hard stop that blocks the code from being released, like a bouncer refusing entry. -->

```bash
# Run from: devsecops-dissertation/
python scripts/aggregate_results.py
# Output: reports/findings.json
# Exits with code 1 if HIGH/CRITICAL findings from Bandit or Semgrep are detected
```

---

### 7. Generate HTML dashboard

<!-- Turns all those raw scan results into a readable page you can open in a browser — colour-coded by severity, filterable by tool, with a score showing how many of the planted vulnerabilities were actually caught. -->

```bash
# Run from: devsecops-dissertation/
python scripts/generate_report.py
# Output: reports/dashboard.html
# Open in browser to view findings by tool, severity, and detection rate
```

---

### 8. Start Docker vulnerable apps (for DAST)

<!-- Spins up three well-known deliberately-broken websites that security researchers use worldwide for practice and live scanning. These are the targets for dynamic (live traffic) security testing. -->

```bash
# Run from: devsecops-dissertation/
docker-compose up -d
```

| App | URL | Purpose |
|-----|-----|---------|
| DVWA | <http://localhost:8081> | Damn Vulnerable Web Application |
| OWASP Juice Shop | <http://localhost:3000> | Modern vulnerable Node.js app |
| WebGoat | <http://localhost:8080/WebGoat> | Java-based security training app |

#### DVWA — http://localhost:8081

A classic PHP web application built specifically to be hacked. On first visit, click **Setup / Reset DB** to initialise the database, then log in with `admin` / `password`. Once in, use the left menu to pick a vulnerability category (SQL Injection, XSS, File Upload, etc.) and attempt to exploit it. The difficulty level can be changed under **DVWA Security** — start on Low to see vulnerabilities with no defences, then raise it to see how protections work.

#### OWASP Juice Shop — http://localhost:3000

A modern online shop deliberately full of security flaws. No login needed to browse — just start using the site and try to find weaknesses. There is a built-in **Score Board** (find it by looking for a hidden menu item or navigating to `/score-board`) that lists all the challenges and tracks your progress. Challenges range from finding hidden pages to bypassing login and manipulating prices.

#### WebGoat — http://localhost:8080/WebGoat

A structured security training platform. On first visit, click **Register** to create a free local account (no email needed). Once logged in, the left sidebar lists lessons organised by topic (Injection, Authentication, Broken Access Control, etc.). Each lesson explains the vulnerability, then gives you a live form to exploit it yourself, followed by hints and a solution if you get stuck.

```bash
docker-compose down  # stop all services
```

---

## CI/CD Pipeline

The GitHub Actions pipeline (`.github/workflows/devsecops.yml`) runs automatically on push or pull request to `main`.

### Pipeline Jobs

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

### Security Gate

The security gate fails the build if any **HIGH** or **CRITICAL** finding is detected by Bandit or Semgrep. All scan artifacts are downloadable from the GitHub Actions run summary.

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
