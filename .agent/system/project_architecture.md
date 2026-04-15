# Project Architecture

## Project Goal

This dissertation project focuses on **DevSecOps practices and automated security vulnerability detection**. The project implements a security scanning pipeline that integrates multiple security tools (Bandit, Semgrep) to detect vulnerabilities in Python applications, with a test application containing intentionally seeded vulnerabilities for testing and validation purposes.

## Project Structure

```
devsecops-dissertation/
├── .agent/                      # Documentation directory
│   ├── system/                  # System architecture documentation
│   ├── tasks/                   # PRD & implementation plans
│   ├── sop/                     # Standard operating procedures
│   └── README.md                # Documentation index
├── test-app/                    # Test application with seeded vulnerabilities
│   ├── app.py                   # Flask application with intentional security flaws
│   ├── requirements.txt         # Python dependencies
│   └── seeded_vulnerabilities.json  # Catalog of known vulnerabilities
├── commands/                    # Command scripts and utilities
│   └── update-doc.md            # Documentation update instructions
├── docs/                        # Additional documentation
│   └── screenshots/             # Screenshot assets
├── reports/                     # Security scan reports
│   └── bandit_report.json       # Bandit security scan results
├── results/                     # Scan output results
├── scripts/                     # Automation scripts
├── skills/                      # Qwen Code skills (AI assistant capabilities)
├── .github/                     # GitHub configuration
│   └── workflows/               # CI/CD workflows (empty)
├── docker-compose.yml           # Docker services configuration
├── requirements.txt             # Root-level Python dependencies
└── README.md                    # Project overview
```

## Tech Stack

### Core Technologies

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Language** | Python | 3.11.x | Primary programming language |
| **Web Framework** | Flask | 3.1.1 | Test application framework |
| **Database** | SQLite | - | Local database for test app |
| **Containerization** | Docker | - | Service orchestration |

### Security Scanning Tools

| Tool | Version | Purpose |
|------|---------|---------|
| **Bandit** | 1.17.4 | Python security linter - detects common security issues |
| **Semgrep** | 1.156.0 | Static analysis tool - pattern-based security scanning |

### Key Dependencies

**Security & Analysis:**
- `bandit==1.17.4` - Python security scanner
- `semgrep==1.156.0` - Static analysis engine

**Web & API:**
- `fastapi==0.135.1` - Modern web framework
- `flask==3.1.1` - Lightweight web framework
- `flask-cors==6.0.0` - CORS support for Flask

**Database & ORM:**
- `sqlalchemy==2.0.48` - SQL toolkit and ORM
- `alembic==1.18.4` - Database migrations

**Testing:**
- `pytest==9.0.2` - Testing framework
- `pytest-cov==7.0.0` - Coverage plugin

**ML & Data (for analysis):**
- `scikit-learn==1.8.0` - Machine learning library
- `pandas==2.3.2` - Data manipulation
- `numpy==2.3.2` - Numerical computing

**Utilities:**
- `python-dotenv==1.2.1` - Environment variable management
- `pydantic==2.12.5` - Data validation
- `loguru==0.7.3` - Logging library

## Integration Points

### Docker Services

The project uses Docker Compose to run vulnerable web applications for security testing:

```yaml
services:
  dvwa:         # Damn Vulnerable Web Application (port 8081)
  dvwa-db:      # MariaDB backend for DVWA
  juiceshop:    # OWASP Juice Shop (port 3000)
  webgoat:      # OWASP WebGoat (ports 8080, 9090)
```

These services provide:
- **DVWA**: PHP/MySQL web application with intentional vulnerabilities
- **Juice Shop**: Modern Node.js vulnerable application
- **WebGoat**: Java-based security training application

### Security Pipeline Integration

The project integrates security tools into a DevSecOps pipeline:

1. **Bandit** → Scans Python source code for security issues
2. **Semgrep** → Pattern-based static analysis
3. **Reports** → JSON output for CI/CD integration

## Test Application Architecture

### Overview

The `test-app/` directory contains a deliberately vulnerable Flask application designed to test security scanning tools.

### Seeded Vulnerabilities

| ID | Type | CWE | OWASP Category | Severity | Detection Tool |
|----|------|-----|----------------|----------|----------------|
| VULN-001 | Hardcoded Credentials | CWE-798 | A07:2021 - Auth Failures | HIGH | Bandit |
| VULN-002 | SQL Injection | CWE-89 | A03:2021 - Injection | HIGH | Bandit/Semgrep |
| VULN-003 | OS Command Injection | CWE-78 | A03:2021 - Injection | HIGH | Bandit/Semgrep |
| VULN-004 | Code Injection (eval) | CWE-94 | A03:2021 - Injection | HIGH | Bandit/Semgrep |
| VULN-005 | Unvalidated Redirect | CWE-601 | A01:2021 - Access Control | MEDIUM | Semgrep |
| VULN-006 | Path Traversal | CWE-22 | A01:2021 - Access Control | HIGH | Bandit/Semgrep |

### Application Endpoints

```python
POST /login      # SQL injection vulnerability
POST /run        # OS command injection
POST /evaluate   # Code injection via eval()
GET  /redirect   # Unvalidated redirect
GET  /file       # Path traversal
```

## Database Schema

### Test Application (SQLite)

The test application uses a simple SQLite database (`users.db`):

```sql
-- Users table (vulnerable implementation)
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);
```

**Note**: The current implementation uses vulnerable string concatenation for SQL queries instead of parameterized statements.

## Core Functionalities

### Security Scanning Workflow

1. **Source Code Analysis**: Bandit and Semgrep scan Python files
2. **Vulnerability Detection**: Tools identify security anti-patterns
3. **Report Generation**: JSON reports with findings
4. **Validation**: Compare detected vulnerabilities against known seeded issues

### Vulnerability Categories Covered

- **Injection Attacks**: SQL, OS command, code injection
- **Authentication Failures**: Hardcoded credentials
- **Access Control**: Path traversal, unvalidated redirects
- **Security Misconfiguration**: Debug mode enabled

## Development Workflow

### Running the Test Application

```bash
cd test-app
python app.py
```

### Running Security Scans

```bash
# Bandit scan
bandit -r test-app/ -f json -o reports/bandit_report.json

# Semgrep scan
semgrep --config auto test-app/
```

### Docker Services

```bash
# Start all vulnerable services
docker-compose up -d

# Stop all services
docker-compose down
```

## Related Documentation

- [.agent/README.md](../README.md) - Documentation index
- [seeded_vulnerabilities.json](../../test-app/seeded_vulnerabilities.json) - Complete vulnerability catalog
