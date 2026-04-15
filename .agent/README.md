# .agent Documentation Index

This directory contains all critical documentation for the DevSecOps Dissertation project. Use this index to find the information you need.

---

## 📁 Directory Structure

```
.agent/
├── README.md                    # This file - documentation index
├── system/                      # System architecture & state
│   └── project_architecture.md  # Complete project architecture
├── tasks/                       # PRDs & implementation plans
│   └── (empty - add PRDs here)
└── sop/                         # Standard operating procedures
    └── (empty - add SOPs here)
```

---

## 📚 Documentation Files

### System Documentation

| Document | Description |
|----------|-------------|
| [system/project_architecture.md](./system/project_architecture.md) | **Complete project architecture** - Project goal, structure, tech stack, integration points, database schema, test application details, and seeded vulnerabilities catalog |

### Tasks (PRDs & Implementation Plans)

*No task documents yet. Add PRDs here when planning new features.*

### Standard Operating Procedures (SOPs)

*No SOPs yet. Add procedures for common tasks like:*
- Adding schema migrations
- Running security scans
- Adding new test endpoints
- CI/CD pipeline updates

---

## 🚀 Quick Start for New Engineers

### 1. Understand the Project
Start here → [system/project_architecture.md](./system/project_architecture.md)

This document covers:
- Project goals and structure
- Tech stack and dependencies
- Security tools (Bandit, Semgrep)
- Test application architecture
- Seeded vulnerabilities catalog
- Docker services setup

### 2. Set Up Your Environment

```bash
# Install Python dependencies
pip install -r requirements.txt

# Start vulnerable Docker services
docker-compose up -d

# Verify test application
cd test-app && python app.py
```

### 3. Run Security Scans

```bash
# Bandit
bandit -r test-app/ -f json -o reports/bandit_report.json

# Semgrep
semgrep --config auto test-app/
```

---

## 📋 Documentation Guidelines

### When to Update Documentation

| Scenario | Action |
|----------|--------|
| New feature implemented | Update `project_architecture.md`, add PRD to `tasks/` |
| Architecture changes | Update `project_architecture.md` |
| New dependency added | Update tech stack table in `project_architecture.md` |
| New vulnerability added | Update `seeded_vulnerabilities.json` and `project_architecture.md` |
| Process/procedure created | Add new SOP to `sop/` |

### Documentation Structure

- **System/**: Current state of the system (architecture, tech stack, database schema)
- **Tasks/**: PRDs and implementation plans for features
- **SOP/**: Step-by-step procedures for common tasks

### Related Files

- [test-app/seeded_vulnerabilities.json](../test-app/seeded_vulnerabilities.json) - Vulnerability catalog
- [docker-compose.yml](../docker-compose.yml) - Service configuration
- [requirements.txt](../requirements.txt) - Python dependencies

---

## 📞 Need Help?

1. Check this documentation index first
2. Review `project_architecture.md` for system context
3. Create/update SOPs for repeatable tasks
4. Add PRDs for new feature planning
