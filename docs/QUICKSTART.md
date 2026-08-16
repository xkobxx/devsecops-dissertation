# Quick Start

Get from zero to a security gate decision in five minutes.

## Prerequisites

- Python 3.11 or later

## Install

```bash
pip install trustgate
```

Verify the installation:

```bash
trustgate --version
```

## 1. Aggregate scanner reports

Point TrustGate at a directory containing raw scanner output (Bandit,
Semgrep, pip-audit, Trivy, Gitleaks, and others). It normalises every
report into a single canonical findings file.

```bash
trustgate aggregate --reports-dir ./reports/
```

This writes `reports/findings.json` by default. Use `--output` to change
the path, and `--fail-on` to set the minimum severity that fails the gate
(`critical`, `high`, `medium`, `low`, or `none`).

## 2. Evaluate a policy decision

Feed the aggregated findings into the contextual decision engine along
with an optional policy snapshot:

```bash
trustgate decide --input reports/findings.json --policy policy.json
```

The output lands in `reports/decisions.json`. Each finding receives an
explainable pass/fail verdict. Supply `--runtime-context context.json` to
attach environment or per-finding context that refines the evaluation.

## 3. Generate an HTML report

Produce a self-contained dashboard from the normalised findings:

```bash
trustgate report --input reports/findings.json --output report.html
```

Open `report.html` in any browser to review severity breakdowns and
individual finding details.

## Putting it together

A typical CI snippet chains all three steps:

```bash
trustgate aggregate --reports-dir ./reports/ --fail-on high
trustgate decide    --input reports/findings.json
trustgate report    --input reports/findings.json --output report.html
```

## Other useful commands

| Command | Purpose |
|---------|---------|
| `trustgate plan` | Preview scanner selection without scanning |
| `trustgate policy` | Validate or simulate policy-as-code |
| `trustgate sarif` | Export findings as SARIF 2.1.0 |
| `trustgate sbom` | Generate CycloneDX / SPDX SBOMs |
| `trustgate remediate` | List or apply deterministic fixes |
| `trustgate baseline` | Create or compare a finding baseline |

Run `trustgate --help` or `trustgate <command> --help` for full option
details.
