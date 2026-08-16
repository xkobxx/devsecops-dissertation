# Baseline Setup

TrustGate baselines capture a snapshot of known findings so that subsequent scans surface only new issues. This guide covers creating, comparing, and maintaining baselines.

## Creating a Baseline

Generate a baseline from the current state of a branch:

```bash
trustgate baseline --create --branch main
```

This scans the branch, fingerprints every finding, and writes the result to `.trustgate/baselines/main.json`.

To baseline a different branch:

```bash
trustgate baseline --create --branch release/v2
```

## Comparing Against a Baseline

Run a scan and compare its output against the stored baseline to isolate new findings:

```bash
trustgate baseline --compare --findings findings.json
```

The command exits with a non-zero status if new (unbaselined) findings are present, making it suitable for CI gates.

## Updating Baselines

After triaging findings and confirming they are accepted, update the baseline in place:

```bash
trustgate baseline --update
```

This re-fingerprints the current findings and overwrites the active baseline file.

## Baseline Format

Each baseline is a JSON file containing fingerprinted findings:

```json
{
  "version": "1.0",
  "branch": "main",
  "created_at": "2026-08-13T10:00:00Z",
  "findings": [
    {
      "fingerprint": "sha256:ab12cd...",
      "rule_id": "SEC-001",
      "file": "src/app/auth.py",
      "severity": "high"
    }
  ]
}
```

Fingerprints are derived from the rule ID, file path, and code context so that minor formatting changes do not invalidate a baseline entry.

## Baseline Storage

Baselines are stored under the project root:

```
.trustgate/
  baselines/
    main.json
    release-v2.json
```

Add `.trustgate/baselines/` to version control so the team shares a single source of truth. The directory is created automatically on first use.

## Using Baselines in CI

A typical GitHub Actions step:

```yaml
- name: Check for new findings
  run: |
    trustgate scan --output findings.json
    trustgate baseline --compare --findings findings.json
```

The compare step fails the pipeline when new findings appear. After review, merge an updated baseline to accept intentional changes:

```bash
trustgate baseline --update
git add .trustgate/baselines/
git commit -m "chore: update security baseline"
```
