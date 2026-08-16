# Deployment modes

Trust Gate supports three deployment modes controlling how data is handled.

## Local-only mode (default)

All scanning occurs in CI. No data leaves the runner.

```yaml
with:
  deployment-mode: local
```

**Guarantees:**
- All findings remain local to the CI runner
- All policies are evaluated locally
- All reporting stays local
- Threat intelligence feeds are cached locally
- No telemetry is sent without explicit consent
- Network mode is disabled

## Hybrid mode

Source code stays local. Approved finding metadata may be uploaded after
redaction and approval.

```yaml
with:
  deployment-mode: hybrid
```

**Guarantees:**
- Source code never leaves the runner
- Only approved finding metadata is uploaded
- Field-level redaction removes source excerpts by default
- Upload allowlists control which findings may be transmitted
- Customer-managed encryption keys are supported
- Exact transmitted fields are documented below

### Transmitted fields (hybrid mode)

When upload is approved, only these fields are transmitted:

| Field | Description |
|-------|-------------|
| `finding_id` | Opaque identifier |
| `fingerprint` | Content-independent hash |
| `scanner` | Tool name |
| `rule_id` | Rule identifier |
| `category` | Finding category |
| `cwe` | CWE identifier |
| `severity` | Normalised severity |
| `confidence` | Confidence assessment |
| `status` | Current lifecycle status |

Source code, file paths, descriptions, and raw scanner output are
**never** transmitted by default.

### Upload allowlists

```yaml
with:
  upload-allowlist-scanners: "Bandit,Semgrep"
  upload-allowlist-severities: "critical,high"
  upload-require-approval: true
```

## Self-hosted enterprise mode

For organisations that operate Trust Gate entirely on their own
infrastructure.

### Container deployment

```bash
docker pull ghcr.io/owner/trustgate:latest
docker run -v $(pwd):/workspace trustgate scan
```

### Data handling

Every feature documents its data-handling behaviour in the
[Architecture docs](ARCHITECTURE.md).

Enterprise users can operate Trust Gate without sending any data to
the vendor. The following features support fully offline operation:

- Scanning (all scanners run locally)
- Policy evaluation (policies are local YAML files)
- Threat intelligence (offline import via `--offline-threat-data`)
- Reporting (all reports are generated locally)
- Calibration (feedback stored locally)

### Security hardening

See [docs/security/WORKFLOW_SECURITY.md](security/WORKFLOW_SECURITY.md)
for workflow hardening guidance.

### Configuration reference

| Setting | Values | Default |
|---------|--------|---------|
| `deployment-mode` | `local`, `hybrid`, `full` | `local` |
| `network-mode` | `disabled`, `metadata-only`, `full` | per deployment mode |
| `telemetry-consent` | `true`, `false` | `false` |
| `upload-require-approval` | `true`, `false` | `true` |
