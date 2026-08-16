# Data processing documentation

## What data Trust Gate processes

Trust Gate processes security scanner output to produce aggregated
findings, policy decisions, and reports. It handles:

- Scanner reports (SARIF, JSON, custom formats)
- Source code file paths and line numbers
- Vulnerability metadata (CVE IDs, CWE IDs, severity)
- Dependency information (package names, versions)
- Threat intelligence data (EPSS scores, KEV status)

## Where data is stored

| Deployment mode | Location | Network |
|----------------|----------|---------|
| Local (default) | CI runner filesystem | None |
| Hybrid | Runner + approved metadata upload | Metadata only |
| Full | Runner + cloud storage | Full |

## Data retention

- Local mode: data exists only for the lifetime of the CI job.
- Hybrid/full modes: retention follows the configured policy.
- Calibration feedback is stored locally until explicitly exported.

## Privacy controls

See [docs/PRIVACY_MODEL.md](PRIVACY_MODEL.md) for field-level redaction,
telemetry consent, and data handling guarantees.
