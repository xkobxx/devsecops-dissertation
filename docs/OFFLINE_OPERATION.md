# Offline Operation Guide

TrustGate runs entirely offline by default. Core scanning, policy evaluation, and remediation guidance require no network access.

## Local Deployment Mode

All analysis executes locally against your codebase and configured rule sets. No telemetry, external API calls, or cloud services are contacted during a scan.

```bash
trustgate scan ./src --policy default
```

This works identically whether the host has network access or not.

## Offline Threat Intelligence Import

Threat intelligence feeds can be pre-downloaded and imported from a JSON file:

```bash
# Export feeds on a connected machine
trustgate threat-intel --export feeds.json

# Transfer feeds.json to the air-gapped host, then import
trustgate threat-intel --import feeds.json
```

The imported feed data is stored in the local cache and used for all subsequent scans until replaced by a newer import.

## No-Network Scanning

All analysis engines (SAST, dependency audit, IaC checks, reachability analysis) run locally. Vulnerability matching uses the imported threat intelligence cache rather than live lookups.

```bash
# Full scan with no network dependency
trustgate scan ./project --format sarif --output results.sarif
```

## Air-Gapped Environments

### Pre-Download Dependencies

On a connected machine, download the package and all dependencies:

```bash
pip download trustgate -d ./trustgate-bundle
```

### Bundle Install

Transfer the `trustgate-bundle/` directory to the target host, then install:

```bash
pip install --no-index --find-links ./trustgate-bundle trustgate
```

### Vendored Rule Sets

Rule sets ship with the package. To update them offline, export on a connected machine and copy across:

```bash
trustgate rules --export rules-snapshot.json
# Transfer to air-gapped host
trustgate rules --import rules-snapshot.json
```

## Cache Management

TrustGate caches threat intelligence, rule sets, and scan metadata locally.

```bash
# Show cache location and size
trustgate cache --status

# Clear all cached data
trustgate cache --clear

# Clear only threat intelligence cache
trustgate cache --clear --scope threat-intel
```

The default cache directory is `~/.trustgate/cache/`. Override it with the `TRUSTGATE_CACHE_DIR` environment variable.

## Verifying Offline Readiness

Confirm that all required components are available locally before going offline:

```bash
trustgate --check-offline
```

This validates that rule sets are present, threat intelligence data is cached, and no scan configuration references external resources. A non-zero exit code indicates missing components, with details printed to stderr.
